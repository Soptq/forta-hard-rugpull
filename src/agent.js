require('dotenv').config()
const {
    Finding,
    FindingSeverity,
    FindingType,
    getEthersProvider,
    ethers,
    Label,
    Network,
    EntityType,
} = require("forta-agent");
const fs = require('fs');
const getDirName = require('path').dirname;
const fetch = require('node-fetch');
const { DynamicTest, DefaultInjector } = require('./detectors');
const shell = require('shelljs');

const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY;
const OPTIMISM_ETHERSCAN_API_KEY = process.env.OPTIMISM_ETHERSCAN_API_KEY;
const BSCSCAN_API_KEY = process.env.BSCSCAN_API_KEY;
const POLYGONSCAN_API_KEY = process.env.POLYGONSCAN_API_KEY;
const FTMSCAN_API_KEY = process.env.FTMSCAN_API_KEY;
const ARBISCAN_API_KEY = process.env.ARBISCAN_API_KEY;
const SNOWTRACE_API_KEY = process.env.SNOWTRACE_API_KEY;

const taskQueue = [];
let findingsCache = [];

const getCreatedContractAddress = async (txEvent) => {
    if (!txEvent.to) {
        return ethers.utils.getAddress(ethers.utils.getContractAddress({
            from: txEvent.from,
            nonce: txEvent.transaction.nonce,
        }));
    }

    return null;
}

const getSourceCode = async (txEvent, contractAddress) => {
    let apiEndpoint;
    const network = parseInt(txEvent.network);
    if (network === Network.MAINNET) {
        apiEndpoint = `https://api.etherscan.io/api?module=contract&action=getsourcecode&address=${contractAddress}&apikey=${ETHERSCAN_API_KEY}`;
    } else if (network === Network.OPTIMISM) {
        apiEndpoint = `https://api-optimistic.etherscan.io/api?module=contract&action=getsourcecode&address=${contractAddress}&apikey=${OPTIMISM_ETHERSCAN_API_KEY}`;
    } else if (network === Network.BSC) {
        apiEndpoint = `https://api.bscscan.com/api?module=contract&action=getsourcecode&address=${contractAddress}&apikey=${BSCSCAN_API_KEY}`;
    } else if (network === Network.POLYGON) {
        apiEndpoint = `https://api.polygonscan.com/api?module=contract&action=getsourcecode&address=${contractAddress}&apikey=${POLYGONSCAN_API_KEY}`;
    } else if (network === Network.FANTOM) {
        apiEndpoint = `https://api.ftmscan.com/api?module=contract&action=getsourcecode&address=${contractAddress}&apikey=${FTMSCAN_API_KEY}`;
    } else if (network === Network.ARBITRUM) {
        apiEndpoint = `https://api.arbiscan.io/api?module=contract&action=getsourcecode&address=${contractAddress}&apikey=${ARBISCAN_API_KEY}`;
    } else if (network === Network.AVALANCHE) {
        apiEndpoint = `https://api.snowtrace.io/api?module=contract&action=getsourcecode&address=${contractAddress}&apikey=${SNOWTRACE_API_KEY}`;
    } else {
        throw new Error('Network not supported');
    }

    const response = await fetch(apiEndpoint);
    const data = await response.json();
    return data.result[0].SourceCode;
}

const runTaskConsumer = async () => {
    console.log("Starting task consumer...")
    while (true) {
        if (taskQueue.length === 0) {
            await new Promise(r => setTimeout(r, 1000 * 10));
            continue;
        }

        try {
            const { txEvent, createdContract } = taskQueue.shift();
            console.log(`Running task for ${txEvent.transaction.hash}...`)

            let sourceCode = await getSourceCode(txEvent, createdContract);
            if (!sourceCode) continue;
            console.log(`Found source code for ${createdContract}...`)

            if (sourceCode.startsWith("{")) {
                // multiple contracts in the same file
                let responseType = 0;
                if (sourceCode[1] === "{") responseType = 1;

                let inner;
                if (responseType === 0) {
                    inner = JSON.parse(sourceCode)
                } else if (responseType === 1) {
                    inner = JSON.parse(sourceCode.slice(1, -1)).sources
                }

                for (const [contractName, contractSourceCode] of Object.entries(inner)) {
                    // write files locally
                    fs.mkdirSync(getDirName(`./working/${contractName}`), { recursive: true });
                    fs.writeFileSync(`./working/${contractName}`, contractSourceCode.content)
                }

                // forge flatten
                let longestFlattenedContractLength = 0;
                for (const contractName of Object.keys(inner)) {
                    const contractCode = shell.exec(`forge flatten --root ./working ./working/${contractName}`, {silent: true});
                    if (contractCode.length > longestFlattenedContractLength) {
                        sourceCode = contractCode;
                        longestFlattenedContractLength = contractCode.length;
                    }
                }

                // remove files under working
                fs.rmSync('./working', { recursive: true });
            }

            const deploymentData = txEvent.transaction.data;
            const code = await getEthersProvider().getCode(createdContract);
            const loc = deploymentData.lastIndexOf(code.slice(-32));
            if (loc < 0) continue;

            const constructArguments = deploymentData.slice(loc + 32)

            let localFindingsCount = 0;
            let testing;

            const injectedSourceCode = DefaultInjector(sourceCode);
            testing = new DynamicTest(injectedSourceCode, constructArguments);

            const results = await testing.test(txEvent);
            const rugpullTechniques = [];

            for (const [key, value] of Object.entries(results)) {
                if (!key.startsWith("test/test.sol")) continue;
                const testName = key.split(":")[1];
                const result = value["test_results"];
                let success = true
                for (const [subTestName, testResult] of Object.entries(result)) {
                    if (subTestName === "setUp()") continue;
                    success = success && testResult["success"]
                }

                if (!success) {
                    rugpullTechniques.push(testName.slice(7, -4).toUpperCase());
                    findingsCache.push(Finding.fromObject({
                        name: `HARD-RUG-PULL-${testName.slice(7, -4).toUpperCase()}-DYNAMIC`,
                        alertId: `HARD-RUG-PULL-${testName.slice(7, -4).toUpperCase()}-DYNAMIC`,
                        description: `${txEvent.transaction.from} deployed a token contract ${createdContract} that may result in a hard rug pull`,
                        severity: FindingSeverity.Medium,
                        type: FindingType.Suspicious,
                        metadata: {
                            "attacker_deployer_address": txEvent.transaction.from,
                            "token_contract_address": createdContract,
                        },
                        labels: [
                            Label.fromObject({
                                entityType: EntityType.ADDRESS,
                                label: "scam",
                                confidence: 0.5,
                            }),
                            Label.fromObject({
                                entityType: EntityType.ADDRESS,
                                label: "scam-contract",
                                confidence: 0.5,
                            }),
                        ]
                    }));
                    localFindingsCount += 1;
                }
            }

            if (localFindingsCount > 1)  {
                findingsCache.push(Finding.fromObject({
                    name: `HARD-RUG-PULL-1`,
                    alertId: `HARD-RUG-PULL-1`,
                    description: `${txEvent.transaction.from} deployed a token contract ${createdContract} that may result in a hard rug pull`,
                    severity: FindingSeverity.High,
                    type: FindingType.Suspicious,
                    metadata: {
                        "attacker_deployer_address": txEvent.transaction.from,
                        "token_contract_address": createdContract,
                        "rugpull_techniques": rugpullTechniques.join(", ")
                    },
                    labels: [
                        Label.fromObject({
                            entityType: EntityType.ADDRESS,
                            label: "scam",
                            confidence: 0.8,
                        }),
                        Label.fromObject({
                            entityType: EntityType.ADDRESS,
                            label: "scam-contract",
                            confidence: 0.8,
                        }),
                    ]
                }));
            }

            if (fs.existsSync('./out')) {
                fs.rmSync('./out', {recursive: true});
            }
        } catch (e) {
            // console.log(e)
        }
    }
}

const handleTransaction = async (txEvent) => {
    let findings = [];

    const createdContract = await getCreatedContractAddress(txEvent);
    if (!createdContract) return findings;
    console.log(`Found contract creation transaction ${txEvent.transaction.hash}: ${createdContract}...`)

    taskQueue.push({txEvent, createdContract});
    console.log(`[${taskQueue.length}] Added task for ${txEvent.transaction.hash}...`)

    if (findingsCache.length > 0) {
        findings = findingsCache;
        findingsCache = [];
    }

    return findings;
};

const initialize = async () => {
    runTaskConsumer();
}

// const handleBlock = async (blockEvent) => {
//   const findings = [];
//   // detect some block condition
//   return findings;
// };

// const handleAlert = async (alertEvent) => {
//   const findings = [];
//   // detect some alert condition
//   return findings;
// };

module.exports = {
    initialize,
    handleTransaction,
    // handleBlock,
    // handleAlert,
};
