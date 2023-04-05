require('dotenv').config()
const {
    Finding,
    FindingSeverity,
    FindingType,
    getEthersProvider,
    getTransactionReceipt,
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
    // check if the transaction creates a new contract
    const toAddress = txEvent.transaction.to;
    const txContractAddress = txEvent.contractAddress;

    if (toAddress || txContractAddress) {
        return null;
    }

    const receipt = await getTransactionReceipt(txEvent.hash);
    return receipt.contractAddress
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
            await new Promise(r => setTimeout(r, 1000));
            continue;
        }

        const { txEvent, createdContract, sourceCode, constructArguments } = taskQueue.shift();
        console.log(`Running task for ${txEvent.transaction.hash}...`)

        let localFindingsCount = 0;
        let testing;

        try {
            const injectedSourceCode = DefaultInjector(sourceCode);
            testing = new DynamicTest(injectedSourceCode, constructArguments);
        } catch (error) {
            console.log(error)
        }

        const results = await testing.test(txEvent);

        for (const [key, value] of Object.entries(results)) {
            if (!key.startsWith("test/test.sol")) continue;
            const testName = key.split(":")[1];
            const result = value["test_results"];
            let success = true
            for (const [_, testResult] of Object.entries(result)) {
                success = success && testResult["success"]
            }

            if (!success) {
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

        fs.rmSync('./out', { recursive: true });
    }
}

const handleTransaction = async (txEvent) => {
    let findings = [];

    const createdContract = await getCreatedContractAddress(txEvent);
    if (!createdContract) return findings;
    console.log(`Found contract creation transaction ${txEvent.transaction.hash}...`)

    let sourceCode = await getSourceCode(txEvent, createdContract);
    if (!sourceCode) return findings;
    console.log(`Found source code for ${createdContract}...`)

    if (sourceCode.startsWith("{")) {
        // multiple contracts in the same file
        const contractsJson = JSON.parse(sourceCode.slice(1, -1));
        for (const [contractName, contractSourceCode] of Object.entries(contractsJson.sources)) {
            // write files locally
            fs.mkdirSync(getDirName(`./working/${contractName}`), { recursive: true });
            fs.writeFileSync(`./working/${contractName}`, contractSourceCode.content)
        }

        // forge flatten
        let longestFlattenedContractLength = 0;
        for (const contractName of Object.keys(contractsJson.sources)) {
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
    if (loc < 0) return findings;

    const constructArguments = deploymentData.slice(loc + 32)
    taskQueue.push({txEvent, createdContract, sourceCode, constructArguments});
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
