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
const HttpsProxyAgent = require('https-proxy-agent');
const shell = require('shelljs');
const {exit} = require("shelljs");

const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY;
const proxy = process.env.http_proxy

let findingsCount = 0;

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
        apiEndpoint = `https://api.etherscan.io/api?module=contract&action=getsourcecode&address=${contractAddress}&apikey=${ETHERSCAN_API_KEY}`
    } else {
        throw new Error('Network not supported');
    }

    let response;
    if (proxy) {
        response = await fetch(apiEndpoint, {agent: new HttpsProxyAgent(proxy)});
    } else {
        response = await fetch(apiEndpoint);
    }
    const data = await response.json();
    return data.result[0].SourceCode;
}

const handleTransaction = async (txEvent) => {
    console.log(`Handling transaction ${txEvent.transaction.hash}...`)
    const findings = [];

    // limiting this agent to emit only 5 findings so that the alert feed is not spammed
    if (findingsCount >= 5) return findings;

    const createdContract = await getCreatedContractAddress(txEvent);
    if (!createdContract) return findings;

    let sourceCode = await getSourceCode(txEvent, createdContract);
    if (!sourceCode) return findings;

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
        fs.rmdirSync('./working', { recursive: true });
    }

    const deploymentData = txEvent.transaction.data;
    const code = await getEthersProvider().getCode(createdContract);
    const loc = deploymentData.lastIndexOf(code.slice(-32));
    if (loc < 0) return findings;

    const constructArguments = deploymentData.slice(loc + 32)
    let testing;
    try {
        const injectedSourceCode = DefaultInjector(sourceCode);
        testing = new DynamicTest(injectedSourceCode, constructArguments);
    } catch (error) {
        console.log(error)
        return findings;
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
            findings.push(Finding.fromObject({
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
        }
    }

    if (findings.length > 1)  {
        findings.push(Finding.fromObject({
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

    // cleaning
    fs.rmdirSync('./out', { recursive: true });

    return findings;
};

// const initialize = async () => {
//   // do some initialization on startup e.g. fetch data
// }

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
    // initialize,
    handleTransaction,
    // handleBlock,
    // handleAlert,
};
