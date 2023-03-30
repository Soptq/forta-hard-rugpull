require('dotenv').config()
const {
    Finding,
    FindingSeverity,
    FindingType,
    getEthersProvider,
    getTransactionReceipt,
    TransactionEvent,
    Network, ethers,
} = require("forta-agent");
const fetch = require('node-fetch');
const parser = require('./parser');
const { DynamicHoneypotDetector } = require('./detectors');
const HttpsProxyAgent = require('https-proxy-agent');

const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY;
const proxy = process.env.http_proxy
const detectors = [
    DynamicHoneypotDetector
]

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

    const response = await fetch(apiEndpoint, {agent: new HttpsProxyAgent(proxy)});
    const data = await response.json();
    return data.result[0].SourceCode;
}

const handleTransaction = async (txEvent) => {
    const findings = [];

    // limiting this agent to emit only 5 findings so that the alert feed is not spammed
    if (findingsCount >= 5) return findings;

    const createdContract = await getCreatedContractAddress(txEvent);
    if (!createdContract) return findings;

    const sourceCode = await getSourceCode(txEvent, createdContract);
    if (!sourceCode) return findings;

    const deploymentData = txEvent.transaction.data;
    const code = await getEthersProvider().getCode(createdContract);
    const loc = deploymentData.lastIndexOf(code.slice(-32));
    if (loc < 0) return findings;

    const constructArguments = deploymentData.slice(loc + 32)
    console.log(constructArguments)

    let contractInfo;
    try {
        contractInfo = parser.parseContract(sourceCode)
    } catch (e) {
        console.error(e.errors)
        return findings;
    }
    console.log(contractInfo.entryContract.loc.start)
    if (!contractInfo.isTokenContract) return findings;

    for (const detector of detectors) {
        const findingsFromDetector = await detector(txEvent, createdContract, contractInfo.ast);
        findings.push(...findingsFromDetector);
    }

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
