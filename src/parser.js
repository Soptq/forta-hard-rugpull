const parser = require('@solidity-parser/parser');

const isTokenContract = (callableFunctions, events) => {
    return callableFunctions.includes('name') &&
        callableFunctions.includes('symbol') &&
        callableFunctions.includes('decimals') &&
        callableFunctions.includes('totalSupply') &&
        callableFunctions.includes('balanceOf') &&
        callableFunctions.includes('transfer') &&
        callableFunctions.includes('transferFrom') &&
        callableFunctions.includes('approve') &&
        callableFunctions.includes('allowance') &&
        events.includes('Transfer') &&
        events.includes('Approval');
}

const isOwnableContract = (callableFunctions, events) => {
return callableFunctions.includes('owner') &&
        callableFunctions.includes('transferOwnership') &&
        events.includes('OwnershipTransferred');
}

const parseContract = (sourceCode) => {
    const ast = parser.parse(sourceCode, { loc: true });

    let callableFunctions = new Set();
    let events = new Set();
    const contracts = [];
    for (const node of ast.children) {
        if (node.type === 'ContractDefinition') {
            for (const fn of node.subNodes) {
                if (fn.type === 'FunctionDefinition' &&
                    (fn.visibility === 'public' || fn.visibility === 'external' || fn.visibility === 'default')
                    && fn.name) {
                    callableFunctions.add(fn.name);
                } else if (fn.type === 'EventDefinition') {
                    events.add(fn.name);
                }
            }
            contracts.push(node);
        }
    }
    callableFunctions = new Array(...callableFunctions)
    events = new Array(...events)

    // construct dependency tree
    const dependencyTree = {};
    let topNode;

    while (Object.keys(dependencyTree).length !== contracts.length) {
        for (const contract of contracts) {
            let notMatch = false
            for (const baseContract of contract.baseContracts) {
                if (!(baseContract.baseName.namePath in dependencyTree)) {
                    notMatch = true;
                    break;
                }
            }
            if (!notMatch) {
                dependencyTree[contract.name] = contract.baseContracts.map(baseContract => baseContract.baseName.namePath);
                topNode = contract;
            }
        }
    }


    return {
        "ast": ast,
        "callableFunctions": callableFunctions,
        "events": events,
        "isTokenContract": isTokenContract(callableFunctions, events),
        "isOwnableContract": isOwnableContract(callableFunctions, events),
        "dependencyTree": dependencyTree,
        "entryContract": topNode,
    };
}

module.exports = {
    parseContract
}