const {
    ethers,
    getJsonRpcUrl,
    getEthersProvider
} = require("forta-agent");
const ganache = require("ganache-core");
const parser = require('@solidity-parser/parser');
const { parseContract } = require('./parser')
const prettier = require("prettier");

const ERC20_TRANSFER_EVENT =
    "event Transfer(address indexed from, address indexed to, uint256 value)";

const getEthersForkProvider = (blockNumber, unlockedAccounts) => {
    return new ethers.providers.Web3Provider(
        ganache.provider({
            fork: getJsonRpcUrl(),
            fork_block_number: blockNumber,
            unlocked_accounts: unlockedAccounts,
            default_balance_ether: 1.23456,
            gasPrice: 0,
        })
    );
}

const findConstructor = (entryContract) => {
    let constructor;
    parser.visit(entryContract, {
        FunctionDefinition: function(fn) {
            if (fn.isConstructor && fn.name === null) {
                constructor = fn;
            }
        }
    })
    return constructor;
}

const DefaultInjector = (sourceCode) => {
    const formattedSourceCode = prettier.format(sourceCode, {
        parser: 'solidity-parse',
    });
    let contractInfo;
    try {
        contractInfo = parseContract(formattedSourceCode)
    } catch (e) {
        console.error(e.errors)
    }

    // find constructor
    const entryContract = contractInfo.entryContract;
    const constructor = findConstructor(entryContract);

    let injectLocation, injectCode;

    if (!constructor) {
        injectCode = '\nconstructor() public { '
        injectLocation = entryContract.loc.end.line;
    } else {
        injectCode = '\n'
        injectLocation = constructor.loc.end.line;
    }

    if (contractInfo.isTokenContract) {
        // inject _mint() to constructor
        injectCode += '_mint(msg.sender, 1000000000000000000000000); '
    }

    if (contractInfo.isOwnableContract) {
        // inject transferOwnership() to constructor
        injectCode += 'transferOwnership(msg.sender); '
    }

    if (!constructor) {
        injectCode += '}'
    }

    // add injectCode to formattedSourceCode at line injectLocation
    let injectSourceCode = formattedSourceCode.split('\n').slice(0, injectLocation - 1).join('\n') +
        injectCode + formattedSourceCode.split('\n').slice(injectLocation - 1).join('\n');
    // add forge library
    injectSourceCode += '\nimport "forge-std/Test.sol";\n';
    return prettier.format(injectSourceCode, {
        parser: 'solidity-parse',
    })
}

const DynamicDetectHoneypot = async (txEvent, contractAddress, parsedInfo) => {
    if (!parsedInfo.isTokenContract) return [];

    let forkedProvider, contract, initialAddress;
    const randomFromAddress = ethers.Wallet.createRandom().address;
    const randomToAddress = ethers.Wallet.createRandom().address;
    contract = new ethers.Contract(contractAddress, [
        "function balanceOf(address account) view returns (uint256)",
        "function transfer(address to, uint amount) returns (bool)"
    ], getEthersProvider());
    const senderBalance = await contract.balanceOf(txEvent.transaction.from, { blockTag: txEvent.block.number })
    if (senderBalance.gt(0)) {
        initialAddress = txEvent.transaction.from;
    } else {
        const tokenTransferEvents = txEvent.filterLog(
            ERC20_TRANSFER_EVENT,
            contractAddress
        );
        if (tokenTransferEvents.length > 0) initialAddress = tokenTransferEvents[0].args.to;
    }

    forkedProvider = getEthersForkProvider(txEvent.block.number,
        [initialAddress, randomFromAddress, randomToAddress]
    );
    contract = new ethers.Contract(contractAddress, [
        "function balanceOf(address account) view returns (uint256)",
        "function transfer(address to, uint amount) returns (bool)"
    ], forkedProvider);

    const initalTokenBalance = await contract.balanceOf(initialAddress);
    if (initalTokenBalance.eq(0)) return [];

    await contract.connect(forkedProvider.getSigner(initialAddress)).transfer(randomFromAddress, initalTokenBalance);

    // test transfer tokens to another address 0, 30 and 365 days later
    const increaseTimes = [0, 60 * 60 * 24 * 30, 60 * 60 * 24 * 365];
    for (const increaseTime of increaseTimes) {
        await forkedProvider.send("evm_increaseTime", [increaseTime]);
        await forkedProvider.send("evm_mine");

        try {
            const fromBalanceBefore = await contract.balanceOf(randomFromAddress);
            await contract.connect(forkedProvider.getSigner(randomFromAddress)).transfer(randomToAddress, fromBalanceBefore);
            const toBalance = await contract.balanceOf(randomToAddress);
            await contract.connect(forkedProvider.getSigner(randomToAddress)).transfer(randomFromAddress, toBalance);
            const fromBalanceAfter = await contract.balanceOf(randomFromAddress);
            if (fromBalanceAfter.lt(fromBalanceBefore.mul(9).div(10))) {
                throw new Error("Honeypot detected");
            }
        } catch (e) {
            return [{
                name: "Dynamic Honeypot",
                description: "A dynamic honeypot was detected",
                alertId: "FORTA-3",
                severity: 3,
                type: "bad contract",
                metadata: {
                    contractAddress,
                    ast
                }
            }];
        }
    }

    return [];
}

class DynamicTest {
    constructor(sourceCode, constructorArguments) {
        this.sourceCode = sourceCode;

        let contractInfo;
        try {
            contractInfo = parseContract(sourceCode)
        } catch (e) {
            console.error(e.errors)
        }

        const entryContract = contractInfo.entryContract;
        const constructor = findConstructor(entryContract);
        let args = []
        if (constructor.parameters.length > 0) {
            const types = constructor.parameters.map(p => {
                const depth = [];
                let curr = p.typeName, name;

                while (true) {
                    if (curr.type === "ElementaryTypeName") {
                        name = curr.name;
                        break;
                    } else if (curr.type === "ArrayTypeName") {
                        depth.push(!!curr.length ? curr.length.toString() : "");
                        curr = curr.baseTypeName;
                    }
                }

                return `${name}${depth.map(d => `[${d}]`).join('')}`;
            });

            for (const arg of ethers.utils.defaultAbiCoder.decode(types, `0x${constructorArguments}`)) {
                if (ethers.BigNumber.isBigNumber(arg)) {
                    args.push(arg.toString());
                } else if (typeof arg === 'string') {
                    if (arg.startsWith("0x")) {
                        args.push(arg);
                    } else {
                        args.push(`"${arg}"`);
                    }
                } else {
                    args.push(arg);
                }
            }
        }

        this.testCode = `
contract DynamicFuzzingTest is Test {
    ${entryContract.name} target;
    address[] public actors;
    address internal currentActor;

    function setUp() public {
        target = new ${entryContract.name}(${args.join(", ")});
    }
    
    function invariant_transfer(uint256 actorIndexSeed) external {
        currentActor = actors[bound(actorIndexSeed, 0, actors.length - 1)];
        uint256 balanceBefore = target.balanceOf(currentActor);
        target.transfer(currentActor, 10000);
        uint256 balanceCurrent = target.balanceOf(currentActor);
        assertGt(balanceCurrent, balanceBefore);
        
        vm.startPrank(currentActor);
        uint256 balanceBeforePrank = target.balanceOf(0x2b5eA638b863eD0073499b4944edcf5aE9df5463);
        target.transfer(0x2b5eA638b863eD0073499b4944edcf5aE9df5463, balanceBefore);
        uint256 balanceCurrentPrank = target.balanceOf(0x2b5eA638b863eD0073499b4944edcf5aE9df5463);
        assertGt(balanceCurrentPrank, balanceBeforePrank);
        vm.stopPrank();
    }
}
`
    }

    insert() {
        return this.sourceCode += `\n${this.testCode}`;
    }
}

const StaticDetectHiddenMints = async (txEvent, contractAddress, parsedInfo) => {
    if (!parsedInfo.isTokenContract) return [];

    const publicFunctions = [], internalFunctions = [];
    let exploring = true;

    while (exploring) {
        exploring = false;
        parser.visit(parsedInfo.ast, {
            FunctionDefinition: function(node) {
                let hasExpressionsToIncreaseTotalSupply = false;
                parser.visit(node, {
                    BinaryOperation: function(op) {
                        if (op.left.type === 'Identifier' &&
                            op.left.name === '_totalSupply' &&
                            op.right.type === 'FunctionCall' &&
                            op.right.expression.type === 'MemberAccess' &&
                            op.right.expression.memberName === 'add'
                        ) {
                            hasExpressionsToIncreaseTotalSupply = true;
                        }

                        if (op.left.type === 'Identifier' &&
                            op.left.name === '_totalSupply' &&
                            op.operator === '+='
                        ) {
                            hasExpressionsToIncreaseTotalSupply = true;
                        }

                        if (op.left.type === 'Identifier' &&
                            op.left.name === '_totalSupply' &&
                            op.right.type === 'BinaryOperation' &&
                            op.right.operator === '+'
                        ) {
                            hasExpressionsToIncreaseTotalSupply = true;
                        }
                    },
                    FunctionCall: function(call) {
                        if (call.expression.type === 'Identifier' &&
                            (publicFunctions.includes(call.expression.name) || internalFunctions.includes(call.expression.name))
                        ) {
                            hasExpressionsToIncreaseTotalSupply = true;
                        }
                    }
                })

                if (hasExpressionsToIncreaseTotalSupply) {
                    if (publicFunctions.includes(node.name) || internalFunctions.includes(node.name)) return;
                    if (!node.name) return;

                    exploring = true;
                    if (
                        node.visibility === 'public' ||
                        node.visibility === 'external' ||
                        node.visibility === 'default')
                    {
                        publicFunctions.push(node.name);
                    } else {
                        internalFunctions.push(node.name);
                    }
                }
            }
        })
    }

    console.log(publicFunctions, internalFunctions);
}

const DynamicDetectFakeRenounceOwnership = async (txEvent, contractAddress, parsedInfo) => {
    if (!parsedInfo.isOwnableContract) return [];
    let contract;

    // query the owner
    contract = new ethers.Contract(contractAddress, [
        "function owner() view returns (address)"
    ], getEthersProvider());

    const owner = await contract.owner();
    const randomAddress = ethers.Wallet.createRandom().address;

    const forkedProvider = getEthersForkProvider(txEvent.block.number,
        [owner, randomAddress]
    );
    contract = new ethers.Contract(contractAddress, [
        "function owner() view returns (address)",
        "function transferOwnership(address newOwner) returns (bool)"
    ], getEthersProvider());
}

module.exports = {
    DefaultInjector,
    DynamicTest,
    DynamicDetectHoneypot,
    StaticDetectHiddenMints
}