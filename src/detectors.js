const {
    ethers,
    getJsonRpcUrl,
} = require("forta-agent");
const parser = require('@solidity-parser/parser');
const { parseContract } = require('./parser')
const prettier = require("prettier");
const fs = require('fs');
const shell = require('shelljs');

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
    const contractInfo = parseContract(formattedSourceCode)

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
        if (contractInfo.internalFunctions.includes('_mint')) {
            // inject _mint() to constructor
            injectCode += '_mint(msg.sender, 1e20); '
        }
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
    if (injectSourceCode.includes("pragma experimental ABIEncoderV2") < 0) {
        injectSourceCode += '\npragma experimental ABIEncoderV2;\n';
    }
    injectSourceCode += '\nimport "forge-std/Test.sol";\n';
    return prettier.format(injectSourceCode, {
        parser: 'solidity-parse',
    })
}

class DynamicTest {
    constructor(sourceCode, constructorArguments) {
        this.sourceCode = sourceCode;

        let contractInfo;
        contractInfo = parseContract(sourceCode)
        this.contractInfo = contractInfo;

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

        this.testHoneypot = `
contract DynamicHoneypotTest is Test {
    ${entryContract.name} target;
    bool willSkip;

    function setUp() public {
        target = new ${entryContract.name}(${args.join(", ")});
        ${this.contractInfo.hasBalanceVariable ? 'deal(address(target), address(this), 1e20);' : ''}
        uint balanceInitial = target.balanceOf(address(this));
        if (balanceInitial > 0) {
            willSkip = false;
            target.transfer(address(0x1), 100000000);
        } else {
            willSkip = true;
        }
        skip(60 * 60 * 24 * 365);
    }
    
    function invariant_transfer() external {
        if (willSkip) return;
    
        uint balanceInitial = target.balanceOf(address(0x1));
        if (balanceInitial > 0) {
            vm.startPrank(address(0x1));
            uint256 balanceBefore = target.balanceOf(address(0x2));
            target.transfer(address(0x2), 100);
            uint256 balanceAfter = target.balanceOf(address(0x2));
            assertGt(balanceAfter, balanceBefore);
            vm.stopPrank();
        }
    }
}
`
        this.testHiddenMints = `
contract DynamicHiddenMintsTest is Test {
    ${entryContract.name} target;
    uint256 totalSupply;

    function setUp() public {
        target = new ${entryContract.name}(${args.join(", ")});
        totalSupply = target.totalSupply();
        targetSender(address(this));
        skip(60 * 60 * 24 * 365);
    }
    
    function invariant_totalsupply() external {
        assertTrue(totalSupply >= target.totalSupply());
    }
}
`
        this.testFakeOwnershipRenounciation = `
contract DynamicFakeOwnershipRenounciationTest is Test {
    ${entryContract.name} target;

    function setUp() public {
        target = new ${entryContract.name}(${args.join(", ")});
        targetSender(address(this));
        // transfer ownership to 0x1
        target.transferOwnership(address(0x1));
        excludeSender(address(0x1));
        skip(60 * 60 * 24 * 365);
    }
    
    function invariant_ownership() external {
        assertTrue(target.owner() != msg.sender);
    }
}
`
        this.testHiddenTransfers = `
contract DynamicHiddenTransfersTest is Test {
    ${entryContract.name} target;
    uint256 balance;
    bool willSkip;

    function setUp() public {
        target = new ${entryContract.name}(${args.join(", ")});
        ${this.contractInfo.hasBalanceVariable ? 'deal(address(target), address(this), 1e20);' : ''}
        uint balanceInitial = target.balanceOf(address(this));
        if (balanceInitial > 0) {
            willSkip = false;
            target.transfer(address(0x1), 100000000);
            balance = target.balanceOf(address(0x1));
        } else {
            willSkip = true;
        }
        targetSender(address(this));
        excludeSender(address(0x1));
        skip(60 * 60 * 24 * 365);
    }
    
    function invariant_balances() external {
        if (willSkip) return;
        assertTrue(target.balanceOf(address(0x1)) >= balance);
    }
}
`
        this.testHiddenFeeModifiers = `
contract DynamicHiddenFeeModifiersTest is Test {
    ${entryContract.name} target;
    uint256 fee;
    bool willSkip;

    function setUp() public {
        target = new ${entryContract.name}(${args.join(", ")});
        ${this.contractInfo.hasBalanceVariable ? 'deal(address(target), address(this), 1e20);' : ''}
        uint balanceInitial = target.balanceOf(address(this));
        if (balanceInitial > 0) {
            willSkip = false;
            target.transfer(address(0x1), 1e6);
            // get current Fee
            vm.startPrank(address(0x1));
            uint256 balanceBefore = target.balanceOf(address(0x2));
            target.transfer(address(0x2), 1e5);
            uint256 balanceAfter = target.balanceOf(address(0x2));
            fee = 1e5 - (balanceAfter - balanceBefore);
            vm.stopPrank();
        } else {
            willSkip = true;
        }
        targetSender(address(this));
        skip(60 * 60 * 24 * 365);
    }
    
    function invariant_fee() external {
        if (willSkip) return;
        
        vm.startPrank(address(0x1));
        uint256 balanceBefore = target.balanceOf(address(0x2));
        target.transfer(address(0x2), 1e5);
        uint256 balanceAfter = target.balanceOf(address(0x2));
        uint256 currentFee = 1e5 - (balanceAfter - balanceBefore);
        vm.stopPrank();
        assertEq(fee, currentFee);
    }
}
`
        this.testHiddenTransferReverts = `
contract DynamicHiddenTransferRevertsTest is Test {
    ${entryContract.name} target;
    bool willSkip;

    function setUp() public {
        target = new ${entryContract.name}(${args.join(", ")});
        ${this.contractInfo.hasBalanceVariable ? 'deal(address(target), address(this), 1e20);' : ''}
        uint balanceInitial = target.balanceOf(address(this));
        if (balanceInitial > 0) {
            willSkip = false;
            target.transfer(address(0x1), 100000000);
        } else {
            willSkip = true;
        }
        targetSender(address(this));
        skip(60 * 60 * 24 * 365);
    }
    
    function invariant_transfer_without_revert() external {
        if (willSkip) return;
        
        vm.startPrank(address(0x1));
        uint256 selfBalance = target.balanceOf(address(0x1));
        target.transfer(address(0x2), selfBalance);
        vm.stopPrank();
    }
}
`
    }

    async test(txEvent) {
        if (!this.contractInfo.isTokenContract && !this.contractInfo.isOwnableContract) {
            console.log(`Tests skipped for ${txEvent.transaction.hash}`);
            return {};
        }

        let testedCode = this.sourceCode

        if (this.contractInfo.isTokenContract) {
            testedCode += `\n${this.testHoneypot}`;
            testedCode += `\n${this.testHiddenMints}`;
            testedCode += `\n${this.testHiddenTransfers}`;
            testedCode += `\n${this.testHiddenFeeModifiers}`;
            testedCode += `\n${this.testHiddenTransferReverts}`;
        }

        if (this.contractInfo.isOwnableContract) {
            testedCode += `\n${this.testFakeOwnershipRenounciation}`;
        }

        fs.writeFileSync('./test/test.sol', testedCode, 'utf8');

        let testResultJson;
        try {
            const testCommand = `RUST_LOG=off forge test -f ${getJsonRpcUrl()} --fork-block-number ${txEvent.block.number} --json --silent`
            const timeBefore = Date.now();
            const testResult = await shell.exec(testCommand, {silent: true}).toString();
            const timeAfter = Date.now();
            console.log(`Tested ${txEvent.transaction.hash}: ${timeAfter - timeBefore}ms`);
            testResultJson = JSON.parse(testResult);
        } catch (e) {
            console.error(e)
            return {};
        }

        return testResultJson;
    }
}

module.exports = {
    DefaultInjector,
    DynamicTest,
}