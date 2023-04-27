# Hard Regpull Detection Agent

## Description

This agent trys to detect different kinds of hard rug pulls:
1. Honeypot: token holders are unable to transfer their tokens.
2. Hidden mints: tokens can be minted using hidden functions.
3. Fake ownership renounciation: renounced owners can somehow recover its ownership.
4. Hidden fee modifier: transfer fee can be modified using hidden functions.
5. Hidden transfer: token holders's tokens can be transferred by others.
6. Hidden transfer reverts: changeable parameters that can cause transfer to revert.

Current, this agent uses [invariant testing](https://book.getfoundry.sh/forge/invariant-testing) to detect the above mentioned rug pulls. Invariant testing is a technique that uses a set of invariants to test the correctness of a smart contract. For example, to detect `HiddenMints`, we can use the following invariant:

```solidity
assert(totalSupply() == initialSupply)
```

## Supported Chains

All chains that Forta supports.

## Alerts

When one of the above mentioned rug pull is detected:

- HARD-RUG-PULL-{RUGPULL_CATEGORY}-DYNAMIC
  - Fired when a created token contract is detected to be suspicious.
  - Severity is always set to "medium"
  - Type is always set to "suspicious"
  - Metadata:
    - attacker_deployer_address: the address of the attacker's deployer contract
    - token_contract_address: the address of the token contract
    - reason: the reason for the alert
    - couterexample: give a example sequence of function calls that trigger the alert

Here, {RUGPULL_CATEGORY} is the category of the rug pull. The following rug pull categories are supported:
 - HONEYPOT
 - HIDDENMINTS
 - FAKEOWNERSHIPRENOUNCIATION
 - HIDDENTRANSFERS
 - HIDDENFEEMODIFIERS
 - HIDDENTRANSFERREVERTS

When two or more of the above mentioned rug pull is detected, the agent will additionally fire the following alert:

- HARD-RUG-PULL-1
  - Fired when a created token contract is detected to be suspicious.
  - Severity is always set to "high"
  - Type is always set to "suspicious"
  - Metadata:
    - attacker_deployer_address: the address of the attacker's deployer contract
    - token_contract_address: the address of the token contract

### How to read the counterexample and the reason

A example below:
```shell
{"attacker_deployer_address":"0xfb941dd93dac213ecb38d6728901ce20234acac5","counterexample":"{\"Sequence\":[{\"sender\":\"0x7fa9385be102ac3eac297483dd6233d62b3e1496\",\"addr\":\"0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f\",\"calldata\":\"0xec28438a0000000000000000000000000000000000000000000000000000000000000001\",\"signature\":\"setMaxTxAmount(uint256)\",\"contract_name\":\"test/test.sol:NETWORK\",\"traces\":{\"arena\":[{\"parent\":null,\"children\":[],\"idx\":0,\"trace\":{\"depth\":0,\"success\":true,\"contract\":null,\"label\":null,\"caller\":\"0x7fa9385be102ac3eac297483dd6233d62b3e1496\",\"address\":\"0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f\",\"kind\":\"CALL\",\"value\":\"0x0\",\"data\":{\"Raw\":\"0xec28438a0000000000000000000000000000000000000000000000000000000000000001\"},\"output\":{\"Raw\":\"0x\"},\"gas_cost\":7457,\"status\":\"Stop\",\"call_context\":null,\"steps\":[]},\"ordering\":[]}]}}]}","reason":"Transfer amount exceeds the maxTxAmount.","token_contract_address":"0x1e9804d7a48F661871eFcdE4669b39263f47F3e4"}
```

The sequence is a ordered list of transactions that triggers the rugpull. So, if you deploy a new contract, and execute transactions as the sequence suggests, you will end up triggering the hard-rugpull (for this example you provide, it is the HiddenTransferReverts rug pull. Next. the reason field gives exact reason of why the rugpull took placed (in this case, it is because the transfer is reverted due to the error Transfer amount exceeds the maxTxAmount, where `maxTxAmount  is set by setMaxTxAmount function.) In other words, if the deployer calls the setMaxTxAmount function with 0, the transfer of the token is actually disabled, because no transfer can be made, which causes a hard-rugpull.

## Test

```shell
npm run tx 0xa6fa9abc4dcf094749997e57beb20b2287614bd9da34bcab1ffd912ccdd1775e
```

## Reproduce to test a token contract locally

1. get the transaction ID that deploys the token.
2. at `handleTransaction()` function in `agent.js`, change `false` in `provideHandleTransaction()` call to `true`
```js
// return await provideHandleTransaction(txEvent, false);
return await provideHandleTransaction(txEvent, true);
```
3run `npm run tx {TXID}`
