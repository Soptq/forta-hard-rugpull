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

When two or more of the above mentioned rug pull is detected, the agent will additionally fire the following alert:

- HARD-RUG-PULL-1
  - Fired when a created token contract is detected to be suspicious.
  - Severity is always set to "high"
  - Type is always set to "suspicious"
  - Metadata:
    - attacker_deployer_address: the address of the attacker's deployer contract
    - token_contract_address: the address of the token contract

## Test

```shell
npm run tx 0xa6fa9abc4dcf094749997e57beb20b2287614bd9da34bcab1ffd912ccdd1775e
```
