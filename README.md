# <h1 align="center">Puffer Preconf: A Based Rollup Solution</h1>

[![Website][Website-badge]][Website] [![Docs][docs-badge]][docs]
[![Discord][discord-badge]][discord] [![X][X-badge]][X] [![Foundry][foundry-badge]][foundry]

[Website-badge]: https://img.shields.io/badge/WEBSITE-8A2BE2
[Website]: https://unifi.puffer.fi
[X-badge]: https://img.shields.io/twitter/follow/puffer_unifi
[X]: https://twitter.com/puffer_unifi
[discord-badge]: https://dcbadge.vercel.app/api/server/pufferfi?style=flat
[discord]: https://discord.gg/pufferfi
[docs-badge]: https://img.shields.io/badge/DOCS-8A2BE2
[docs]: https://unifi.puffer.fi/files/Puffer-UniFi-Litepaper.pdf
[foundry]: https://getfoundry.sh
[foundry-badge]: https://img.shields.io/badge/Built%20with-Foundry-FFDB1C.svg

## Overview

Puffer Preconf is a based rollup solution designed to enhance Ethereum's scalability while maintaining its core principles.

A based rollup is an L1-sequenced rollup that leverages Ethereum's existing validator set for block production, offering improved liveness guarantees and simplified architecture compared to traditional rollups.

This repository contains all the pieces that make up UniFi.

## Key Concepts

### Pre-confirmations (Pre-confs)

Pre-confs are a mechanism in Ethereum where validators commit to including transactions in their blocks before proposing them to L1. This process significantly improves user experience by providing near-instant transaction confirmations (~100ms instead of 12s).

### Actively Validated Service (AVS)
The UniFi AVS is the core component of our based rollup solution. It's an Eigenlayer AVS and is managed primarily through the UniFiAVSManager contract, which handles critical functions such as:

- Registration and deregistration of operators and validators
- Implementation of the pre-confirmation system for faster transaction finality
- Slashing mechanism to ensure accountability
- Rewards distribution for distributing validator rewards

To learn more about the UniFi AVS components and how to interact with the AVS contracts, check the [documentation here](l1-contracts/docs/readme.md).

### Commit-Boost

UniFi AVS integrates Commit-Boost, an open-source component that enhances proposer commitment protocols. This integration allows for standardization and easier implementation of pre-confirmation services.

### Node Software

Validators participating in UniFi AVS run Commit-Boost alongside their standard validator stack. This setup enables seamless participation in the pre-confirmation process while maintaining regular validation duties.

## Deployments

For detailed information on deployments (Mainnet, Testnet, etc.) and ABIs, please check our [Deployments and ACL](./docs/README.md) doc.

## Audits

- Audit reports will be listed here once available.

## How to Run Tests

1. Clone this repository
2. Install dependencies: `yarn install`
3. Run tests: `cd l1-contracts/ && forge test`


## Neutrality

UniFi AVS is designed with a strong commitment to neutrality. It ensures permissionless participation, integrates with a neutral registry, and avoids requiring specific governance tokens for participation.
