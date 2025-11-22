# CasperSecure Audit Registry Smart Contract

This is the on-chain component of CasperSecure that stores audit results on the Casper blockchain.

## Features

- **register_audit()** - Submit audit results to the blockchain
- **get_audit()** - Retrieve full audit record for a contract
- **get_security_score()** - Quick lookup of security score

## Building

The contract requires Rust nightly and the wasm32 target:

```bash
# Install nightly toolchain
rustup toolchain install nightly
rustup target add wasm32-unknown-unknown --toolchain nightly

# Build the contract
cargo +nightly build --release --target wasm32-unknown-unknown

# The compiled WASM will be at:
# target/wasm32-unknown-unknown/release/casper_audit_registry.wasm
```

## Deploying

Deploy to Casper testnet:

```bash
casper-client put-deploy \
  --chain-name casper-test \
  --node-address http://NODE_IP:7777 \
  --secret-key /path/to/secret_key.pem \
  --payment-amount 100000000000 \
  --session-path target/wasm32-unknown-unknown/release/casper_audit_registry.wasm
```

## Usage

After deployment, you can submit audits using the CasperSecure CLI:

```bash
casper-secure submit contract.rs \
  --contract-address hash-abc123 \
  --registry hash-xyz789
```

## Data Structure

Each audit record contains:
- Auditor address
- Timestamp
- Security score (0-100)
- Security grade (A+, A, B, C, D, F)
- Vulnerability counts (critical, high, medium, low, info)
- Contract source hash

All data is immutable and publicly verifiable on the Casper blockchain.
