# CasperSecure

**Advanced Security Analyzer for Casper Smart Contracts**

CasperSecure is an automated security auditing tool that detects vulnerabilities in Casper Network smart contracts written in Rust. It uses static analysis, pattern recognition, and Casper-specific security checks to identify issues before deployment.

![Version](https://img.shields.io/badge/Version-6.0.0-blue)
![Detectors](https://img.shields.io/badge/Detectors-30-orange)
![Casper](https://img.shields.io/badge/Casper-Specific-purple)
![Odra](https://img.shields.io/badge/Odra-2.4.0-green)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Quick Start

```bash
# Clone and build
git clone https://github.com/le-stagiaire-ag2r/CasperSecure.git
cd CasperSecure
cargo build --release

# Analyze a contract
cargo run -- analyze examples/vulnerable_contract.rs

# List all 30 detectors
cargo run -- detectors

# Filter by category
cargo run -- analyze contract.rs --category casper-specific
```

---

## Features

### V6.0 - Casper-Specific Security (Current)

**30 Vulnerability Detectors:**
- 20 original detectors (reentrancy, overflow, access control, etc.)
- 10 NEW Casper-specific detectors based on real vulnerabilities

**Casper-Specific Checks:**
- URef access rights validation (July 2024 $6.7M breach prevention)
- Unprotected init detection (node doesn't enforce single-call)
- Purse in dictionary detection (ForgedReference error)
- Call stack depth analysis (max 10 contracts)
- Dictionary key length validation (128 bytes limit)
- CEP-18/CEP-78 compliance checking

**Odra 2.4.0 Support:**
- `#[odra::module]` detection
- `Var<T>`, `Mapping<K,V>`, `List<T>` analysis
- `#[odra(init)]` protection checking

**Reduced False Positives:**
- Checked arithmetic recognition (`checked_add`, `saturating_sub`, etc.)
- Real access control analysis (not just pattern matching)
- Context-aware detection

**On-Chain Audit Registry:**
- Store audit results on Casper blockchain
- Public verification of security scores
- Immutable audit history

---

## Installation

### Prerequisites
- Rust 1.70+ ([Install Rust](https://rustup.rs/))

### Build from Source

```bash
git clone https://github.com/le-stagiaire-ag2r/CasperSecure.git
cd CasperSecure
cargo build --release
```

Binary: `target/release/casper-secure`

---

## Usage

### Analyze a Contract

```bash
# Basic analysis
casper-secure analyze path/to/contract.rs

# JSON output for CI/CD
casper-secure analyze contract.rs --format json

# Filter by severity
casper-secure analyze contract.rs --severity high

# Filter by category (V6.0)
casper-secure analyze contract.rs --category casper-specific
```

### List Detectors

```bash
casper-secure detectors
```

### Submit to On-Chain Registry

```bash
casper-secure submit contract.rs --contract-address hash-abc123
```

---

## Example Output

```bash
$ cargo run -- analyze examples/vulnerable_contract.rs
```

```
CasperSecure V6.0 - Smart Contract Analyzer
30 Detectors | Casper-Specific | Odra 2.4.0 Support

Parsing contract: examples/vulnerable_contract.rs
  ✓ 8 entry points found
  ✓ 13 functions found

Analyzing contract...
  ✓ Control flow analysis complete
  ✓ Data flow analysis complete
  ✓ Storage analysis complete
  ✓ Security patterns detected

Running 30 vulnerability detectors...
  ✓ Detection complete

════════════════════════════════════════════════════════════
SECURITY ANALYSIS REPORT
════════════════════════════════════════════════════════════

Summary:
  Total vulnerabilities: 16
  Detectors run: 30
  Security Score: 15/100
  Security Grade: F

  Medium:   16

  CONTRACT IS DANGEROUS - DO NOT DEPLOY!

Detected Vulnerabilities:
────────────────────────────────────────────────────────────

1. Integer Overflow [MEDIUM] [CSPR-002]
   Category: Arithmetic
   Function: transfer
   Function 'transfer' performs unchecked arithmetic operation 'sub'.
   Fix: Use checked arithmetic operations (checked_add, checked_sub, etc.)

2. Unsafe Unwrap [MEDIUM] [CSPR-026]
   Category: Security
   Function: withdraw
   Function 'withdraw' uses unsafe .unwrap() which can panic.
   Fix: Use .unwrap_or(), .unwrap_or_default(), or ? operator.

... (14 more vulnerabilities)

────────────────────────────────────────────────────────────
Analysis complete.
```

---

## Vulnerability Detectors (30 Total)

### Original Detectors (V0.2.0 - V4.0)

| ID | Detector | Severity | Description |
|----|----------|----------|-------------|
| CSPR-001 | Reentrancy | HIGH | External calls before state updates |
| CSPR-002 | Integer Overflow | MEDIUM | Unchecked arithmetic operations |
| CSPR-003 | Access Control | HIGH | Missing permission checks |
| CSPR-004 | Unchecked Calls | MEDIUM | External calls without error handling |
| CSPR-005 | Storage Collision | LOW | Risky storage key patterns |
| CSPR-006 | DOS Risk | MEDIUM | Unbounded loops with external calls |
| CSPR-007 | Gas Limit Risk | LOW | Loops with excessive operations |
| CSPR-008 | Uninitialized Storage | MEDIUM | Storage read before initialization |
| CSPR-009 | Multiple External Calls | LOW | Many external dependencies |
| CSPR-010 | Complex Entry Point | INFO | High cyclomatic complexity |
| CSPR-011 | Write-Only Storage | INFO | Storage never read |
| CSPR-012 | Timestamp Manipulation | MEDIUM | Manipulable block timestamps |
| CSPR-013 | Unchecked Return Values | MEDIUM | Unchecked call returns |
| CSPR-014 | Dangerous Delegatecall | HIGH | Risky delegatecall usage |
| CSPR-015 | Redundant Code | INFO | Duplicate patterns |
| CSPR-016 | Dead Code | INFO | Unused private functions |
| CSPR-017 | Magic Numbers | INFO | Hardcoded numbers |
| CSPR-018 | Unsafe Type Casting | LOW | Unsafe type conversions |
| CSPR-019 | Inefficient Storage | MEDIUM | Storage writes in loops |
| CSPR-020 | Missing Events | LOW | State changes without events |

### NEW V6.0 Casper-Specific Detectors

| ID | Detector | Severity | Description |
|----|----------|----------|-------------|
| CSPR-021 | URef Access Rights | HIGH | URef ops without access check (July 2024 breach) |
| CSPR-022 | Unprotected Init | CRITICAL | Init callable multiple times |
| CSPR-023 | Purse in Dictionary | CRITICAL | Purses in dictionaries (ForgedReference) |
| CSPR-024 | Call Stack Depth | MEDIUM | Call depth approaching 10 limit |
| CSPR-025 | Dictionary Key Length | MEDIUM | Keys exceeding 128 bytes |
| CSPR-026 | Unsafe Unwrap | MEDIUM | .unwrap()/.expect() usage |
| CSPR-027 | Missing Caller Validation | CRITICAL | Ownership changes without verification |
| CSPR-028 | Unbounded Loop | MEDIUM | while/loop without bounds |
| CSPR-029 | CEP Compliance | MEDIUM | Missing CEP-18/CEP-78 methods |
| CSPR-030 | Odra Issues | MEDIUM | Odra module without init |

---

## Architecture

```
CasperSecure/
├── crates/
│   ├── parser/       # Rust AST parser with Casper/Odra support
│   ├── analyzer/     # Static analysis engine
│   ├── detector/     # 30 vulnerability detectors
│   ├── cli/          # Command-line interface
│   └── contract/     # On-chain audit registry
├── examples/         # Example vulnerable contracts
├── archive/          # Historical release notes
└── CHANGELOG.md      # Version history
```

### Technology Stack

**Analysis Engine:**
- Syn - Rust syntax parsing
- Static Analysis - Control & data flow
- Pattern Matching - Vulnerability detection
- Casper-Specific - URef, Purse, Call stack analysis

**CLI:**
- Clap - Command framework
- Colored - Terminal output

**On-Chain:**
- Casper Contract API
- WASM compilation

---

## Security Research

CasperSecure V6.0 detectors are based on:

- **Halborn Security Audits** - Casper 2.0 audit findings
- **July 2024 URef Breach** - $6.7M stolen via access rights bypass
- **Casper Documentation** - Official storage and call stack limits
- **Odra Framework** - Common patterns and anti-patterns

---

## Contributing

```bash
# Clone
git clone https://github.com/le-stagiaire-ag2r/CasperSecure.git
cd CasperSecure

# Build
cargo build

# Test
cargo test

# Run
cargo run -- analyze examples/vulnerable_contract.rs
```

---

## License

MIT License - See [LICENSE](LICENSE) for details

---

## Links

- [Casper Network](https://casper.network/)
- [Casper Documentation](https://docs.casper.network/)
- [Odra Framework](https://odra.dev/)
- [Changelog](CHANGELOG.md)

---

**GitHub:** [le-stagiaire-ag2r/CasperSecure](https://github.com/le-stagiaire-ag2r/CasperSecure)

*Making Casper smart contracts safer, one analysis at a time.*
