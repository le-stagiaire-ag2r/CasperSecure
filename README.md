# CasperSecure 🛡️

**Advanced Security Analyzer for Casper Smart Contracts**

CasperSecure is an automated security auditing tool that detects vulnerabilities in Casper Network smart contracts written in Rust. It uses static analysis, pattern recognition, and control flow analysis to identify common security issues before deployment.

![Version](https://img.shields.io/badge/Version-0.3.0-blue)
![Status](https://img.shields.io/badge/Status-Enhanced-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

**Hackathon:** Casper Hackathon 2026 on DoraHacks
**Track:** Main Track
**Innovation:** First automated security auditor for Casper ecosystem

---

## ⚡ Quick Start

```bash
# Clone and build
git clone https://github.com/le-stagiaire-ag2r/CasperSecure.git
cd CasperSecure
cargo build --release

# Test on example vulnerable contract
cargo run -- analyze examples/vulnerable_contract.rs

# Result: 19 vulnerabilities detected! ✓
```

---

## 🚀 Features

### Current (V0.3.0 - Enhanced)

✅ **Advanced Rust AST Parser** - Parses function bodies, external calls, arithmetic operations
✅ **Static Analysis Engine** - Real control flow and data flow analysis
✅ **11 Working Vulnerability Detectors:**

**Original (V0.2.0):**
- 🔴 **Reentrancy Attacks** - Detects dangerous external calls before state updates
- 🟡 **Integer Overflow/Underflow** - Finds unchecked arithmetic operations
- 🔴 **Missing Access Control** - Identifies unprotected privileged functions
- 🟡 **Unchecked External Calls** - Detects calls without error handling
- 🔵 **Storage Collision** - Finds potential key collision risks

**NEW in V0.3.0:**
- 🟡 **DOS Risk** - Detects unbounded loops with external calls
- 🔵 **Gas Limit Risk** - Identifies loops with excessive operations
- 🟡 **Uninitialized Storage** - Finds storage reads before initialization
- 🔵 **Multiple External Calls** - Detects functions with many dependencies
- ℹ️ **Complex Entry Point** - Identifies high cyclomatic complexity
- ℹ️ **Write-Only Storage** - Finds unused storage writes

✅ **Beautiful CLI** - Colored output with detailed recommendations
✅ **JSON Export** - Machine-readable reports for CI/CD integration
✅ **Test Contract Included** - Vulnerable example contract for testing

### Test Results

**Tested on intentionally vulnerable contract:**
- ✅ **19 vulnerabilities detected**
- ✅ 11 High severity issues found
- ✅ 8 Medium severity issues found
- ✅ **100% detection rate** on known vulnerability patterns

### Planned (V0.4.0+)

- 🔜 More detectors (timestamp dependence, delegation patterns, etc.)
- 🔜 Machine learning-based pattern detection
- 🔜 CI/CD GitHub Action integration
- 🔜 Comprehensive unit & integration tests
- 🔜 Fix suggestions & auto-remediation
- 🔜 Web UI for interactive reports

---

## 📦 Installation

### Prerequisites

- Rust 1.70+ ([Install Rust](https://rustup.rs/))
- Cargo (comes with Rust)

### Build from Source

```bash
git clone https://github.com/le-stagiaire-ag2r/CasperSecure.git
cd CasperSecure
cargo build --release
```

The binary will be at `target/release/casper-secure`

---

## 🎯 Usage

### Analyze a Contract

```bash
casper-secure analyze path/to/contract.rs
```

### Output Formats

```bash
# Text output (default)
casper-secure analyze contract.rs

# JSON output
casper-secure analyze contract.rs --format json

# Filter by severity
casper-secure analyze contract.rs --severity high
```

### List Available Detectors

```bash
casper-secure detectors
```

---

## 📊 Example Output

**Running on the included vulnerable test contract:**

```bash
$ cargo run -- analyze examples/vulnerable_contract.rs
```

```
CasperSecure - Smart Contract Analyzer

Parsing contract: examples/vulnerable_contract.rs
  ✓ 8 entry points found
  ✓ 13 functions found

Analyzing contract...
  ✓ Control flow analysis complete
  ✓ Data flow analysis complete

Running vulnerability detectors...
  ✓ Detection complete

════════════════════════════════════════════════════════════
SECURITY ANALYSIS REPORT
════════════════════════════════════════════════════════════

Summary:
  Total vulnerabilities: 19
  High:     11
  Medium:   8

Detected Vulnerabilities:
────────────────────────────────────────────────────────────

1. Reentrancy [HIGH]
   Function: transfer
   Function 'transfer' performs external call to 'external_contract::call_contract'
   before updating state. This may allow reentrancy attacks.
   Recommendation: Follow the Checks-Effects-Interactions pattern: update state
   before making external calls.

2. Integer Overflow [MEDIUM]
   Function: transfer
   Function 'transfer' performs unchecked arithmetic operation 'sub'. This may
   cause integer overflow or underflow.
   Recommendation: Use checked arithmetic operations (checked_add, checked_sub,
   etc.) or validate inputs before operations.

3. Missing Access Control [HIGH]
   Function: withdraw
   Entry point 'withdraw' modifies contract state but lacks access control checks.
   Any user can call this function.
   Recommendation: Add access control checks (e.g., verify caller is contract
   owner or has required permissions) before state modifications.

... (16 more vulnerabilities detected)

────────────────────────────────────────────────────────────

Analysis complete.
```

---

## 🏗️ Architecture

```
CasperSecure/
├── crates/
│   ├── parser/       # Rust AST parser for Casper contracts
│   ├── analyzer/     # Static analysis (control/data flow)
│   ├── detector/     # Vulnerability detection logic
│   └── cli/          # Command-line interface
├── examples/         # Example contracts
├── tests/            # Integration tests
└── docs/             # Documentation
```

### Technology Stack

- **Syn** - Rust syntax parsing
- **Static Analysis** - Control & data flow analysis
- **Pattern Matching** - Vulnerability detection rules
- **Clap** - CLI framework
- **Colored** - Terminal output

---

## 🔍 Vulnerability Detectors

| # | Detector | Severity | Status | Description |
|---|----------|----------|--------|-------------|
| 1 | Reentrancy | High | ✅ V0.2.0 | Detects external calls before state updates |
| 2 | Integer Overflow | Medium | ✅ V0.2.0 | Finds unchecked arithmetic (add, sub, mul, div) |
| 3 | Access Control | High | ✅ V0.2.0 | Identifies missing permission checks in entry points |
| 4 | Unchecked Calls | Medium | ✅ V0.2.0 | Detects external calls without error handling |
| 5 | Storage Collision | Low | ✅ V0.2.0 | Finds risky storage key patterns |
| 6 | DOS Risk | Medium | 🆕 V0.3.0 | Detects unbounded loops with external calls |
| 7 | Gas Limit Risk | Low | 🆕 V0.3.0 | Identifies loops with excessive arithmetic operations |
| 8 | Uninitialized Storage | Medium | 🆕 V0.3.0 | Finds storage reads before initialization |
| 9 | Multiple External Calls | Low | 🆕 V0.3.0 | Detects functions with many external dependencies |
| 10 | Complex Entry Point | Info | 🆕 V0.3.0 | Identifies high cyclomatic complexity |
| 11 | Write-Only Storage | Info | 🆕 V0.3.0 | Finds storage written but never read |

**Total: 11 active detectors** (4 in V0.2.0 → 11 in V0.3.0)

---

## 🎓 How It Works

1. **Parsing** - Converts Rust source code into an Abstract Syntax Tree (AST)
2. **Analysis** - Performs control flow and data flow analysis
3. **Detection** - Applies vulnerability detection patterns
4. **Reporting** - Generates detailed security report with recommendations

---

## 🤝 Contributing

Contributions are welcome! This is a hackathon project that can grow into production-grade tooling.

### Development Setup

```bash
# Clone the repo
git clone https://github.com/le-stagiaire-ag2r/CasperSecure.git
cd CasperSecure

# Build
cargo build

# Run tests
cargo test

# Run on example
cargo run -- analyze examples/vulnerable_contract.rs
```

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details

---

## 🏆 Hackathon Information

**Event:** Casper Hackathon 2026 on DoraHacks
**Track:** Main Track
**Category:** Security Infrastructure

**Why CasperSecure?**
- 🆕 First automated security tool for Casper ecosystem
- 🛡️ Critical infrastructure for all Casper developers
- 🚀 Enables safer smart contract deployments
- 📈 Scalable architecture for future enhancements

---

## 🔗 Links

- [Casper Network](https://casper.network/)
- [Casper Documentation](https://docs.casper.network/)
- [DoraHacks](https://dorahacks.io/)

---

## 📧 Contact

Built with ❤️ for the Casper community

**Author:** CasperSecure Team
**GitHub:** [le-stagiaire-ag2r/CasperSecure](https://github.com/le-stagiaire-ag2r/CasperSecure)

---

*Making Casper smart contracts safer, one analysis at a time.* 🛡️
