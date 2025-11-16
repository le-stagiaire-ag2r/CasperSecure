# CasperSecure 🛡️

**Advanced Security Analyzer for Casper Smart Contracts**

CasperSecure is an automated security auditing tool that detects vulnerabilities in Casper Network smart contracts written in Rust. It uses static analysis, pattern recognition, and control flow analysis to identify common security issues before deployment.

![Version](https://img.shields.io/badge/Version-0.1.0-blue)
![Status](https://img.shields.io/badge/Status-MVP-green)
![License](https://img.shields.io/badge/License-MIT-green)

**Hackathon:** Casper Hackathon 2026 on DoraHacks
**Track:** Main Track
**Innovation:** First automated security auditor for Casper ecosystem

---

## 🚀 Features

### Current (V0.1.0 - MVP)

✅ **Rust AST Parser** - Parse Casper contracts into analyzable syntax trees
✅ **Static Analysis Engine** - Control flow and data flow analysis
✅ **5 Core Vulnerability Detectors:**
- 🔴 **Reentrancy Attacks** - Detects dangerous external calls before state updates
- 🟡 **Integer Overflow/Underflow** - Finds unchecked arithmetic operations
- 🔴 **Missing Access Control** - Identifies unprotected privileged functions
- 🟡 **Unchecked External Calls** - Detects calls without error handling
- 🔵 **Storage Collision Risks** - Finds potential key collision issues

✅ **Beautiful CLI** - Colored output with detailed recommendations
✅ **JSON Export** - Machine-readable reports for CI/CD integration

### Planned (V0.2.0+)

- 🔜 More detectors (DOS, timestamp dependence, etc.)
- 🔜 Machine learning-based pattern detection
- 🔜 CI/CD GitHub Action integration
- 🔜 Web UI for reports
- 🔜 Fix suggestions & auto-remediation

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

```
CasperSecure - Smart Contract Analyzer

Parsing contract: examples/contract.rs
  ✓ 3 entry points found
  ✓ 12 functions found

Analyzing contract...
  ✓ Control flow analysis complete
  ✓ Data flow analysis complete

Running vulnerability detectors...
  ✓ Detection complete

═══════════════════════════════════════════════════════════
SECURITY ANALYSIS REPORT
═══════════════════════════════════════════════════════════

Summary:
  Total vulnerabilities: 3
  High:     2
  Medium:   1

Detected Vulnerabilities:
────────────────────────────────────────────────────────────

1. Reentrancy [HIGH]
   Function: transfer
   Function 'transfer' performs external call before updating state.
   Recommendation: Follow Checks-Effects-Interactions pattern

2. Missing Access Control [HIGH]
   Function: withdraw
   Entry point 'withdraw' modifies state without access control.
   Recommendation: Add caller verification checks
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

| Detector | Severity | Description |
|----------|----------|-------------|
| Reentrancy | High | Detects external calls before state updates |
| Integer Overflow | Medium | Finds unchecked arithmetic (add, sub, mul) |
| Access Control | High | Identifies missing permission checks |
| Unchecked Calls | Medium | Detects calls without error handling |
| Storage Collision | Low | Finds risky storage key patterns |

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
