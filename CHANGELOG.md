# Changelog

All notable changes to CasperSecure are documented in this file.

---

## [6.0.0] - 2025-12-16

### Major Release - Casper-Specific Security Detectors

#### New Detectors (10 Casper-Specific)
- **CSPR-021** URef Access Rights [HIGH] - Detects URef operations without access rights validation (July 2024 $6.7M breach)
- **CSPR-022** Unprotected Init [CRITICAL] - Init functions callable multiple times (node doesn't enforce)
- **CSPR-023** Purse in Dictionary [CRITICAL] - Storing purses in dictionaries (ForgedReference error)
- **CSPR-024** Call Stack Depth [MEDIUM] - Cross-contract calls approaching 10 limit
- **CSPR-025** Dictionary Key Length [MEDIUM] - Keys exceeding 128 byte limit
- **CSPR-026** Unsafe Unwrap [MEDIUM] - Using .unwrap()/.expect() which can panic
- **CSPR-027** Missing Caller Validation [CRITICAL] - Ownership changes without verification
- **CSPR-028** Unbounded Loop [MEDIUM] - while/loop without clear bounds
- **CSPR-029** CEP Compliance [MEDIUM] - Missing required CEP-18/CEP-78 methods
- **CSPR-030** Odra Issues [MEDIUM] - Odra module without proper init

#### Parser V6.0
- Checked arithmetic detection (checked_add, checked_sub, saturating_*, wrapping_*)
- Odra 2.4.0 framework support (#[odra::module], Var<T>, Mapping<K,V>)
- Access control pattern recognition
- URef/Purse operation tracking
- Contract metadata extraction (CEP-18, CEP-78 detection)

#### Analyzer V6.0
- Real access control analysis (not just pattern matching)
- Call graph construction for depth analysis
- Storage initialization tracking
- Casper-specific analysis module
- Odra module analysis

#### CLI V6.0
- Category filtering (--category)
- Enhanced detector listing with categories
- Better output formatting
- Security grade scoring improvements

### Statistics
- **Total Detectors:** 30 (was 20)
- **New Code:** +2,452 lines
- **False Positive Reduction:** Significant improvement with checked arithmetic recognition

---

## [5.0.0] - 2025-11-22

### Major Release - On-Chain Audit Registry

#### On-Chain Components
- **Audit Registry Smart Contract** - Store audit results on Casper blockchain
- `register_audit()` - Submit audit results on-chain
- `get_audit()` - Retrieve full audit record
- `get_security_score()` - Quick score lookup (0-100)
- Immutable storage with blockchain timestamp

#### CLI Enhancements
- New `submit` command for on-chain registration
- Contract hash (MD5) generation
- Deployment instructions display

#### Architecture
- New crate: `crates/contract/` for smart contract
- Added casper-client 2.0, casper-types 4.0
- WebAssembly compilation ready

---

## [4.0.0] - 2025-11-20

### New Detectors (9 new, total 20)
- **CSPR-012** Timestamp Manipulation [MEDIUM]
- **CSPR-013** Unchecked Return Values [MEDIUM]
- **CSPR-014** Dangerous Delegatecall [HIGH]
- **CSPR-015** Redundant Code [INFO]
- **CSPR-016** Dead Code [INFO]
- **CSPR-017** Magic Numbers [INFO]
- **CSPR-018** Unsafe Type Casting [LOW]
- **CSPR-019** Inefficient Storage [MEDIUM]
- **CSPR-020** Missing Events [LOW]

---

## [0.3.0] - 2025-11-15

### New Detectors (6 new, total 11)
- **CSPR-006** DOS Risk [MEDIUM]
- **CSPR-007** Gas Limit Risk [LOW]
- **CSPR-008** Uninitialized Storage [MEDIUM]
- **CSPR-009** Multiple External Calls [LOW]
- **CSPR-010** Complex Entry Point [INFO]
- **CSPR-011** Write-Only Storage [INFO]

---

## [0.2.0] - 2025-11-10

### Initial Release
- 5 core vulnerability detectors
- **CSPR-001** Reentrancy [HIGH]
- **CSPR-002** Integer Overflow [MEDIUM]
- **CSPR-003** Access Control [HIGH]
- **CSPR-004** Unchecked Calls [MEDIUM]
- **CSPR-005** Storage Collision [LOW]
- Basic Rust AST parser
- CLI with analyze and detectors commands
- Security scoring system (0-100)
- Security grading (A+ to F)

---

## Archives

Historical release notes are available in the `archive/` folder:
- `archive/RELEASE_NOTES_V5.md` - Detailed V5.0.0 release notes
