# CasperSecure Guide - V6.0

A practical guide to using CasperSecure for Casper smart contract security analysis.

---

## What is CasperSecure?

CasperSecure is an automated security tool that:

1. **Analyzes** your Rust smart contract code
2. **Detects** 30 types of vulnerabilities
3. **Reports** issues with severity and fix recommendations
4. **Scores** your contract's security (0-100)
5. **Certifies** audits on-chain (optional)

---

## Quick Example

### You write this code:

```rust
pub fn transfer(recipient: String, amount: u64) {
    // External call BEFORE state update
    call_external_contract(recipient, amount);

    // State update AFTER
    let balance = get_balance();
    set_balance(balance - amount);  // Unchecked arithmetic!
}
```

### CasperSecure detects:

```
1. Reentrancy [HIGH]
   External call before state update allows reentrancy attacks.
   Fix: Update state BEFORE making external calls.

2. Integer Overflow [MEDIUM]
   Unchecked arithmetic operation 'sub'.
   Fix: Use checked_sub() or saturating_sub().
```

### You fix to:

```rust
pub fn transfer(recipient: String, amount: u64) {
    // State update FIRST
    let balance = get_balance();
    let new_balance = balance.checked_sub(amount)
        .expect("Insufficient balance");
    set_balance(new_balance);

    // External call AFTER
    call_external_contract(recipient, amount);
}
```

---

## The 30 Detectors

### Critical (3)
| ID | Name | What it catches |
|----|------|-----------------|
| CSPR-022 | Unprotected Init | Init callable multiple times |
| CSPR-023 | Purse in Dictionary | Purses stored in dictionaries |
| CSPR-027 | Missing Caller Validation | Ownership changes without verification |

### High (4)
| ID | Name | What it catches |
|----|------|-----------------|
| CSPR-001 | Reentrancy | External calls before state updates |
| CSPR-003 | Access Control | Missing permission checks |
| CSPR-014 | Dangerous Delegatecall | Risky delegatecall patterns |
| CSPR-021 | URef Access Rights | URef without access check |

### Medium (13)
| ID | Name | What it catches |
|----|------|-----------------|
| CSPR-002 | Integer Overflow | Unchecked arithmetic |
| CSPR-004 | Unchecked Calls | External calls without error handling |
| CSPR-006 | DOS Risk | Unbounded loops with external calls |
| CSPR-008 | Uninitialized Storage | Storage read before init |
| CSPR-012 | Timestamp Manipulation | Manipulable timestamps |
| CSPR-013 | Unchecked Return Values | Unchecked call returns |
| CSPR-019 | Inefficient Storage | Storage writes in loops |
| CSPR-024 | Call Stack Depth | Call depth > 10 |
| CSPR-025 | Dictionary Key Length | Keys > 128 bytes |
| CSPR-026 | Unsafe Unwrap | .unwrap()/.expect() usage |
| CSPR-028 | Unbounded Loop | while/loop without bounds |
| CSPR-029 | CEP Compliance | Missing CEP methods |
| CSPR-030 | Odra Issues | Odra module problems |

### Low (5)
| ID | Name | What it catches |
|----|------|-----------------|
| CSPR-005 | Storage Collision | Short storage keys |
| CSPR-007 | Gas Limit Risk | Expensive loops |
| CSPR-009 | Multiple External Calls | Too many dependencies |
| CSPR-018 | Unsafe Type Casting | Unsafe type conversions |
| CSPR-020 | Missing Events | State changes without events |

### Info (5)
| ID | Name | What it catches |
|----|------|-----------------|
| CSPR-010 | Complex Entry Point | High complexity |
| CSPR-011 | Write-Only Storage | Storage never read |
| CSPR-015 | Redundant Code | Duplicate patterns |
| CSPR-016 | Dead Code | Unused functions |
| CSPR-017 | Magic Numbers | Hardcoded values |

---

## V6.0 Casper-Specific Vulnerabilities

### URef Access Rights (CSPR-021)

**The Problem:** In July 2024, $6.7M was stolen because URef access rights weren't validated.

```rust
// BAD - No access check
pub fn withdraw(uref: URef) {
    let value = storage::read(uref);  // Anyone can read!
}

// GOOD - Check access rights
pub fn withdraw(uref: URef) {
    if !uref.is_readable() {
        revert(Error::NoAccess);
    }
    let value = storage::read(uref);
}
```

### Unprotected Init (CSPR-022)

**The Problem:** Casper doesn't enforce single-call on init functions.

```rust
// BAD - Can be called multiple times
#[no_mangle]
pub extern "C" fn init() {
    set_key("owner", get_caller());
}

// GOOD - Check if already initialized
#[no_mangle]
pub extern "C" fn init() {
    if storage::has_key("initialized") {
        revert(Error::AlreadyInitialized);
    }
    set_key("owner", get_caller());
    set_key("initialized", true);
}
```

### Purse in Dictionary (CSPR-023)

**The Problem:** Storing purses in dictionaries causes ForgedReference errors.

```rust
// BAD - Purse in dictionary
let purse = system::create_purse();
dictionary::put("purses", user, purse);  // ForgedReference!

// GOOD - Store purse in named keys
let purse = system::create_purse();
runtime::put_key(&format!("purse_{}", user), purse.into());
```

### Call Stack Depth (CSPR-024)

**The Problem:** Casper limits call stack to 10 contracts.

```rust
// BAD - Deep call chain
fn process() {
    contract_a::call();  // -> calls contract_b
                         // -> calls contract_c
                         // -> ... (max 10 total!)
}

// GOOD - Flatten call structure
fn process() {
    let data = contract_a::get_data();
    let result = process_locally(data);
    contract_b::store_result(result);
}
```

---

## Scoring System

| Score | Grade | Meaning |
|-------|-------|---------|
| 95-100 | A+ | Excellent - Minor issues only |
| 90-94 | A | Very good |
| 80-89 | B | Good - Some issues to fix |
| 70-79 | C | Average - Multiple issues |
| 60-69 | D | Poor - Significant issues |
| 0-59 | F | Dangerous - Do not deploy! |

**Point deductions:**
- Critical: -50 points
- High: -15 points
- Medium: -5 points
- Low: -2 points
- Info: -1 point

---

## Usage Examples

### Basic Analysis

```bash
casper-secure analyze my_contract.rs
```

### JSON Output (CI/CD)

```bash
casper-secure analyze my_contract.rs --format json > report.json
```

### Filter by Severity

```bash
casper-secure analyze my_contract.rs --severity high
```

### Filter by Category

```bash
casper-secure analyze my_contract.rs --category casper-specific
```

### On-Chain Certification

```bash
casper-secure submit my_contract.rs --contract-address hash-abc123
```

---

## Odra 2.4.0 Support

CasperSecure understands Odra framework patterns:

```rust
#[odra::module]
pub struct MyToken {
    balances: Mapping<Address, U256>,
    total_supply: Var<U256>,
}

#[odra::module]
impl MyToken {
    #[odra(init)]  // CasperSecure checks this is protected
    pub fn init(&mut self, supply: U256) {
        self.total_supply.set(supply);
    }
}
```

**Detected issues:**
- Missing `#[odra(init)]` protection
- Incorrect Var/Mapping usage
- Missing required methods

---

## Best Practices

1. **Always check external call results**
2. **Update state BEFORE external calls**
3. **Use checked arithmetic** (`checked_add`, `saturating_sub`)
4. **Add access control to sensitive functions**
5. **Validate URef access rights**
6. **Protect init functions from re-calling**
7. **Never store purses in dictionaries**
8. **Keep call depth under 10**
9. **Limit dictionary keys to 128 bytes**
10. **Emit events for state changes**

---

## FAQ

**Q: Does CasperSecure replace manual audits?**
A: No. Use it as a first line of defense, but professional audits are recommended for production contracts.

**Q: Can it auto-fix issues?**
A: Not yet. It provides fix recommendations that you implement manually.

**Q: Is the on-chain registry mandatory?**
A: No. It's optional for public certification.

**Q: Does it work with Odra?**
A: Yes! V6.0 has full Odra 2.4.0 support.

---

## Links

- [README](README.md) - Full documentation
- [CHANGELOG](CHANGELOG.md) - Version history
- [Examples](examples/) - Sample contracts
- [Casper Docs](https://docs.casper.network/)
- [Odra Docs](https://odra.dev/)

---

*Making Casper smart contracts safer, one analysis at a time.*
