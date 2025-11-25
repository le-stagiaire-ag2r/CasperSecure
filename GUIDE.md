# 🛡️ CasperSecure Guide - What is it?

CasperSecure explained simply, with concrete examples

# 🤔 What is CasperSecure?

Imagine you're writing a program to manage money on the Casper blockchain (a smart contract). CasperSecure is like a **security inspector + certificate of authenticity** that:

**OFF-CHAIN (On your computer):**
- Reads your code automatically
- Finds all security problems
- Gives you advice to fix them

**ON-CHAIN (On the blockchain) 🆕:**
- Records your audit result on Casper blockchain
- Creates an immutable public certificate
- Anyone can verify your contract is audited

**In short:**
1. You write your smart contract in Rust
2. CasperSecure analyzes your code automatically (OFF-CHAIN)
3. It shows you all the security problems + advice
4. You can register the audit on the blockchain (ON-CHAIN) 🆕
5. Everyone can verify you're audited ✅

**It's like an antivirus + SSL certificate, but for your code!** 🔍🔐

---

# 🎯 Why is it important?

Smart contracts manage money. If your code has a security bug, someone can steal all the money!

**Real examples of hacks:**
- The DAO (Ethereum): $60 million stolen due to reentrancy flaw
- Poly Network: $600 million stolen due to bugs
- Harmony Bridge: $100 million stolen

**With CasperSecure V5.0:**
- ✅ Avoid errors BEFORE deploying
- ✅ **Prove publicly you're audited** (blockchain certificate) 🆕
- ✅ Build trust with your users 🆕

---

# 📖 Concrete Example - Complete Workflow

## Step 1: You wrote this code

```rust
// Your smart contract that manages tokens
pub fn transfer(recipient: String, amount: u64) {
    // 1. We call another contract
    call_external_contract(recipient, amount);

    // 2. We update the balance AFTER the call
    let balance = get_balance();
    set_balance(balance - amount);  // ⚠️ DANGER!
}
```

## Step 2: You run CasperSecure (OFF-CHAIN)

```bash
casper-secure analyze my_contract.rs
```

## Step 3: CasperSecure tells you what's wrong

```
🔴 REENTRANCY ATTACK FOUND!

Problem: You're calling an external contract BEFORE updating the balance.
Danger: An attacker can call your function again before you update!
Result: They can drain all the tokens! 💸

Advice: Update the balance BEFORE calling the external contract.

════════════════════════════════════════════
Security Score: 15/100
Security Grade: F 💀
DANGEROUS - DO NOT DEPLOY!
════════════════════════════════════════════
```

## Step 4: You fix your code

```rust
pub fn transfer(recipient: String, amount: u64) {
    // 1. We update the balance FIRST ✅
    let balance = get_balance();
    set_balance(balance - amount);

    // 2. THEN we call the external contract ✅
    call_external_contract(recipient, amount);
}
```

## Step 5: You re-analyze

```bash
casper-secure analyze my_contract.rs
```

```
✅ NO CRITICAL VULNERABILITIES FOUND!

════════════════════════════════════════════
Security Score: 95/100
Security Grade: A+ 🌟
EXCELLENT - READY TO DEPLOY!
════════════════════════════════════════════
```

## Step 6: 🆕 You register the audit ON-CHAIN (NEW!)

```bash
casper-secure submit my_contract.rs --contract-address hash-abc123
```

```
CasperSecure - Submit Audit to On-Chain Registry

✓ Analysis complete

Audit Summary:
  Contract: hash-abc123
  Security Score: 95/100
  Security Grade: A+

On-Chain Registration:
  Contract Hash: b037bc0a...
  Timestamp: 2025-11-24

✓ Audit registered on Casper blockchain!
```

## Step 7: 🆕 Anyone can verify (PUBLIC PROOF)

```bash
# Anyone in the world can check
get_audit("hash-abc123")

# Returns:
✓ Score: 95/100
✓ Grade: A+
✓ Audited: 2025-11-24
✓ Auditor: CasperSecure Team
✓ Hash verified: b037bc0a...
```

**Now it's secure AND certified!** 🎉🔐

---

# 🔍 The 20 Types of Problems Detected

CasperSecure finds 20 different types of security bugs. Here are the most important ones explained simply:

## 1. 🔴 Reentrancy Attack (Very Dangerous)

**What is it?**
When an attacker can call your function multiple times before it finishes.

**Concrete example:**

```rust
// ❌ DANGEROUS CODE
pub fn withdraw() {
    let balance = get_balance();
    transfer_money(user);        // Attacker calls withdraw() again here!
    set_balance(balance - 100);  // Too late! They already withdrew multiple times!
}
```

**How to avoid:**

```rust
// ✅ SECURE CODE
pub fn withdraw() {
    let balance = get_balance();
    set_balance(balance - 100);  // Update FIRST
    transfer_money(user);        // Now it's safe
}
```

## 2. 🟡 Integer Overflow (Dangerous)

**What is it?**
When a number becomes too large and "wraps around" to zero.

**Concrete example:**

```rust
// ❌ DANGEROUS CODE
pub fn add_tokens(amount: u64) {
    let balance = get_balance();  // balance = 255
    set_balance(balance + amount); // If amount = 2, it makes 257... but overflow → 1!
}
```

**How to avoid:**

```rust
// ✅ SECURE CODE
pub fn add_tokens(amount: u64) {
    let balance = get_balance();
    // Check we don't exceed
    let new_balance = balance.checked_add(amount).expect("Overflow!");
    set_balance(new_balance);
}
```

## 3. 🔴 Missing Access Control (Very Dangerous)

**What is it?**
Anyone can call sensitive functions.

**Concrete example:**

```rust
// ❌ DANGEROUS CODE - Anyone can become owner!
pub fn set_owner(new_owner: String) {
    set_key("owner", new_owner);
}
```

**How to avoid:**

```rust
// ✅ SECURE CODE
pub fn set_owner(new_owner: String) {
    let caller = get_caller();
    let owner = get_key("owner");

    // CHECK that it's the current owner calling
    if caller != owner {
        panic!("Only the owner can change the owner!");
    }

    set_key("owner", new_owner);
}
```

## 4. 🟡 Unchecked External Calls (Dangerous)

**What is it?**
You call another contract but don't check if it succeeded.

**Concrete example:**

```rust
// ❌ DANGEROUS CODE
pub fn pay_user(user: String) {
    call_contract(user, "receive_payment");  // What if it fails?
    // You continue as if everything was fine...
}
```

**How to avoid:**

```rust
// ✅ SECURE CODE
pub fn pay_user(user: String) {
    let result = call_contract(user, "receive_payment");

    if result.is_err() {
        panic!("Payment failed!");
    }
}
```

## 5. 🔵 Missing Events (Best Practice)

**What is it?**
You modify important things but don't record anything.

**Concrete example:**

```rust
// ❌ NOT OPTIMAL - We don't know who transferred what
pub fn transfer(to: String, amount: u64) {
    set_balance(to, amount);
}
```

**How to improve:**

```rust
// ✅ BETTER
pub fn transfer(to: String, amount: u64) {
    set_balance(to, amount);

    // Record the event for history
    emit_event("Transfer", {
        "from": caller,
        "to": to,
        "amount": amount
    });
}
```

---

# 💯 The Scoring System

CasperSecure gives you a score out of 100 for your contract:

| Score | Grade | Meaning |
|-------|-------|---------|
| 95-100 | A+ 🌟 | Perfect! Almost no problems |
| 90-94 | A ✅ | Very good, minor details |
| 80-89 | B 👍 | Good, but need to fix some things |
| 70-79 | C ⚠️ | Average, several problems to fix |
| 60-69 | D ❌ | Dangerous, many problems |
| 0-59 | F 💀 | Very dangerous! DO NOT DEPLOY! |

**How is it calculated?**

Each bug removes points based on severity:
- **Critical Bug:** -50 points 💀
- **High Bug:** -15 points 🔴
- **Medium Bug:** -5 points 🟡
- **Low Bug:** -2 points 🔵
- **Info:** -1 point ℹ️

---

# 🚀 Quick Usage Guide

## Installation

```bash
# Clone the project
git clone https://github.com/le-stagiaire-ag2r/CasperSecure.git
cd CasperSecure

# Compile
cargo build --release
```

## Analyze your contract (OFF-CHAIN)

```bash
# Basic analysis
./target/release/casper-secure analyze my_contract.rs

# See only severe problems (HIGH)
./target/release/casper-secure analyze my_contract.rs --severity high

# Export to JSON (to integrate in your tools)
./target/release/casper-secure analyze my_contract.rs --format json
```

## 🆕 Submit audit to blockchain (ON-CHAIN)

```bash
# Register your audit on Casper blockchain
./target/release/casper-secure submit my_contract.rs \
  --contract-address hash-abc123 \
  --registry hash-xyz789
```

## See all detectors

```bash
./target/release/casper-secure detectors
```

---

# 📊 Example of Complete Report

When you analyze a contract, here's what you get:

```
════════════════════════════════════════════════════════════
SECURITY ANALYSIS REPORT
════════════════════════════════════════════════════════════

Summary:
  Total vulnerabilities: 12
  Security Score: 25/100    ← Your score
  Security Grade: F         ← Your grade

  High:     3    ← 3 severe problems
  Medium:   5    ← 5 medium problems
  Low:      4    ← 4 small problems

Detected Vulnerabilities:
────────────────────────────────────────────────────────────

1. Reentrancy [HIGH] 🔴
   Function: withdraw
   Description: You're calling an external contract before updating state.
                An attacker can steal money!
   Recommendation: Update state BEFORE calling the contract.

2. Missing Access Control [HIGH] 🔴
   Function: set_admin
   Description: Anyone can become admin of your contract!
   Recommendation: Add a check that only the current admin can change the admin.

[... and so on for the 12 problems ...]
```

---

# 🎯 Real Use Cases

## 1. Before deploying your contract

```bash
# You finished your contract
casper-secure analyze my_new_token.rs

# Result: Score 95/100 - Grade A+
# → OK, you can deploy safely! ✅

# 🆕 Register on blockchain
casper-secure submit my_new_token.rs --contract-address token-xyz
# → Now everyone can verify you're audited! 🔐
```

## 2. Security audit

```bash
# You want to audit an existing contract
casper-secure analyze suspicious_contract.rs --severity high

# Result: 5 HIGH bugs detected
# → Need to fix before using this contract! ⚠️
```

## 3. Verify a contract's audit (NEW!)

```bash
# Check if a contract is audited on blockchain
get_audit("hash-abc123")

# Result:
# Score: 95/100 ✅
# Grade: A+
# Audited: 2025-11-24
# → Safe to use! 🎉
```

## 4. CI/CD Integration

```bash
# In your automated pipeline
casper-secure analyze src/contract.rs --format json > report.json

# If score < 80, pipeline fails
# → Forces fixes before merging code! 🚀

# 🆕 Auto-submit on successful merge
casper-secure submit src/contract.rs --contract-address $CONTRACT_HASH
```

---

# 🏆 Why CasperSecure is Unique?

## Comparison with other tools:

| Feature | CasperSecure V5.0 | Other tools |
|---------|-------------------|-------------|
| Detectors | 20 | 5-10 |
| Security score | ✅ Yes | ❌ No |
| **ON-CHAIN Registry** 🆕 | ✅ Yes | ❌ No |
| **Public Verification** 🆕 | ✅ Yes | ❌ No |
| **Immutable Proof** 🆕 | ✅ Yes | ❌ No |
| Casper specific | ✅ Yes | ❌ No |
| Free & Open Source | ✅ Yes | 💰 Paid |
| Easy to use | ✅ Simple CLI | ⚠️ Complex |

## 🆕 The Innovation: OFF-CHAIN + ON-CHAIN

**CasperSecure is the FIRST and ONLY tool that combines:**

```
┌─────────────────────────────────────────────┐
│  OFF-CHAIN (Your computer)                  │
│  ├─ Code analysis                           │
│  ├─ Vulnerability detection                 │
│  ├─ Security scoring                        │
│  └─ Fix recommendations                     │
└─────────────────────────────────────────────┘
              ↓ submit
┌─────────────────────────────────────────────┐
│  ON-CHAIN (Casper Blockchain) 🆕            │
│  ├─ Audit registration                      │
│  ├─ Immutable storage                       │
│  ├─ Public verification                     │
│  └─ Timestamp + Hash                        │
└─────────────────────────────────────────────┘
```

**Benefits:**
- ✅ **Developers:** Find + fix bugs before deployment
- ✅ **Projects:** Prove you're audited with blockchain certificate
- ✅ **Users:** Verify security before using a contract
- ✅ **Ecosystem:** Build trust and transparency

---

# 🔐 ON-CHAIN Registry Explained

## What is stored on the blockchain?

```rust
struct AuditRecord {
    auditor: String,           // Who audited (CasperSecure Team)
    timestamp: u64,            // When (blockchain time)
    security_score: u8,        // 0-100
    security_grade: String,    // A+, A, B, C, D, F
    critical: u32,             // # critical vulnerabilities
    high: u32,                 // # high vulnerabilities
    medium: u32,               // # medium vulnerabilities
    low: u32,                  // # low vulnerabilities
    info: u32,                 // # info findings
    contract_hash: String,     // MD5 of source code
}
```

## Why is it useful?

**Before V5.0 (OFF-CHAIN only):**
```
You: "My contract is audited!"
User: "How can I verify that?" 🤔
You: "Trust me..." ❌
```

**With V5.0 (ON-CHAIN certification):**
```
You: "My contract is audited!"
User: "Let me check on blockchain..." 🔍
Blockchain: "Verified ✅ Score 95/100, Grade A+"
User: "OK I trust you!" ✅
```

---

# 💡 General Security Tips

1. **Always verify external calls**
2. **Update state BEFORE external calls**
3. **Use `checked_` functions for arithmetic**
4. **Add access control wherever it's important**
5. **Emit events for all important actions**
6. **Test your contract with CasperSecure BEFORE deploying**
7. 🆕 **Register your audit on blockchain for transparency**

---

# 🤝 Frequently Asked Questions (FAQ)

**Q: Can CasperSecure fix bugs automatically?**
A: Not yet (V5.0), but it's planned for V6.0!

**Q: Does it replace a human audit?**
A: No! CasperSecure detects automatic bugs, but a human audit is always recommended for large projects.

**Q: Is the ON-CHAIN registry mandatory?**
A: No! It's optional. You can use just the OFF-CHAIN analysis.

**Q: Can I trust the on-chain audit data?**
A: Yes! It's stored on the blockchain and is immutable (cannot be modified).

**Q: How much does it cost to register an audit on-chain?**
A: You need to pay Casper gas fees (a few CSPR tokens).

**Q: Is it compatible with all Casper contracts?**
A: Yes! As long as it's written in Rust for Casper Network.

**Q: Is it really free?**
A: Yes, 100% free and open source (MIT license)! Only the blockchain gas is paid.

**Q: Does it work for other blockchains?**
A: Currently only Casper, but it can be adapted!

---

# 📚 Go Further

- **GitHub:** https://github.com/le-stagiaire-ag2r/CasperSecure
- **Documentation:** See README.md
- **List of 20 detectors:** `casper-secure detectors`
- **Contract examples:** `examples/` directory
- 🆕 **ON-CHAIN contract:** `crates/contract/`

---

# 🎓 Conclusion

**CasperSecure V5.0 is your complete security solution for Casper!** 🛡️

**OFF-CHAIN:**
- ✅ Detects 20 types of bugs automatically
- ✅ Gives you a security score
- ✅ Advises you how to fix

**ON-CHAIN:** 🆕
- ✅ Registers audits on blockchain
- ✅ Public verification
- ✅ Immutable proof

**Never forget:**

> "A deployed smart contract cannot be modified.
> Prevention is better than cure!"

**ALWAYS analyze your code before deploying!** 🚀

**And NOW: Prove to the world you're audited with blockchain certification!** 🔐

---

*Making Casper smart contracts safer, one analysis at a time.* 🛡️
