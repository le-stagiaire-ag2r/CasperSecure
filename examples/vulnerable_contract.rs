//! Example Vulnerable Casper Contract
//!
//! This contract intentionally contains multiple security vulnerabilities
//! to demonstrate CasperSecure's detection capabilities.
//!
//! ⚠️ DO NOT USE IN PRODUCTION ⚠️

use casper_types::{
    runtime_args, ContractHash, Key, RuntimeArgs, URef, U512,
};

// Contract storage keys
const BALANCE_KEY: &str = "bal";  // ⚠️ VULN: Short key (storage collision risk)
const OWNER_KEY: &str = "owner";
const LOCKED_KEY: &str = "locked";

/// Initialize the contract
/// ⚠️ VULN: No access control check
#[no_mangle]
pub extern "C" fn init() {
    let caller = get_caller();
    set_key(OWNER_KEY, caller);
    set_key(BALANCE_KEY, U512::zero());
    set_key(LOCKED_KEY, false);
}

/// Transfer tokens to another address
/// ⚠️ VULN #1: Reentrancy - external call before state update
/// ⚠️ VULN #2: Integer overflow - unchecked subtraction
/// ⚠️ VULN #3: No access control
#[no_mangle]
pub extern "C" fn transfer() {
    let recipient: ContractHash = runtime::get_named_arg("recipient");
    let amount: U512 = runtime::get_named_arg("amount");

    let balance = get_balance();

    // ⚠️ VULNERABILITY: External call BEFORE state update (reentrancy risk!)
    runtime::call_contract::<()>(
        recipient,
        "receive",
        runtime_args! {
            "amount" => amount
        }
    );

    // ⚠️ VULNERABILITY: Unchecked arithmetic (overflow risk!)
    let new_balance = balance - amount;
    set_balance(new_balance);
}

/// Withdraw funds
/// ⚠️ VULN #1: Missing access control (anyone can withdraw!)
/// ⚠️ VULN #2: Unchecked external call
#[no_mangle]
pub extern "C" fn withdraw() {
    let amount: U512 = runtime::get_named_arg("amount");
    let recipient: Key = runtime::get_named_arg("recipient");

    let balance = get_balance();

    // ⚠️ VULNERABILITY: No check that caller is owner!
    // Anyone can call this function!

    // ⚠️ VULNERABILITY: Unchecked arithmetic
    let new_balance = balance - amount;
    set_balance(new_balance);

    // ⚠️ VULNERABILITY: External call result not checked
    runtime::transfer_to_account(
        recipient.into_account().unwrap(),
        amount,
        None
    );
    // No error handling if transfer fails!
}

/// Deposit funds
/// ⚠️ VULN: Integer overflow on addition
#[no_mangle]
pub extern "C" fn deposit() {
    let amount: U512 = runtime::get_named_arg("amount");

    let balance = get_balance();

    // ⚠️ VULNERABILITY: Unchecked addition (overflow risk!)
    let new_balance = balance + amount;
    set_balance(new_balance);
}

/// Update contract owner
/// ⚠️ VULN: Missing access control - anyone can become owner!
#[no_mangle]
pub extern "C" fn set_owner() {
    let new_owner: Key = runtime::get_named_arg("new_owner");

    // ⚠️ VULNERABILITY: No verification that caller is current owner!
    // Any user can call this and take ownership!
    set_key(OWNER_KEY, new_owner);
}

/// Complex function with multiple vulnerabilities
/// ⚠️ VULN #1: Reentrancy
/// ⚠️ VULN #2: Integer overflow
/// ⚠️ VULN #3: Missing access control
/// ⚠️ VULN #4: Unchecked external call
#[no_mangle]
pub extern "C" fn complex_operation() {
    let target: ContractHash = runtime::get_named_arg("target");
    let amount: U512 = runtime::get_named_arg("amount");
    let multiplier: u64 = runtime::get_named_arg("multiplier");

    let balance = get_balance();

    // ⚠️ VULNERABILITY: Unchecked multiplication
    let computed = amount * U512::from(multiplier);

    // ⚠️ VULNERABILITY: External call before state change
    let result: U512 = runtime::call_contract(
        target,
        "process",
        runtime_args! {
            "value" => computed
        }
    );

    // ⚠️ VULNERABILITY: Unchecked addition
    let new_balance = balance + result;
    set_balance(new_balance);
}

/// Emergency stop function
/// ⚠️ VULN: Missing access control
#[no_mangle]
pub extern "C" fn emergency_stop() {
    // ⚠️ VULNERABILITY: Anyone can lock the contract!
    set_key(LOCKED_KEY, true);
}

/// Batch transfer
/// ⚠️ VULN: Multiple reentrancy opportunities
#[no_mangle]
pub extern "C" fn batch_transfer() {
    let recipients: Vec<ContractHash> = runtime::get_named_arg("recipients");
    let amounts: Vec<U512> = runtime::get_named_arg("amounts");

    let mut balance = get_balance();

    for (recipient, amount) in recipients.iter().zip(amounts.iter()) {
        // ⚠️ VULNERABILITY: External call in loop (multiple reentrancy risks!)
        runtime::call_contract::<()>(
            *recipient,
            "receive",
            runtime_args! {
                "amount" => *amount
            }
        );

        // ⚠️ VULNERABILITY: Unchecked subtraction in loop
        balance = balance - *amount;
    }

    set_balance(balance);
}

// Helper functions (simplified for example)

fn get_caller() -> Key {
    runtime::get_caller()
}

fn get_balance() -> U512 {
    get_key(BALANCE_KEY).unwrap_or(U512::zero())
}

fn set_balance(amount: U512) {
    set_key(BALANCE_KEY, amount);
}

fn get_key<T: casper_types::FromBytes>(name: &str) -> Option<T> {
    runtime::get_key(name)
        .and_then(|key| key.into_uref())
        .and_then(|uref| {
            let value: T = runtime::read(uref).ok()?;
            Some(value)
        })
}

fn set_key<T: casper_types::CLTyped + casper_types::ToBytes>(name: &str, value: T) {
    match runtime::get_key(name) {
        Some(key) => {
            let uref = key.into_uref().unwrap();
            runtime::write(uref, value);
        }
        None => {
            let uref = runtime::new_uref(value);
            runtime::put_key(name, Key::from(uref));
        }
    }
}

// Mock runtime module for compilation
mod runtime {
    use super::*;

    pub fn get_caller() -> Key {
        unimplemented!()
    }

    pub fn get_named_arg<T>(_name: &str) -> T {
        unimplemented!()
    }

    pub fn call_contract<T>(_contract: ContractHash, _entry_point: &str, _args: RuntimeArgs) -> T {
        unimplemented!()
    }

    pub fn transfer_to_account(_account: casper_types::AccountHash, _amount: U512, _id: Option<u64>) {
        unimplemented!()
    }

    pub fn get_key(_name: &str) -> Option<Key> {
        unimplemented!()
    }

    pub fn new_uref<T>(_value: T) -> URef {
        unimplemented!()
    }

    pub fn put_key(_name: &str, _key: Key) {
        unimplemented!()
    }

    pub fn read<T>(_uref: URef) -> Result<T, ()> {
        unimplemented!()
    }

    pub fn write<T>(_uref: URef, _value: T) {
        unimplemented!()
    }
}
