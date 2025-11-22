#![no_std]
#![no_main]

//! CasperSecure Audit Registry Smart Contract
//!
//! This contract stores security audit results on-chain, allowing anyone to verify
//! that a contract has been audited by CasperSecure and see its security score.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use casper_contract::{
    contract_api::{runtime, storage},
    unwrap_or_revert::UnwrapOrRevert,
};
use casper_types::{
    contracts::NamedKeys, CLType, CLValue, EntryPoint, EntryPointAccess, EntryPointType,
    EntryPoints, Key, Parameter, URef, U256,
};

// Storage keys
const AUDITS_DICT: &str = "audits";
const CONTRACT_VERSION: &str = "contract_version";

// Contract version
const VERSION: &str = "1.0.0";

/// Audit record structure (stored as tuple in dictionary)
/// Format: (auditor, timestamp, score, grade, critical, high, medium, low, info, contract_hash)
type AuditRecord = (
    String,  // auditor address
    u64,     // timestamp
    u8,      // security_score (0-100)
    String,  // security_grade (A+, A, B, C, D, F)
    u32,     // critical count
    u32,     // high count
    u32,     // medium count
    u32,     // low count
    u32,     // info count
    String,  // contract_hash (optional - hash of audited contract)
);

/// Initialize the contract
#[no_mangle]
pub extern "C" fn init() {
    // Create the audits dictionary
    let audits_dict = storage::new_dictionary(AUDITS_DICT).unwrap_or_revert();

    // Store contract version
    let version_uref = storage::new_uref(VERSION.to_string());
    runtime::put_key(CONTRACT_VERSION, version_uref.into());

    // Store the dictionary reference
    runtime::put_key(AUDITS_DICT, audits_dict.into());
}

/// Register a new audit result
///
/// Arguments:
/// - contract_address: The address/hash of the audited contract
/// - auditor: Address of the auditor
/// - security_score: Security score (0-100)
/// - security_grade: Security grade (A+, A, B, C, D, F)
/// - critical: Number of critical vulnerabilities
/// - high: Number of high severity vulnerabilities
/// - medium: Number of medium severity vulnerabilities
/// - low: Number of low severity vulnerabilities
/// - info: Number of info severity vulnerabilities
/// - contract_hash: Optional hash of the contract source code
#[no_mangle]
pub extern "C" fn register_audit() {
    let contract_address: String = runtime::get_named_arg("contract_address");
    let auditor: String = runtime::get_named_arg("auditor");
    let security_score: u8 = runtime::get_named_arg("security_score");
    let security_grade: String = runtime::get_named_arg("security_grade");
    let critical: u32 = runtime::get_named_arg("critical");
    let high: u32 = runtime::get_named_arg("high");
    let medium: u32 = runtime::get_named_arg("medium");
    let low: u32 = runtime::get_named_arg("low");
    let info: u32 = runtime::get_named_arg("info");
    let contract_hash: String = runtime::get_named_arg("contract_hash");

    // Get current timestamp
    let timestamp = runtime::get_blocktime().into();

    // Create audit record
    let audit_record: AuditRecord = (
        auditor,
        timestamp,
        security_score,
        security_grade,
        critical,
        high,
        medium,
        low,
        info,
        contract_hash,
    );

    // Get the audits dictionary
    let audits_uref = runtime::get_key(AUDITS_DICT)
        .unwrap_or_revert()
        .into_uref()
        .unwrap_or_revert();

    // Store the audit record
    storage::dictionary_put(audits_uref, &contract_address, audit_record);

    // Emit event (via runtime revert with custom error - Casper doesn't have events like Ethereum)
    // In production, you'd use a proper event mechanism or log to storage
}

/// Get audit information for a contract
///
/// Arguments:
/// - contract_address: The address/hash of the audited contract
///
/// Returns: Audit record or None if not found
#[no_mangle]
pub extern "C" fn get_audit() {
    let contract_address: String = runtime::get_named_arg("contract_address");

    // Get the audits dictionary
    let audits_uref = runtime::get_key(AUDITS_DICT)
        .unwrap_or_revert()
        .into_uref()
        .unwrap_or_revert();

    // Read the audit record
    let audit_record: Option<AuditRecord> =
        storage::dictionary_get(audits_uref, &contract_address).unwrap_or_revert();

    // Return the result
    runtime::ret(CLValue::from_t(audit_record).unwrap_or_revert());
}

/// Get just the security score for a contract (quick lookup)
///
/// Arguments:
/// - contract_address: The address/hash of the audited contract
///
/// Returns: Security score (0-100) or None if not found
#[no_mangle]
pub extern "C" fn get_security_score() {
    let contract_address: String = runtime::get_named_arg("contract_address");

    // Get the audits dictionary
    let audits_uref = runtime::get_key(AUDITS_DICT)
        .unwrap_or_revert()
        .into_uref()
        .unwrap_or_revert();

    // Read the audit record
    let audit_record: Option<AuditRecord> =
        storage::dictionary_get(audits_uref, &contract_address).unwrap_or_revert();

    // Extract just the security score
    let score = audit_record.map(|record| record.2);

    // Return the result
    runtime::ret(CLValue::from_t(score).unwrap_or_revert());
}

/// Install the contract
#[no_mangle]
pub extern "C" fn call() {
    // Create entry points
    let mut entry_points = EntryPoints::new();

    // init entry point
    entry_points.add_entry_point(EntryPoint::new(
        "init",
        Vec::new(),
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    ));

    // register_audit entry point
    entry_points.add_entry_point(EntryPoint::new(
        "register_audit",
        alloc::vec![
            Parameter::new("contract_address", CLType::String),
            Parameter::new("auditor", CLType::String),
            Parameter::new("security_score", CLType::U8),
            Parameter::new("security_grade", CLType::String),
            Parameter::new("critical", CLType::U32),
            Parameter::new("high", CLType::U32),
            Parameter::new("medium", CLType::U32),
            Parameter::new("low", CLType::U32),
            Parameter::new("info", CLType::U32),
            Parameter::new("contract_hash", CLType::String),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Contract,
    ));

    // get_audit entry point
    entry_points.add_entry_point(EntryPoint::new(
        "get_audit",
        alloc::vec![Parameter::new("contract_address", CLType::String)],
        CLType::Option(alloc::boxed::Box::new(CLType::Tuple3([
            alloc::boxed::Box::new(CLType::String),
            alloc::boxed::Box::new(CLType::U64),
            alloc::boxed::Box::new(CLType::U8),
        ]))),
        EntryPointAccess::Public,
        EntryPointType::Contract,
    ));

    // get_security_score entry point
    entry_points.add_entry_point(EntryPoint::new(
        "get_security_score",
        alloc::vec![Parameter::new("contract_address", CLType::String)],
        CLType::Option(alloc::boxed::Box::new(CLType::U8)),
        EntryPointAccess::Public,
        EntryPointType::Contract,
    ));

    // Create named keys
    let named_keys = NamedKeys::new();

    // Install the contract
    let (contract_hash, _contract_version) = storage::new_contract(
        entry_points,
        Some(named_keys),
        Some("casper_audit_registry_package".to_string()),
        Some("casper_audit_registry_access".to_string()),
    );

    // Store contract hash for access
    runtime::put_key("casper_audit_registry", contract_hash.into());

    // Call init to set up storage
    runtime::call_contract::<()>(contract_hash, "init", runtime::named_args! {});
}
