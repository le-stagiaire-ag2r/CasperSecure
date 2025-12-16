//! Vulnerability Detector for Casper Contracts V6.0
//!
//! Detects common security vulnerabilities in Casper smart contracts
//!
//! V6.0 Enhancements:
//! - 30 total detectors (10 new Casper-specific)
//! - Reduced false positives with checked arithmetic recognition
//! - URef and Purse security checks
//! - Odra framework support
//! - Call stack depth analysis

use anyhow::Result;
use casper_analyzer::{AnalysisResult, StorageOpType};
use casper_parser::{ParsedContract, Statement, URefOpType};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Vulnerability severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

/// Detected vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Vulnerability type
    pub vuln_type: String,
    /// Severity level
    pub severity: Severity,
    /// Description
    pub description: String,
    /// Location in code
    pub location: Location,
    /// Recommendation
    pub recommendation: String,
    /// V6.0: Detector ID
    pub detector_id: String,
    /// V6.0: Category
    pub category: VulnCategory,
}

/// V6.0: Vulnerability categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VulnCategory {
    Security,
    AccessControl,
    Arithmetic,
    Reentrancy,
    Storage,
    Gas,
    CodeQuality,
    CasperSpecific,
    OdraSpecific,
}

/// Code location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub function: String,
    pub line: Option<u32>,
}

/// Detection report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionReport {
    pub contract_path: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub summary: Summary,
    /// V6.0: Contract metadata
    pub contract_info: ContractInfo,
}

/// V6.0: Contract information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContractInfo {
    pub is_odra: bool,
    pub uses_cep18: bool,
    pub uses_cep78: bool,
    pub entry_point_count: usize,
    pub function_count: usize,
    pub has_init: bool,
}

/// Summary of detection results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub total_vulns: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    /// Security score out of 100 (100 = perfect, 0 = critical issues)
    pub security_score: u8,
    /// Security grade (A+, A, B, C, D, F)
    pub security_grade: String,
    /// V6.0: Detectors run
    pub detectors_run: usize,
}

/// Vulnerability Detector V6.0
pub struct VulnerabilityDetector;

impl VulnerabilityDetector {
    pub fn new() -> Self {
        Self
    }

    /// Run all detectors on a contract
    pub fn detect(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Result<DetectionReport> {
        let mut vulnerabilities = Vec::new();

        // ═══════════════════════════════════════════════════════════
        // ORIGINAL DETECTORS (20) - Enhanced for V6.0
        // ═══════════════════════════════════════════════════════════

        // V0.2.0 detectors (5)
        vulnerabilities.extend(self.detect_reentrancy(contract, analysis));
        vulnerabilities.extend(self.detect_integer_overflow(contract, analysis));
        vulnerabilities.extend(self.detect_access_control(contract, analysis));
        vulnerabilities.extend(self.detect_unchecked_calls(contract, analysis));
        vulnerabilities.extend(self.detect_storage_collision(contract, analysis));

        // V0.3.0 detectors (6)
        vulnerabilities.extend(self.detect_dos_risk(contract, analysis));
        vulnerabilities.extend(self.detect_gas_limit_risk(contract, analysis));
        vulnerabilities.extend(self.detect_uninitialized_storage(contract, analysis));
        vulnerabilities.extend(self.detect_multiple_external_calls(contract, analysis));
        vulnerabilities.extend(self.detect_complex_entry_point(contract, analysis));
        vulnerabilities.extend(self.detect_write_only_storage(contract, analysis));

        // V4.0 detectors (9)
        vulnerabilities.extend(self.detect_timestamp_manipulation(contract, analysis));
        vulnerabilities.extend(self.detect_unchecked_return_values(contract, analysis));
        vulnerabilities.extend(self.detect_dangerous_delegatecall(contract, analysis));
        vulnerabilities.extend(self.detect_redundant_code(contract, analysis));
        vulnerabilities.extend(self.detect_dead_code(contract, analysis));
        vulnerabilities.extend(self.detect_magic_numbers(contract, analysis));
        vulnerabilities.extend(self.detect_unsafe_type_casting(contract, analysis));
        vulnerabilities.extend(self.detect_inefficient_storage(contract, analysis));
        vulnerabilities.extend(self.detect_missing_events(contract, analysis));

        // ═══════════════════════════════════════════════════════════
        // V6.0 NEW DETECTORS (10) - Casper-Specific
        // ═══════════════════════════════════════════════════════════

        vulnerabilities.extend(self.detect_uref_access_rights(contract, analysis));
        vulnerabilities.extend(self.detect_unprotected_init(contract, analysis));
        vulnerabilities.extend(self.detect_purse_in_dictionary(contract, analysis));
        vulnerabilities.extend(self.detect_call_stack_depth(contract, analysis));
        vulnerabilities.extend(self.detect_dictionary_key_length(contract, analysis));
        vulnerabilities.extend(self.detect_unsafe_unwrap(contract, analysis));
        vulnerabilities.extend(self.detect_missing_caller_validation(contract, analysis));
        vulnerabilities.extend(self.detect_unbounded_loop(contract, analysis));
        vulnerabilities.extend(self.detect_cep_compliance(contract, analysis));
        vulnerabilities.extend(self.detect_odra_issues(contract, analysis));

        let summary = Self::create_summary(&vulnerabilities);

        let contract_info = ContractInfo {
            is_odra: contract.metadata.is_odra_contract,
            uses_cep18: contract.metadata.uses_cep18,
            uses_cep78: contract.metadata.uses_cep78,
            entry_point_count: contract.entry_points.len(),
            function_count: contract.functions.len(),
            has_init: contract.metadata.has_init_function,
        };

        Ok(DetectionReport {
            contract_path: contract.path.clone(),
            vulnerabilities,
            summary,
            contract_info,
        })
    }

    // ═══════════════════════════════════════════════════════════
    // ORIGINAL DETECTORS (V0.2.0 - V4.0) - Enhanced
    // ═══════════════════════════════════════════════════════════

    /// Detector 1: Reentrancy Attacks
    fn detect_reentrancy(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for ext_call in &analysis.control_flow.external_calls {
            // Check if state is modified after external call
            let has_post_call_state_change = analysis.data_flow.storage_ops.iter()
                .any(|op| op.function == ext_call.caller &&
                    matches!(op.operation, StorageOpType::Write));

            // V6.0: Check if function has reentrancy guard
            let has_guard = analysis.security_patterns.functions_with_reentrancy_guards
                .contains(&ext_call.caller);

            if has_post_call_state_change && !has_guard {
                vulns.push(Vulnerability {
                    vuln_type: "Reentrancy".to_string(),
                    severity: Severity::High,
                    description: format!(
                        "Function '{}' performs external call to '{}' before updating state. \
                         This may allow reentrancy attacks.",
                        ext_call.caller, ext_call.callee
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: ext_call.caller.clone(),
                        line: None,
                    },
                    recommendation: "Follow the Checks-Effects-Interactions pattern: \
                                     update state before making external calls.".to_string(),
                    detector_id: "CSPR-001".to_string(),
                    category: VulnCategory::Reentrancy,
                });
            }
        }

        vulns
    }

    /// Detector 2: Integer Overflow/Underflow - V6.0 Enhanced
    fn detect_integer_overflow(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let mut reported_functions: HashSet<String> = HashSet::new();

        for arith_op in &analysis.data_flow.arithmetic_ops {
            // V6.0: Skip if using checked arithmetic
            if arith_op.is_checked {
                continue;
            }

            // V6.0: Only report once per function
            if reported_functions.contains(&arith_op.function) {
                continue;
            }

            // V6.0: Check if function uses any checked arithmetic
            let func_uses_checked = analysis.security_patterns.functions_with_checked_arithmetic
                .contains(&arith_op.function);

            if func_uses_checked {
                continue; // Function uses checked arithmetic elsewhere, likely intentional
            }

            reported_functions.insert(arith_op.function.clone());

            vulns.push(Vulnerability {
                vuln_type: "Integer Overflow".to_string(),
                severity: Severity::Medium,
                description: format!(
                    "Function '{}' performs unchecked arithmetic operation '{}'. \
                     This may cause integer overflow or underflow.",
                    arith_op.function, arith_op.operation
                ),
                location: Location {
                    file: contract.path.clone(),
                    function: arith_op.function.clone(),
                    line: None,
                },
                recommendation: "Use checked arithmetic operations (checked_add, checked_sub, \
                                 saturating_add, etc.) or validate inputs before operations.".to_string(),
                detector_id: "CSPR-002".to_string(),
                category: VulnCategory::Arithmetic,
            });
        }

        vulns
    }

    /// Detector 3: Missing Access Control - V6.0 Enhanced
    fn detect_access_control(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for ep_analysis in &analysis.entry_points {
            // V6.0: Use properly detected access control
            if ep_analysis.has_access_control {
                continue;
            }

            // V6.0: Skip init functions (they should be protected differently)
            if ep_analysis.is_init {
                continue;
            }

            // V6.0: Skip view functions
            let func = contract.functions.iter().find(|f| f.name == ep_analysis.name);
            if let Some(f) = func {
                if f.patterns.is_view_function {
                    continue;
                }
            }

            // Check if entry point modifies state
            if ep_analysis.modifies_state {
                vulns.push(Vulnerability {
                    vuln_type: "Missing Access Control".to_string(),
                    severity: Severity::High,
                    description: format!(
                        "Entry point '{}' modifies contract state but lacks access control checks. \
                         Any user can call this function.",
                        ep_analysis.name
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: ep_analysis.name.clone(),
                        line: None,
                    },
                    recommendation: "Add access control checks (e.g., verify caller is contract owner \
                                     or has required permissions) before state modifications.".to_string(),
                    detector_id: "CSPR-003".to_string(),
                    category: VulnCategory::AccessControl,
                });
            }
        }

        vulns
    }

    /// Detector 4: Unchecked External Calls - V6.0 Enhanced
    fn detect_unchecked_calls(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for ext_call in &analysis.control_flow.external_calls {
            // V6.0: Check the is_checked flag from parser
            if ext_call.is_checked {
                continue;
            }

            vulns.push(Vulnerability {
                vuln_type: "Unchecked External Call".to_string(),
                severity: Severity::Medium,
                description: format!(
                    "Function '{}' calls external contract '{}' without checking the result. \
                     Failed calls may go unnoticed.",
                    ext_call.caller, ext_call.callee
                ),
                location: Location {
                    file: contract.path.clone(),
                    function: ext_call.caller.clone(),
                    line: None,
                },
                recommendation: "Always check the return value of external calls using ? operator \
                                 or match/if-let patterns.".to_string(),
                detector_id: "CSPR-004".to_string(),
                category: VulnCategory::Security,
            });
        }

        vulns
    }

    /// Detector 5: Storage Key Collision
    fn detect_storage_collision(&self, contract: &ParsedContract, _analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let mut seen_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

        for storage_item in &contract.storage_items {
            // Check for very short keys (collision risk)
            if storage_item.name.len() < 3 {
                vulns.push(Vulnerability {
                    vuln_type: "Storage Collision Risk".to_string(),
                    severity: Severity::Low,
                    description: format!(
                        "Storage key '{}' is very short ({} chars). Short keys have higher collision risk.",
                        storage_item.name, storage_item.name.len()
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: "storage".to_string(),
                        line: None,
                    },
                    recommendation: "Use descriptive, unique storage key names to avoid collisions.".to_string(),
                    detector_id: "CSPR-005".to_string(),
                    category: VulnCategory::Storage,
                });
            }

            // Check for duplicate keys
            if seen_keys.contains(&storage_item.name) {
                vulns.push(Vulnerability {
                    vuln_type: "Storage Collision Risk".to_string(),
                    severity: Severity::Medium,
                    description: format!("Duplicate storage key '{}' detected.", storage_item.name),
                    location: Location {
                        file: contract.path.clone(),
                        function: "storage".to_string(),
                        line: None,
                    },
                    recommendation: "Ensure each storage key is unique.".to_string(),
                    detector_id: "CSPR-005".to_string(),
                    category: VulnCategory::Storage,
                });
            }

            seen_keys.insert(storage_item.name.clone());
        }

        vulns
    }

    /// Detector 6: DOS Risk
    fn detect_dos_risk(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for func in &contract.functions {
            let has_loop = analysis.control_flow.functions_with_loops.contains(&func.name);
            let has_external_call = analysis.control_flow.external_calls.iter()
                .any(|call| call.caller == func.name);

            if has_loop && has_external_call {
                vulns.push(Vulnerability {
                    vuln_type: "DOS Risk".to_string(),
                    severity: Severity::Medium,
                    description: format!(
                        "Function '{}' contains a loop with external calls. \
                         Unbounded loops or repeated call failures can cause denial of service.",
                        func.name
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: func.name.clone(),
                        line: None,
                    },
                    recommendation: "Limit loop iterations, add circuit breakers, or move external calls outside loops.".to_string(),
                    detector_id: "CSPR-006".to_string(),
                    category: VulnCategory::Gas,
                });
            }
        }

        vulns
    }

    /// Detector 7: Gas Limit Risk
    fn detect_gas_limit_risk(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for func in &contract.functions {
            if !analysis.control_flow.functions_with_loops.contains(&func.name) {
                continue;
            }

            let arithmetic_ops = analysis.data_flow.arithmetic_ops.iter()
                .filter(|op| op.function == func.name)
                .count();

            if arithmetic_ops > 5 {
                vulns.push(Vulnerability {
                    vuln_type: "Gas Limit Risk".to_string(),
                    severity: Severity::Low,
                    description: format!(
                        "Function '{}' has a loop with {} arithmetic operations. \
                         This may consume excessive gas and fail for large inputs.",
                        func.name, arithmetic_ops
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: func.name.clone(),
                        line: None,
                    },
                    recommendation: "Optimize loops, batch operations, or consider off-chain computation.".to_string(),
                    detector_id: "CSPR-007".to_string(),
                    category: VulnCategory::Gas,
                });
            }
        }

        vulns
    }

    /// Detector 8: Uninitialized Storage - V6.0 Enhanced
    fn detect_uninitialized_storage(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // V6.0: Use storage analysis for better detection
        for key in &analysis.storage_analysis.read_before_write {
            vulns.push(Vulnerability {
                vuln_type: "Uninitialized Storage".to_string(),
                severity: Severity::Medium,
                description: format!(
                    "Storage key '{}' is read but may not be initialized. \
                     This could lead to unexpected default values.",
                    key
                ),
                location: Location {
                    file: contract.path.clone(),
                    function: "multiple".to_string(),
                    line: None,
                },
                recommendation: "Ensure storage is initialized in init/constructor before reading.".to_string(),
                detector_id: "CSPR-008".to_string(),
                category: VulnCategory::Storage,
            });
        }

        vulns
    }

    /// Detector 9: Multiple External Calls
    fn detect_multiple_external_calls(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let mut call_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for call in &analysis.control_flow.external_calls {
            *call_counts.entry(call.caller.clone()).or_insert(0) += 1;
        }

        for (func_name, count) in call_counts {
            if count >= 3 {
                vulns.push(Vulnerability {
                    vuln_type: "Multiple External Calls".to_string(),
                    severity: Severity::Low,
                    description: format!(
                        "Function '{}' makes {} external calls. \
                         This increases attack surface and complexity.",
                        func_name, count
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: func_name.clone(),
                        line: None,
                    },
                    recommendation: "Consider reducing external dependencies or splitting the function.".to_string(),
                    detector_id: "CSPR-009".to_string(),
                    category: VulnCategory::CodeQuality,
                });
            }
        }

        vulns
    }

    /// Detector 10: Complex Entry Point
    fn detect_complex_entry_point(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for ep in &analysis.entry_points {
            if ep.complexity_score > 10 {
                vulns.push(Vulnerability {
                    vuln_type: "Complex Entry Point".to_string(),
                    severity: Severity::Info,
                    description: format!(
                        "Entry point '{}' has high complexity ({}). \
                         Complex entry points are harder to audit and maintain.",
                        ep.name, ep.complexity_score
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: ep.name.clone(),
                        line: None,
                    },
                    recommendation: "Consider refactoring into smaller, testable functions.".to_string(),
                    detector_id: "CSPR-010".to_string(),
                    category: VulnCategory::CodeQuality,
                });
            }
        }

        vulns
    }

    /// Detector 11: Write-Only Storage - V6.0 Enhanced
    fn detect_write_only_storage(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // V6.0: Use storage analysis
        for key in &analysis.storage_analysis.write_only_keys {
            vulns.push(Vulnerability {
                vuln_type: "Write-Only Storage".to_string(),
                severity: Severity::Info,
                description: format!(
                    "Storage key '{}' is written but never read. \
                     This may indicate wasted storage or a logic error.",
                    key
                ),
                location: Location {
                    file: contract.path.clone(),
                    function: "storage".to_string(),
                    line: None,
                },
                recommendation: "Remove unused storage or add read logic if needed.".to_string(),
                detector_id: "CSPR-011".to_string(),
                category: VulnCategory::CodeQuality,
            });
        }

        vulns
    }

    /// Detector 12: Timestamp Manipulation
    fn detect_timestamp_manipulation(&self, contract: &ParsedContract, _analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for func in &contract.functions {
            for stmt in &func.body {
                if let Statement::ExternalCall { method, .. } = stmt {
                    if method.contains("timestamp") || method.contains("block_time") {
                        vulns.push(Vulnerability {
                            vuln_type: "Timestamp Manipulation".to_string(),
                            severity: Severity::Medium,
                            description: format!(
                                "Function '{}' uses block timestamp which can be manipulated by validators. \
                                 Do not use timestamps for critical logic like randomness.",
                                func.name
                            ),
                            location: Location {
                                file: contract.path.clone(),
                                function: func.name.clone(),
                                line: None,
                            },
                            recommendation: "Use block height instead of timestamp for time-dependent logic.".to_string(),
                            detector_id: "CSPR-012".to_string(),
                            category: VulnCategory::Security,
                        });
                    }
                }
            }
        }

        vulns
    }

    /// Detector 13: Unchecked Return Values
    fn detect_unchecked_return_values(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for call in &analysis.control_flow.external_calls {
            let is_entry_point = contract.entry_points.iter()
                .any(|ep| ep.name == call.caller);

            // V6.0: Check if return is actually checked
            if is_entry_point && !call.is_checked {
                vulns.push(Vulnerability {
                    vuln_type: "Unchecked Return Value".to_string(),
                    severity: Severity::Medium,
                    description: format!(
                        "External call from '{}' to '{}' may have unchecked return value.",
                        call.caller, call.callee
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: call.caller.clone(),
                        line: None,
                    },
                    recommendation: "Always check return values from external calls.".to_string(),
                    detector_id: "CSPR-013".to_string(),
                    category: VulnCategory::Security,
                });
            }
        }

        vulns
    }

    /// Detector 14: Dangerous Delegatecall
    fn detect_dangerous_delegatecall(&self, contract: &ParsedContract, _analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for func in &contract.functions {
            for stmt in &func.body {
                if let Statement::ExternalCall { method, .. } = stmt {
                    if method.contains("delegate") || method.contains("call_versioned_contract") {
                        vulns.push(Vulnerability {
                            vuln_type: "Dangerous Delegatecall".to_string(),
                            severity: Severity::High,
                            description: format!(
                                "Function '{}' uses delegatecall which executes code in current context. \
                                 If the target is user-controlled, this is a critical vulnerability.",
                                func.name
                            ),
                            location: Location {
                                file: contract.path.clone(),
                                function: func.name.clone(),
                                line: None,
                            },
                            recommendation: "Ensure delegatecall target is from a whitelist of trusted contracts.".to_string(),
                            detector_id: "CSPR-014".to_string(),
                            category: VulnCategory::Security,
                        });
                    }
                }
            }
        }

        vulns
    }

    /// Detector 15: Redundant Code
    fn detect_redundant_code(&self, contract: &ParsedContract, _analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let mut func_names: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for func in &contract.functions {
            *func_names.entry(func.name.clone()).or_insert(0) += 1;
        }

        for (name, count) in func_names {
            if count > 1 {
                vulns.push(Vulnerability {
                    vuln_type: "Redundant Code".to_string(),
                    severity: Severity::Info,
                    description: format!("Function name '{}' appears {} times.", name, count),
                    location: Location {
                        file: contract.path.clone(),
                        function: name.clone(),
                        line: None,
                    },
                    recommendation: "Consolidate duplicate functions or rename for clarity.".to_string(),
                    detector_id: "CSPR-015".to_string(),
                    category: VulnCategory::CodeQuality,
                });
            }
        }

        vulns
    }

    /// Detector 16: Dead Code
    fn detect_dead_code(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        let called_functions: std::collections::HashSet<String> = analysis.control_flow.external_calls.iter()
            .map(|call| call.callee.clone())
            .collect();

        for func in &contract.functions {
            if !func.is_public && !called_functions.contains(&func.name) {
                let is_entry_point = contract.entry_points.iter()
                    .any(|ep| ep.name == func.name);

                if !is_entry_point {
                    vulns.push(Vulnerability {
                        vuln_type: "Dead Code".to_string(),
                        severity: Severity::Info,
                        description: format!("Function '{}' is private and never called.", func.name),
                        location: Location {
                            file: contract.path.clone(),
                            function: func.name.clone(),
                            line: None,
                        },
                        recommendation: "Remove unused code to reduce contract size.".to_string(),
                        detector_id: "CSPR-016".to_string(),
                        category: VulnCategory::CodeQuality,
                    });
                }
            }
        }

        vulns
    }

    /// Detector 17: Magic Numbers
    fn detect_magic_numbers(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let mut reported: HashSet<String> = HashSet::new();

        for op in &analysis.data_flow.arithmetic_ops {
            if reported.contains(&op.function) {
                continue;
            }

            let op_count = analysis.data_flow.arithmetic_ops.iter()
                .filter(|o| o.function == op.function)
                .count();

            if op_count >= 3 {
                reported.insert(op.function.clone());
                vulns.push(Vulnerability {
                    vuln_type: "Magic Numbers".to_string(),
                    severity: Severity::Info,
                    description: format!(
                        "Function '{}' may use magic numbers. Hardcoded numbers reduce readability.",
                        op.function
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: op.function.clone(),
                        line: None,
                    },
                    recommendation: "Define constants for magic numbers (e.g., const MAX_SUPPLY: u64 = 1000000).".to_string(),
                    detector_id: "CSPR-017".to_string(),
                    category: VulnCategory::CodeQuality,
                });
            }
        }

        vulns
    }

    /// Detector 18: Unsafe Type Casting
    fn detect_unsafe_type_casting(&self, contract: &ParsedContract, _analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for func in &contract.functions {
            if func.name.contains("as_") || func.name.contains("into_") || func.name.contains("from_") {
                vulns.push(Vulnerability {
                    vuln_type: "Unsafe Type Casting".to_string(),
                    severity: Severity::Low,
                    description: format!(
                        "Function '{}' appears to perform type conversion.",
                        func.name
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: func.name.clone(),
                        line: None,
                    },
                    recommendation: "Use safe conversion methods (try_into, checked_cast).".to_string(),
                    detector_id: "CSPR-018".to_string(),
                    category: VulnCategory::Security,
                });
            }
        }

        vulns
    }

    /// Detector 19: Inefficient Storage
    fn detect_inefficient_storage(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for func in &contract.functions {
            if !analysis.control_flow.functions_with_loops.contains(&func.name) {
                continue;
            }

            let storage_writes = analysis.data_flow.storage_ops.iter()
                .filter(|op| op.function == func.name && matches!(op.operation, StorageOpType::Write))
                .count();

            if storage_writes > 0 {
                vulns.push(Vulnerability {
                    vuln_type: "Inefficient Storage".to_string(),
                    severity: Severity::Medium,
                    description: format!(
                        "Function '{}' performs storage writes inside a loop. This is gas-inefficient.",
                        func.name
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: func.name.clone(),
                        line: None,
                    },
                    recommendation: "Batch storage updates or move writes outside the loop.".to_string(),
                    detector_id: "CSPR-019".to_string(),
                    category: VulnCategory::Gas,
                });
            }
        }

        vulns
    }

    /// Detector 20: Missing Events - V6.0 Enhanced
    fn detect_missing_events(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for ep in &analysis.entry_points {
            if !ep.modifies_state {
                continue;
            }

            // V6.0: Check if function emits events
            let emits_events = analysis.security_patterns.functions_emitting_events
                .contains(&ep.name);

            if !emits_events {
                vulns.push(Vulnerability {
                    vuln_type: "Missing Events".to_string(),
                    severity: Severity::Low,
                    description: format!(
                        "Entry point '{}' modifies state but may not emit events.",
                        ep.name
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: ep.name.clone(),
                        line: None,
                    },
                    recommendation: "Emit events for significant state changes.".to_string(),
                    detector_id: "CSPR-020".to_string(),
                    category: VulnCategory::CodeQuality,
                });
            }
        }

        vulns
    }

    // ═══════════════════════════════════════════════════════════
    // V6.0 NEW DETECTORS (10) - Casper-Specific
    // ═══════════════════════════════════════════════════════════

    /// Detector 21: URef Access Rights (NEW V6.0)
    fn detect_uref_access_rights(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for uref_op in &analysis.data_flow.uref_ops {
            // Check for URef operations without access rights verification
            if !uref_op.has_access_rights_check {
                let severity = match uref_op.operation {
                    URefOpType::Write | URefOpType::PassToContract => Severity::High,
                    URefOpType::StoreInDictionary => Severity::Critical,
                    _ => Severity::Medium,
                };

                vulns.push(Vulnerability {
                    vuln_type: "URef Access Rights".to_string(),
                    severity,
                    description: format!(
                        "Function '{}' performs URef {:?} operation without verifying access rights. \
                         This was the cause of the July 2024 $6.7M breach.",
                        uref_op.function, uref_op.operation
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: uref_op.function.clone(),
                        line: None,
                    },
                    recommendation: "Always verify URef access rights before operations. \
                                     Check AccessRights::READ, WRITE, ADD as appropriate.".to_string(),
                    detector_id: "CSPR-021".to_string(),
                    category: VulnCategory::CasperSpecific,
                });
            }
        }

        vulns
    }

    /// Detector 22: Unprotected Init (NEW V6.0)
    fn detect_unprotected_init(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Check if contract has init function
        if !contract.metadata.has_init_function {
            return vulns;
        }

        // Check if init is protected against re-initialization
        if !analysis.casper_analysis.has_init_protection {
            vulns.push(Vulnerability {
                vuln_type: "Unprotected Init".to_string(),
                severity: Severity::Critical,
                description: format!(
                    "Init function '{}' lacks re-initialization protection. \
                     The Casper node does NOT enforce init-only restrictions - \
                     contract authors MUST implement this check.",
                    contract.metadata.init_function_name.as_ref().unwrap_or(&"init".to_string())
                ),
                location: Location {
                    file: contract.path.clone(),
                    function: contract.metadata.init_function_name.clone().unwrap_or_default(),
                    line: None,
                },
                recommendation: "Add a storage flag (e.g., 'initialized') that is checked at the \
                                 start of init and set to true after initialization.".to_string(),
                detector_id: "CSPR-022".to_string(),
                category: VulnCategory::CasperSpecific,
            });
        }

        vulns
    }

    /// Detector 23: Purse in Dictionary (NEW V6.0)
    fn detect_purse_in_dictionary(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for purse_op in &analysis.data_flow.purse_ops {
            if purse_op.is_in_dictionary {
                vulns.push(Vulnerability {
                    vuln_type: "Purse in Dictionary".to_string(),
                    severity: Severity::Critical,
                    description: format!(
                        "Function '{}' stores a purse in a dictionary. \
                         This will cause a ForgedReference error at runtime! \
                         Purses CANNOT be stored in contract dictionaries.",
                        purse_op.function
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: purse_op.function.clone(),
                        line: None,
                    },
                    recommendation: "Store purses in NamedKeys instead of dictionaries. \
                                     Use URef with proper access rights management.".to_string(),
                    detector_id: "CSPR-023".to_string(),
                    category: VulnCategory::CasperSpecific,
                });
            }
        }

        // Also check from Casper analysis
        if analysis.casper_analysis.stores_purse_in_dictionary {
            if vulns.is_empty() {
                vulns.push(Vulnerability {
                    vuln_type: "Purse in Dictionary".to_string(),
                    severity: Severity::Critical,
                    description: "Contract attempts to store purses in dictionaries. \
                                  This will fail with ForgedReference error.".to_string(),
                    location: Location {
                        file: contract.path.clone(),
                        function: "unknown".to_string(),
                        line: None,
                    },
                    recommendation: "Use NamedKeys for purse storage.".to_string(),
                    detector_id: "CSPR-023".to_string(),
                    category: VulnCategory::CasperSpecific,
                });
            }
        }

        vulns
    }

    /// Detector 24: Call Stack Depth (NEW V6.0)
    fn detect_call_stack_depth(&self, _contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Casper mainnet limit is 10 contract calls
        if analysis.casper_analysis.estimated_call_depth > 8 {
            let severity = if analysis.casper_analysis.estimated_call_depth >= 10 {
                Severity::High
            } else {
                Severity::Medium
            };

            vulns.push(Vulnerability {
                vuln_type: "Call Stack Depth".to_string(),
                severity,
                description: format!(
                    "Estimated call stack depth is {} contracts. \
                     Casper mainnet limit is 10 consecutive contract calls. \
                     Exceeding this will cause transaction failure.",
                    analysis.casper_analysis.estimated_call_depth
                ),
                location: Location {
                    file: analysis.contract_path.clone(),
                    function: "multiple".to_string(),
                    line: None,
                },
                recommendation: "Reduce cross-contract call chains. Consider batching operations \
                                 or restructuring contract architecture.".to_string(),
                detector_id: "CSPR-024".to_string(),
                category: VulnCategory::CasperSpecific,
            });
        }

        vulns
    }

    /// Detector 25: Dictionary Key Length (NEW V6.0)
    fn detect_dictionary_key_length(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Report issues from Casper analysis
        for issue in &analysis.casper_analysis.dictionary_key_issues {
            vulns.push(Vulnerability {
                vuln_type: "Dictionary Key Length".to_string(),
                severity: Severity::Medium,
                description: format!(
                    "{}. Casper dictionary keys have a maximum length of 128 bytes.",
                    issue
                ),
                location: Location {
                    file: contract.path.clone(),
                    function: "storage".to_string(),
                    line: None,
                },
                recommendation: "Use shorter dictionary keys or hash long keys.".to_string(),
                detector_id: "CSPR-025".to_string(),
                category: VulnCategory::CasperSpecific,
            });
        }

        vulns
    }

    /// Detector 26: Unsafe Unwrap (NEW V6.0)
    fn detect_unsafe_unwrap(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for func_name in &analysis.security_patterns.functions_with_unsafe_unwrap {
            vulns.push(Vulnerability {
                vuln_type: "Unsafe Unwrap".to_string(),
                severity: Severity::Medium,
                description: format!(
                    "Function '{}' uses unsafe .unwrap() or .expect() which can panic. \
                     In Casper contracts, panics cause transaction failure and wasted gas.",
                    func_name
                ),
                location: Location {
                    file: contract.path.clone(),
                    function: func_name.clone(),
                    line: None,
                },
                recommendation: "Use .unwrap_or(), .unwrap_or_default(), or ? operator for safe error handling.".to_string(),
                detector_id: "CSPR-026".to_string(),
                category: VulnCategory::Security,
            });
        }

        vulns
    }

    /// Detector 27: Missing Caller Validation (NEW V6.0)
    fn detect_missing_caller_validation(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for ep in &analysis.entry_points {
            // Skip init functions and view functions
            if ep.is_init || !ep.modifies_state {
                continue;
            }

            // Check for functions that modify ownership without access control
            let func = contract.functions.iter().find(|f| f.name == ep.name);
            if let Some(f) = func {
                if f.patterns.modifies_ownership && !ep.has_access_control {
                    vulns.push(Vulnerability {
                        vuln_type: "Missing Caller Validation".to_string(),
                        severity: Severity::Critical,
                        description: format!(
                            "Function '{}' modifies ownership/admin settings without caller validation. \
                             This allows any user to take over the contract.",
                            ep.name
                        ),
                        location: Location {
                            file: contract.path.clone(),
                            function: ep.name.clone(),
                            line: None,
                        },
                        recommendation: "Add strict caller validation: verify runtime::get_caller() \
                                         matches the current owner before allowing ownership changes.".to_string(),
                        detector_id: "CSPR-027".to_string(),
                        category: VulnCategory::AccessControl,
                    });
                }
            }
        }

        vulns
    }

    /// Detector 28: Unbounded Loop (NEW V6.0)
    fn detect_unbounded_loop(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for func_name in &analysis.control_flow.functions_with_unbounded_loops {
            vulns.push(Vulnerability {
                vuln_type: "Unbounded Loop".to_string(),
                severity: Severity::Medium,
                description: format!(
                    "Function '{}' contains an unbounded loop (while/loop without clear bounds). \
                     This can cause out-of-gas errors and denial of service.",
                    func_name
                ),
                location: Location {
                    file: contract.path.clone(),
                    function: func_name.clone(),
                    line: None,
                },
                recommendation: "Use bounded for loops (for i in 0..MAX) or add explicit iteration limits.".to_string(),
                detector_id: "CSPR-028".to_string(),
                category: VulnCategory::Gas,
            });
        }

        vulns
    }

    /// Detector 29: CEP Compliance (NEW V6.0)
    fn detect_cep_compliance(&self, contract: &ParsedContract, _analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Check CEP-18 compliance
        if contract.metadata.uses_cep18 {
            let required_methods = ["transfer", "approve", "transfer_from", "balance_of", "allowance", "total_supply"];
            let entry_point_names: Vec<&str> = contract.entry_points.iter()
                .map(|ep| ep.name.as_str())
                .collect();

            for method in required_methods {
                if !entry_point_names.contains(&method) {
                    vulns.push(Vulnerability {
                        vuln_type: "CEP-18 Compliance".to_string(),
                        severity: Severity::Medium,
                        description: format!(
                            "CEP-18 token contract is missing required method '{}'. \
                             Non-compliant tokens may not work with wallets and DeFi protocols.",
                            method
                        ),
                        location: Location {
                            file: contract.path.clone(),
                            function: method.to_string(),
                            line: None,
                        },
                        recommendation: format!("Implement the '{}' method as per CEP-18 standard.", method),
                        detector_id: "CSPR-029".to_string(),
                        category: VulnCategory::CasperSpecific,
                    });
                }
            }
        }

        vulns
    }

    /// Detector 30: Odra Issues (NEW V6.0)
    fn detect_odra_issues(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        if let Some(odra) = &analysis.odra_analysis {
            // Check for missing init in Odra module
            if !odra.has_init && !odra.storage_fields.is_empty() {
                vulns.push(Vulnerability {
                    vuln_type: "Odra Missing Init".to_string(),
                    severity: Severity::Medium,
                    description: format!(
                        "Odra module '{}' has storage fields but no init function. \
                         Storage should be initialized properly.",
                        odra.module_name
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: odra.module_name.clone(),
                        line: None,
                    },
                    recommendation: "Add an init function with #[odra(init)] attribute.".to_string(),
                    detector_id: "CSPR-030".to_string(),
                    category: VulnCategory::OdraSpecific,
                });
            }
        }

        vulns
    }

    fn create_summary(vulns: &[Vulnerability]) -> Summary {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut info = 0;

        for vuln in vulns {
            match vuln.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Info => info += 1,
            }
        }

        // Calculate security score
        let mut score = 100i32;
        score -= critical as i32 * 50;
        score -= high as i32 * 15;
        score -= medium as i32 * 5;
        score -= low as i32 * 2;
        score -= info as i32 * 1;
        score = score.max(0).min(100);

        let grade = match score {
            95..=100 => "A+".to_string(),
            90..=94 => "A".to_string(),
            80..=89 => "B".to_string(),
            70..=79 => "C".to_string(),
            60..=69 => "D".to_string(),
            _ => "F".to_string(),
        };

        Summary {
            total_vulns: vulns.len(),
            critical,
            high,
            medium,
            low,
            info,
            security_score: score as u8,
            security_grade: grade,
            detectors_run: 30, // V6.0: 30 detectors
        }
    }
}

impl Default for VulnerabilityDetector {
    fn default() -> Self {
        Self::new()
    }
}
