//! Vulnerability Detector for Casper Contracts
//!
//! Detects common security vulnerabilities in Casper smart contracts

use anyhow::Result;
use casper_analyzer::AnalysisResult;
use casper_parser::ParsedContract;
use serde::{Deserialize, Serialize};

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
}

/// Vulnerability Detector
pub struct VulnerabilityDetector;

impl VulnerabilityDetector {
    pub fn new() -> Self {
        Self
    }

    /// Run all detectors on a contract
    pub fn detect(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Result<DetectionReport> {
        let mut vulnerabilities = Vec::new();

        // Run all 20 detectors (V4.0) 🔥
        // Original V0.2.0 detectors (5)
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

        // V4.0 NEW detectors (9) 🚀
        vulnerabilities.extend(self.detect_timestamp_manipulation(contract, analysis));
        vulnerabilities.extend(self.detect_unchecked_return_values(contract, analysis));
        vulnerabilities.extend(self.detect_dangerous_delegatecall(contract, analysis));
        vulnerabilities.extend(self.detect_redundant_code(contract, analysis));
        vulnerabilities.extend(self.detect_dead_code(contract, analysis));
        vulnerabilities.extend(self.detect_magic_numbers(contract, analysis));
        vulnerabilities.extend(self.detect_unsafe_type_casting(contract, analysis));
        vulnerabilities.extend(self.detect_inefficient_storage(contract, analysis));
        vulnerabilities.extend(self.detect_missing_events(contract, analysis));

        let summary = Self::create_summary(&vulnerabilities);

        Ok(DetectionReport {
            contract_path: contract.path.clone(),
            vulnerabilities,
            summary,
        })
    }

    /// Detector 1: Reentrancy Attacks
    fn detect_reentrancy(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for ext_call in &analysis.control_flow.external_calls {
            // Check if state is modified after external call
            let has_post_call_state_change = analysis.data_flow.storage_ops.iter()
                .any(|op| op.function == ext_call.caller &&
                    matches!(op.operation, casper_analyzer::StorageOpType::Write));

            if has_post_call_state_change {
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
                });
            }
        }

        vulns
    }

    /// Detector 2: Integer Overflow/Underflow
    fn detect_integer_overflow(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for arith_op in &analysis.data_flow.arithmetic_ops {
            if !arith_op.is_checked {
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
                    recommendation: "Use checked arithmetic operations (checked_add, checked_sub, etc.) \
                                     or validate inputs before operations.".to_string(),
                });
            }
        }

        vulns
    }

    /// Detector 3: Missing Access Control
    fn detect_access_control(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for ep_analysis in &analysis.entry_points {
            if !ep_analysis.has_access_control {
                // Find if this entry point modifies state
                let modifies_state = analysis.data_flow.storage_ops.iter()
                    .any(|op| op.function == ep_analysis.name &&
                        matches!(op.operation, casper_analyzer::StorageOpType::Write));

                if modifies_state {
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
                    });
                }
            }
        }

        vulns
    }

    /// Detector 4: Unchecked External Calls
    fn detect_unchecked_calls(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for ext_call in &analysis.control_flow.external_calls {
            if !ext_call.is_checked {
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
                    recommendation: "Always check the return value of external calls and handle failures appropriately.".to_string(),
                });
            }
        }

        vulns
    }

    /// Detector 5: Storage Key Collision
    fn detect_storage_collision(&self, contract: &ParsedContract, _analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Check for storage items with similar or hardcoded names
        let mut seen_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

        for storage_item in &contract.storage_items {
            // Check for very short keys (collision risk)
            if storage_item.name.len() < 3 {
                vulns.push(Vulnerability {
                    vuln_type: "Storage Collision Risk".to_string(),
                    severity: Severity::Low,
                    description: format!(
                        "Storage key '{}' is very short. Short keys have higher collision risk.",
                        storage_item.name
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: "storage".to_string(),
                        line: None,
                    },
                    recommendation: "Use descriptive, unique storage key names to avoid collisions.".to_string(),
                });
            }

            // Check for duplicate keys
            if seen_keys.contains(&storage_item.name) {
                vulns.push(Vulnerability {
                    vuln_type: "Storage Collision Risk".to_string(),
                    severity: Severity::Low,
                    description: format!(
                        "Duplicate storage key '{}' detected.",
                        storage_item.name
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: "storage".to_string(),
                        line: None,
                    },
                    recommendation: "Ensure each storage key is unique.".to_string(),
                });
            }

            seen_keys.insert(storage_item.name.clone());
        }

        vulns
    }

    // ═══════════════════════════════════════════════════════════
    // V0.3.0 DETECTORS (6)
    // ═══════════════════════════════════════════════════════════

    /// Detector 6: DOS (Denial of Service) Risk
    fn detect_dos_risk(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Check for unbounded loops with external calls
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
                });
            }
        }

        vulns
    }

    /// Detector 7: Gas Limit Risk
    fn detect_gas_limit_risk(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Check for loops with many arithmetic operations (gas-intensive)
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
                });
            }
        }

        vulns
    }

    /// Detector 8: Uninitialized Storage
    fn detect_uninitialized_storage(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Track storage reads vs writes
        let mut storage_writes: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut storage_reads: Vec<(String, String)> = Vec::new();

        for op in &analysis.data_flow.storage_ops {
            match op.operation {
                casper_analyzer::StorageOpType::Write => {
                    storage_writes.insert(op.key.clone());
                }
                casper_analyzer::StorageOpType::Read => {
                    storage_reads.push((op.function.clone(), op.key.clone()));
                }
            }
        }

        // Check if any reads happen before writes
        for (func, key) in storage_reads {
            if !storage_writes.contains(&key) {
                vulns.push(Vulnerability {
                    vuln_type: "Uninitialized Storage".to_string(),
                    severity: Severity::Medium,
                    description: format!(
                        "Function '{}' reads storage key '{}' which may not be initialized. \
                         This could lead to unexpected default values.",
                        func, key
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: func.clone(),
                        line: None,
                    },
                    recommendation: "Ensure storage is initialized before reading, or use safe defaults.".to_string(),
                });
            }
        }

        vulns
    }

    /// Detector 9: Multiple External Calls
    fn detect_multiple_external_calls(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Count external calls per function
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
                });
            }
        }

        vulns
    }

    /// Detector 10: Complex Entry Point
    fn detect_complex_entry_point(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for entry_point in &contract.entry_points {
            let ep_analysis = analysis.entry_points.iter()
                .find(|ep| ep.name == entry_point.name);

            if let Some(ep_data) = ep_analysis {
                if ep_data.complexity_score > 10 {
                    vulns.push(Vulnerability {
                        vuln_type: "Complex Entry Point".to_string(),
                        severity: Severity::Info,
                        description: format!(
                            "Entry point '{}' has high complexity ({}). \
                             Complex entry points are harder to audit and maintain.",
                            entry_point.name, ep_data.complexity_score
                        ),
                        location: Location {
                            file: contract.path.clone(),
                            function: entry_point.name.clone(),
                            line: None,
                        },
                        recommendation: "Consider refactoring into smaller, testable functions.".to_string(),
                    });
                }
            }
        }

        vulns
    }

    /// Detector 11: Write-Only Storage
    fn detect_write_only_storage(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Track storage that is written but never read
        let mut writes: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut reads: std::collections::HashSet<String> = std::collections::HashSet::new();

        for op in &analysis.data_flow.storage_ops {
            match op.operation {
                casper_analyzer::StorageOpType::Write => { writes.insert(op.key.clone()); }
                casper_analyzer::StorageOpType::Read => { reads.insert(op.key.clone()); }
            }
        }

        for key in &writes {
            if !reads.contains(key) {
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
                });
            }
        }

        vulns
    }

    // ═══════════════════════════════════════════════════════════
    // V4.0 NEW DETECTORS (9) 🚀
    // ═══════════════════════════════════════════════════════════

    /// Detector 12: Timestamp Manipulation
    fn detect_timestamp_manipulation(&self, contract: &ParsedContract, _analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Look for timestamp usage in critical logic
        for func in &contract.functions {
            for stmt in &func.body {
                if let casper_parser::Statement::ExternalCall { method, .. } = stmt {
                    // Check for timestamp-related functions
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
                            recommendation: "Use block height instead of timestamp for time-dependent logic, \
                                           or accept ±15 second variance in timestamps.".to_string(),
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

        // Check for external calls whose return values are not checked
        for call in &analysis.control_flow.external_calls {
            // In a real implementation, we'd check if the return value is used
            // For now, flag all external calls in entry points as potential risks
            let is_entry_point = contract.entry_points.iter()
                .any(|ep| ep.name == call.caller);

            if is_entry_point {
                vulns.push(Vulnerability {
                    vuln_type: "Unchecked Return Value".to_string(),
                    severity: Severity::Medium,
                    description: format!(
                        "External call from '{}' to '{}' may have unchecked return value. \
                         Ignoring return values can lead to unexpected behavior.",
                        call.caller, call.callee
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: call.caller.clone(),
                        line: None,
                    },
                    recommendation: "Always check return values from external calls and handle errors appropriately.".to_string(),
                });
            }
        }

        vulns
    }

    /// Detector 14: Dangerous Delegatecall
    fn detect_dangerous_delegatecall(&self, contract: &ParsedContract, _analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Check for delegatecall usage
        for func in &contract.functions {
            for stmt in &func.body {
                if let casper_parser::Statement::ExternalCall { method, .. } = stmt {
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
                            recommendation: "Ensure delegatecall target is from a whitelist of trusted contracts. \
                                           Never allow user input to control the target address.".to_string(),
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

        // Check for functions with identical names (suspicious)
        let mut func_names: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for func in &contract.functions {
            *func_names.entry(func.name.clone()).or_insert(0) += 1;
        }

        for (name, count) in func_names {
            if count > 1 {
                vulns.push(Vulnerability {
                    vuln_type: "Redundant Code".to_string(),
                    severity: Severity::Info,
                    description: format!(
                        "Function name '{}' appears {} times. \
                         Redundant code increases contract size and maintenance burden.",
                        name, count
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: name.clone(),
                        line: None,
                    },
                    recommendation: "Consolidate duplicate functions or rename for clarity.".to_string(),
                });
            }
        }

        vulns
    }

    /// Detector 16: Dead Code
    fn detect_dead_code(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Check for private functions that are never called
        let called_functions: std::collections::HashSet<String> = analysis.control_flow.external_calls.iter()
            .map(|call| call.callee.clone())
            .collect();

        for func in &contract.functions {
            if !func.is_public && !called_functions.contains(&func.name) {
                // Also check if it's not an entry point
                let is_entry_point = contract.entry_points.iter()
                    .any(|ep| ep.name == func.name);

                if !is_entry_point {
                    vulns.push(Vulnerability {
                        vuln_type: "Dead Code".to_string(),
                        severity: Severity::Info,
                        description: format!(
                            "Function '{}' is private and never called. \
                             Dead code increases contract size unnecessarily.",
                            func.name
                        ),
                        location: Location {
                            file: contract.path.clone(),
                            function: func.name.clone(),
                            line: None,
                        },
                        recommendation: "Remove unused code to reduce contract size and improve clarity.".to_string(),
                    });
                }
            }
        }

        vulns
    }

    /// Detector 17: Magic Numbers
    fn detect_magic_numbers(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Check for arithmetic operations with hardcoded numbers
        for op in &analysis.data_flow.arithmetic_ops {
            // In a real implementation, we'd parse the operands
            // For now, flag functions with multiple arithmetic ops as potentially having magic numbers
            let op_count = analysis.data_flow.arithmetic_ops.iter()
                .filter(|o| o.function == op.function)
                .count();

            if op_count >= 3 {
                vulns.push(Vulnerability {
                    vuln_type: "Magic Numbers".to_string(),
                    severity: Severity::Info,
                    description: format!(
                        "Function '{}' contains multiple arithmetic operations that may use magic numbers. \
                         Hardcoded numbers reduce code readability and maintainability.",
                        op.function
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: op.function.clone(),
                        line: None,
                    },
                    recommendation: "Define constants for magic numbers with descriptive names (e.g., const MAX_SUPPLY: u64 = 1000000).".to_string(),
                });
                break; // Only report once per function
            }
        }

        vulns
    }

    /// Detector 18: Unsafe Type Casting
    fn detect_unsafe_type_casting(&self, contract: &ParsedContract, _analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Look for type conversion functions
        for func in &contract.functions {
            if func.name.contains("as_") || func.name.contains("into_") || func.name.contains("from_") {
                vulns.push(Vulnerability {
                    vuln_type: "Unsafe Type Casting".to_string(),
                    severity: Severity::Low,
                    description: format!(
                        "Function '{}' appears to perform type conversion. \
                         Unsafe casts can cause data loss or unexpected behavior.",
                        func.name
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: func.name.clone(),
                        line: None,
                    },
                    recommendation: "Use safe conversion methods (try_into, checked_cast) and validate ranges.".to_string(),
                });
            }
        }

        vulns
    }

    /// Detector 19: Inefficient Storage
    fn detect_inefficient_storage(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Check for excessive storage writes in loops
        for func in &contract.functions {
            if !analysis.control_flow.functions_with_loops.contains(&func.name) {
                continue;
            }

            let storage_writes = analysis.data_flow.storage_ops.iter()
                .filter(|op| op.function == func.name && matches!(op.operation, casper_analyzer::StorageOpType::Write))
                .count();

            if storage_writes > 0 {
                vulns.push(Vulnerability {
                    vuln_type: "Inefficient Storage".to_string(),
                    severity: Severity::Medium,
                    description: format!(
                        "Function '{}' performs storage writes inside a loop. \
                         This is very gas-inefficient and may fail for large loops.",
                        func.name
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: func.name.clone(),
                        line: None,
                    },
                    recommendation: "Batch storage updates or move writes outside the loop.".to_string(),
                });
            }
        }

        vulns
    }

    /// Detector 20: Missing Events
    fn detect_missing_events(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Check if state-changing entry points emit events
        for entry_point in &contract.entry_points {
            let has_storage_write = analysis.data_flow.storage_ops.iter()
                .any(|op| op.function == entry_point.name && matches!(op.operation, casper_analyzer::StorageOpType::Write));

            if has_storage_write {
                // In a real implementation, we'd check for event emissions
                // For now, flag all state-changing entry points
                vulns.push(Vulnerability {
                    vuln_type: "Missing Events".to_string(),
                    severity: Severity::Low,
                    description: format!(
                        "Entry point '{}' modifies state but may not emit events. \
                         Events are important for tracking state changes and debugging.",
                        entry_point.name
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: entry_point.name.clone(),
                        line: None,
                    },
                    recommendation: "Emit events for all significant state changes (transfers, approvals, config updates).".to_string(),
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

        // Calculate security score (100 = perfect, 0 = critical issues)
        // Deduct points based on severity:
        // Critical: -50 points each
        // High: -15 points each
        // Medium: -5 points each
        // Low: -2 points each
        // Info: -1 point each
        let mut score = 100i32;
        score -= critical as i32 * 50;
        score -= high as i32 * 15;
        score -= medium as i32 * 5;
        score -= low as i32 * 2;
        score -= info as i32 * 1;
        score = score.max(0).min(100); // Clamp between 0-100

        // Calculate security grade
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
        }
    }
}

impl Default for VulnerabilityDetector {
    fn default() -> Self {
        Self::new()
    }
}
