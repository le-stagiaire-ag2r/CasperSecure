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

        // Run all 8 detectors (4 original + 3 new + 1 storage collision)
        vulnerabilities.extend(self.detect_reentrancy(contract, analysis));
        vulnerabilities.extend(self.detect_integer_overflow(contract, analysis));
        vulnerabilities.extend(self.detect_access_control(contract, analysis));
        vulnerabilities.extend(self.detect_unchecked_calls(contract, analysis));
        vulnerabilities.extend(self.detect_storage_collision(contract, analysis));

        // NEW: V0.3.0 detectors
        vulnerabilities.extend(self.detect_dos_risk(contract, analysis));
        vulnerabilities.extend(self.detect_uninitialized_storage(contract, analysis));
        vulnerabilities.extend(self.detect_dangerous_patterns(contract, analysis));

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

    /// Detector 6: DOS (Denial of Service) Risk - NEW V0.3.0
    fn detect_dos_risk(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Check for loops with external calls (unbounded loops = DOS risk)
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
                         If the loop is unbounded or the external call fails repeatedly, \
                         this can cause a denial of service.",
                        func.name
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: func.name.clone(),
                        line: None,
                    },
                    recommendation: "Limit the number of loop iterations, use batch processing, \
                                     or avoid external calls in loops. Consider using a pull-based \
                                     pattern instead of push-based.".to_string(),
                });
            }

            // Also check for loops with many arithmetic operations (gas limit issue)
            if has_loop {
                let arith_count = analysis.data_flow.arithmetic_ops.iter()
                    .filter(|op| op.function == func.name)
                    .count();

                if arith_count > 5 {
                    vulns.push(Vulnerability {
                        vuln_type: "Gas Limit Risk".to_string(),
                        severity: Severity::Low,
                        description: format!(
                            "Function '{}' has a loop with {} arithmetic operations. \
                             This may consume excessive gas and fail for large inputs.",
                            func.name, arith_count
                        ),
                        location: Location {
                            file: contract.path.clone(),
                            function: func.name.clone(),
                            line: None,
                        },
                        recommendation: "Optimize the loop, reduce arithmetic operations, \
                                         or add gas limits and checkpoints.".to_string(),
                    });
                }
            }
        }

        vulns
    }

    /// Detector 7: Uninitialized Storage - NEW V0.3.0
    fn detect_uninitialized_storage(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Track which storage keys are written vs read in each function
        let mut storage_writes: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        let mut storage_reads: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

        for op in &analysis.data_flow.storage_ops {
            match op.operation {
                casper_analyzer::StorageOpType::Write => {
                    storage_writes.entry(op.function.clone())
                        .or_insert_with(Vec::new)
                        .push(op.key.clone());
                }
                casper_analyzer::StorageOpType::Read => {
                    storage_reads.entry(op.function.clone())
                        .or_insert_with(Vec::new)
                        .push(op.key.clone());
                }
            }
        }

        // Check for reads before writes in same function
        for (func_name, reads) in &storage_reads {
            let writes = storage_writes.get(func_name).cloned().unwrap_or_default();

            for read_key in reads {
                if !writes.contains(read_key) && read_key != "storage_read" {
                    vulns.push(Vulnerability {
                        vuln_type: "Uninitialized Storage".to_string(),
                        severity: Severity::Medium,
                        description: format!(
                            "Function '{}' reads from storage key '{}' without initializing it first. \
                             This may return default/zero values unexpectedly.",
                            func_name, read_key
                        ),
                        location: Location {
                            file: contract.path.clone(),
                            function: func_name.clone(),
                            line: None,
                        },
                        recommendation: "Always initialize storage before reading, or handle the case \
                                         where the storage value might be uninitialized.".to_string(),
                    });
                }
            }
        }

        vulns
    }

    /// Detector 8: Dangerous Patterns - NEW V0.3.0
    fn detect_dangerous_patterns(&self, contract: &ParsedContract, analysis: &AnalysisResult) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Pattern 1: Multiple external calls in single function (increased attack surface)
        for func in &contract.functions {
            let external_call_count = analysis.control_flow.external_calls.iter()
                .filter(|call| call.caller == func.name)
                .count();

            if external_call_count > 2 {
                vulns.push(Vulnerability {
                    vuln_type: "Multiple External Calls".to_string(),
                    severity: Severity::Low,
                    description: format!(
                        "Function '{}' makes {} external calls. Multiple external calls \
                         increase the attack surface and complexity.",
                        func.name, external_call_count
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: func.name.clone(),
                        line: None,
                    },
                    recommendation: "Consider splitting the function into smaller functions, \
                                     or reducing the number of external dependencies.".to_string(),
                });
            }
        }

        // Pattern 2: Complex entry points (high cyclomatic complexity)
        for ep_analysis in &analysis.entry_points {
            if ep_analysis.complexity_score > 10 {
                vulns.push(Vulnerability {
                    vuln_type: "Complex Entry Point".to_string(),
                    severity: Severity::Info,
                    description: format!(
                        "Entry point '{}' has high complexity (score: {}). \
                         Complex entry points are harder to audit and more prone to bugs.",
                        ep_analysis.name, ep_analysis.complexity_score
                    ),
                    location: Location {
                        file: contract.path.clone(),
                        function: ep_analysis.name.clone(),
                        line: None,
                    },
                    recommendation: "Refactor the entry point into smaller, simpler functions. \
                                     Use helper functions to reduce complexity.".to_string(),
                });
            }
        }

        // Pattern 3: Storage write without read (potential waste or logic error)
        let mut func_storage_reads: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut func_storage_writes: std::collections::HashSet<String> = std::collections::HashSet::new();

        for op in &analysis.data_flow.storage_ops {
            match op.operation {
                casper_analyzer::StorageOpType::Read => {
                    func_storage_reads.insert(format!("{}:{}", op.function, op.key));
                }
                casper_analyzer::StorageOpType::Write => {
                    func_storage_writes.insert(format!("{}:{}", op.function, op.key));
                }
            }
        }

        for write_key in &func_storage_writes {
            if !func_storage_reads.contains(write_key) {
                let parts: Vec<&str> = write_key.split(':').collect();
                if parts.len() == 2 && parts[1] != "storage_write" {
                    vulns.push(Vulnerability {
                        vuln_type: "Write-Only Storage".to_string(),
                        severity: Severity::Info,
                        description: format!(
                            "Function '{}' writes to storage '{}' but never reads it. \
                             This might indicate unused storage or a logic error.",
                            parts[0], parts[1]
                        ),
                        location: Location {
                            file: contract.path.clone(),
                            function: parts[0].to_string(),
                            line: None,
                        },
                        recommendation: "Verify that this storage write is intentional. \
                                         Remove if unused, or add read logic if needed.".to_string(),
                    });
                }
            }
        }

        vulns
    }

    fn create_summary(vulns: &[Vulnerability]) -> Summary {
        let mut summary = Summary {
            total_vulns: vulns.len(),
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };

        for vuln in vulns {
            match vuln.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }

        summary
    }
}

impl Default for VulnerabilityDetector {
    fn default() -> Self {
        Self::new()
    }
}
