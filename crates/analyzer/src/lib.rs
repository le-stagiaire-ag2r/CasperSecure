//! Casper Contract Analyzer V6.0
//!
//! Analyzes parsed contracts to extract security-relevant information
//!
//! V6.0 Enhancements:
//! - Real access control detection
//! - Call graph analysis
//! - Storage initialization tracking
//! - Taint analysis for user inputs
//! - Odra-specific analysis

use anyhow::Result;
use casper_parser::{
    ParsedContract, Function, EntryPoint, Statement, StorageType,
    AccessControlType, URefOpType, PurseOpType, ErrorHandlingType,
    EntryPointType,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Analysis result for a contract - V6.0 Enhanced
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Contract being analyzed
    pub contract_path: String,
    /// Control flow information
    pub control_flow: ControlFlowAnalysis,
    /// Data flow information
    pub data_flow: DataFlowAnalysis,
    /// Entry point analysis
    pub entry_points: Vec<EntryPointAnalysis>,
    /// Function call graph
    pub call_graph: CallGraph,
    /// V6.0: Storage analysis
    pub storage_analysis: StorageAnalysis,
    /// V6.0: Security patterns found
    pub security_patterns: SecurityPatterns,
    /// V6.0: Casper-specific analysis
    pub casper_analysis: CasperSpecificAnalysis,
    /// V6.0: Odra-specific analysis (if applicable)
    pub odra_analysis: Option<OdraAnalysis>,
}

/// Control flow analysis results - V6.0 Enhanced
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowAnalysis {
    /// Functions with loops
    pub functions_with_loops: Vec<String>,
    /// V6.0: Functions with unbounded loops
    pub functions_with_unbounded_loops: Vec<String>,
    /// Functions with complex branching
    pub complex_branches: Vec<String>,
    /// Functions with external calls
    pub external_calls: Vec<ExternalCall>,
    /// Recursive functions
    pub recursive_functions: Vec<String>,
    /// V6.0: Cross-contract calls
    pub cross_contract_calls: Vec<CrossContractCall>,
}

/// External call information - V6.0 Enhanced
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalCall {
    pub caller: String,
    pub callee: String,
    /// V6.0: Now properly detected
    pub is_checked: bool,
    /// V6.0: Call type
    pub call_type: ExternalCallType,
}

/// V6.0: External call types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExternalCallType {
    ContractCall,
    Transfer,
    DelegateCall,
    VersionedCall,
    SystemCall,
}

/// V6.0: Cross-contract call tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractCall {
    pub from_function: String,
    pub to_contract: String,
    pub method: String,
    pub depth: u32,
}

/// Data flow analysis results - V6.0 Enhanced
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowAnalysis {
    /// Storage operations
    pub storage_ops: Vec<StorageOperation>,
    /// Tainted variables (from external input)
    pub tainted_vars: Vec<TaintedVariable>,
    /// Arithmetic operations
    pub arithmetic_ops: Vec<ArithmeticOp>,
    /// V6.0: URef operations
    pub uref_ops: Vec<URefOperation>,
    /// V6.0: Purse operations
    pub purse_ops: Vec<PurseOperation>,
}

/// Storage operation - V6.0 Enhanced
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageOperation {
    pub function: String,
    pub key: String,
    pub operation: StorageOpType,
    /// V6.0: Storage type
    pub storage_type: Option<StorageType>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StorageOpType {
    Read,
    Write,
}

/// V6.0: Tainted variable tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintedVariable {
    pub name: String,
    pub source: String,
    pub flows_to: Vec<String>,
}

/// Arithmetic operation - V6.0 Enhanced
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArithmeticOp {
    pub function: String,
    pub operation: String,
    /// V6.0: Now properly detected from parser
    pub is_checked: bool,
    /// V6.0: Method used (checked_add, saturating_sub, etc.)
    pub method: Option<String>,
}

/// V6.0: URef operation tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct URefOperation {
    pub function: String,
    pub operation: URefOpType,
    pub has_access_rights_check: bool,
}

/// V6.0: Purse operation tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurseOperation {
    pub function: String,
    pub operation: PurseOpType,
    pub is_in_dictionary: bool,
}

/// Entry point specific analysis - V6.0 Enhanced
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPointAnalysis {
    pub name: String,
    /// V6.0: Now properly detected
    pub has_access_control: bool,
    /// V6.0: Access control type if present
    pub access_control_type: Option<AccessControlType>,
    pub has_reentrancy_guard: bool,
    pub complexity_score: u32,
    /// V6.0: Entry point type
    pub entry_point_type: EntryPointType,
    /// V6.0: Is this an init function
    pub is_init: bool,
    /// V6.0: Modifies state
    pub modifies_state: bool,
    /// V6.0: Has external calls
    pub has_external_calls: bool,
    /// V6.0: Uses checked arithmetic
    pub uses_checked_arithmetic: bool,
}

/// Call graph representation - V6.0 Enhanced
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    pub edges: Vec<CallEdge>,
    /// V6.0: Entry point to functions mapping
    pub entry_point_paths: HashMap<String, Vec<String>>,
    /// V6.0: Max call depth
    pub max_depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub from: String,
    pub to: String,
    /// V6.0: Is this an external call
    pub is_external: bool,
}

/// V6.0: Storage analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAnalysis {
    /// Storage keys that are initialized
    pub initialized_keys: HashSet<String>,
    /// Storage keys that are read
    pub read_keys: HashSet<String>,
    /// Storage keys that are written
    pub written_keys: HashSet<String>,
    /// Read before write (potential uninitialized)
    pub read_before_write: Vec<String>,
    /// Write only keys (never read)
    pub write_only_keys: Vec<String>,
    /// Initialization function
    pub init_function: Option<String>,
}

/// V6.0: Security patterns detected
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityPatterns {
    /// Functions with access control
    pub functions_with_access_control: Vec<String>,
    /// Functions with reentrancy guards
    pub functions_with_reentrancy_guards: Vec<String>,
    /// Functions using checked arithmetic
    pub functions_with_checked_arithmetic: Vec<String>,
    /// Functions with proper error handling
    pub functions_with_safe_error_handling: Vec<String>,
    /// Functions with unsafe unwrap
    pub functions_with_unsafe_unwrap: Vec<String>,
    /// Functions emitting events
    pub functions_emitting_events: Vec<String>,
}

/// V6.0: Casper-specific analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CasperSpecificAnalysis {
    /// Call stack depth (max 10 on mainnet)
    pub estimated_call_depth: u32,
    /// Uses URef operations
    pub uses_urefs: bool,
    /// Has URef access rights checks
    pub has_uref_access_checks: bool,
    /// Stores purses in dictionaries (dangerous!)
    pub stores_purse_in_dictionary: bool,
    /// Dictionary key lengths (max 128 bytes)
    pub dictionary_key_issues: Vec<String>,
    /// Has proper init protection
    pub has_init_protection: bool,
    /// Session vs Contract context awareness
    pub context_aware: bool,
}

/// V6.0: Odra-specific analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OdraAnalysis {
    /// Module name
    pub module_name: String,
    /// Has init function
    pub has_init: bool,
    /// Storage fields
    pub storage_fields: Vec<String>,
    /// Uses Var<T>
    pub uses_var: bool,
    /// Uses Mapping<K, V>
    pub uses_mapping: bool,
    /// Uses List<T>
    pub uses_list: bool,
}

/// Casper Contract Analyzer - V6.0
pub struct CasperAnalyzer;

impl CasperAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Analyze a parsed contract
    pub fn analyze(&self, contract: &ParsedContract) -> Result<AnalysisResult> {
        let control_flow = self.analyze_control_flow(contract);
        let data_flow = self.analyze_data_flow(contract);
        let entry_points = self.analyze_entry_points(contract);
        let call_graph = self.build_call_graph(contract);
        let storage_analysis = self.analyze_storage(contract);
        let security_patterns = self.detect_security_patterns(contract);
        let casper_analysis = self.analyze_casper_specific(contract, &call_graph);
        let odra_analysis = self.analyze_odra(contract);

        Ok(AnalysisResult {
            contract_path: contract.path.clone(),
            control_flow,
            data_flow,
            entry_points,
            call_graph,
            storage_analysis,
            security_patterns,
            casper_analysis,
            odra_analysis,
        })
    }

    fn analyze_control_flow(&self, contract: &ParsedContract) -> ControlFlowAnalysis {
        let mut functions_with_loops = Vec::new();
        let mut functions_with_unbounded_loops = Vec::new();
        let mut complex_branches = Vec::new();
        let mut external_calls = Vec::new();
        let mut cross_contract_calls = Vec::new();
        let recursive_functions = Vec::new();

        for func in &contract.functions {
            let mut has_loop = false;
            let mut has_unbounded_loop = false;
            let mut branch_count = 0;

            for stmt in &func.body {
                match stmt {
                    Statement::Loop { is_bounded } => {
                        has_loop = true;
                        if !is_bounded {
                            has_unbounded_loop = true;
                        }
                    }
                    Statement::Conditional => {
                        branch_count += 1;
                    }
                    Statement::ExternalCall { target, method, is_checked } => {
                        let call_type = self.determine_call_type(method);
                        external_calls.push(ExternalCall {
                            caller: func.name.clone(),
                            callee: format!("{}::{}", target, method),
                            is_checked: *is_checked,
                            call_type: call_type.clone(),
                        });

                        // Track cross-contract calls
                        if call_type == ExternalCallType::ContractCall ||
                           call_type == ExternalCallType::VersionedCall {
                            cross_contract_calls.push(CrossContractCall {
                                from_function: func.name.clone(),
                                to_contract: target.clone(),
                                method: method.clone(),
                                depth: 1,
                            });
                        }
                    }
                    _ => {}
                }
            }

            if has_loop {
                functions_with_loops.push(func.name.clone());
            }
            if has_unbounded_loop {
                functions_with_unbounded_loops.push(func.name.clone());
            }
            if branch_count > 3 {
                complex_branches.push(func.name.clone());
            }
        }

        ControlFlowAnalysis {
            functions_with_loops,
            functions_with_unbounded_loops,
            complex_branches,
            external_calls,
            recursive_functions,
            cross_contract_calls,
        }
    }

    fn determine_call_type(&self, method: &str) -> ExternalCallType {
        let lower = method.to_lowercase();
        if lower.contains("delegate") {
            ExternalCallType::DelegateCall
        } else if lower.contains("versioned") {
            ExternalCallType::VersionedCall
        } else if lower.contains("transfer") {
            ExternalCallType::Transfer
        } else if lower.contains("system") {
            ExternalCallType::SystemCall
        } else {
            ExternalCallType::ContractCall
        }
    }

    fn analyze_data_flow(&self, contract: &ParsedContract) -> DataFlowAnalysis {
        let mut storage_ops = Vec::new();
        let mut arithmetic_ops = Vec::new();
        let mut tainted_vars = Vec::new();
        let mut uref_ops = Vec::new();
        let mut purse_ops = Vec::new();

        for func in &contract.functions {
            // Track tainted inputs
            for param in &func.parameters {
                if param.is_user_input {
                    tainted_vars.push(TaintedVariable {
                        name: param.name.clone(),
                        source: format!("parameter:{}", func.name),
                        flows_to: Vec::new(),
                    });
                }
            }

            for stmt in &func.body {
                match stmt {
                    Statement::StorageAccess { key, is_write, storage_type } => {
                        storage_ops.push(StorageOperation {
                            function: func.name.clone(),
                            key: key.clone(),
                            operation: if *is_write {
                                StorageOpType::Write
                            } else {
                                StorageOpType::Read
                            },
                            storage_type: storage_type.clone(),
                        });
                    }
                    Statement::ArithmeticOp { operation, is_checked, method } => {
                        arithmetic_ops.push(ArithmeticOp {
                            function: func.name.clone(),
                            operation: operation.clone(),
                            is_checked: *is_checked,
                            method: method.clone(),
                        });
                    }
                    Statement::URefOperation { operation, .. } => {
                        let has_check = func.body.iter().any(|s| {
                            matches!(s, Statement::URefOperation {
                                operation: URefOpType::AccessRightsCheck, ..
                            })
                        });
                        uref_ops.push(URefOperation {
                            function: func.name.clone(),
                            operation: operation.clone(),
                            has_access_rights_check: has_check,
                        });
                    }
                    Statement::PurseOperation { operation } => {
                        let is_in_dict = matches!(operation, PurseOpType::StoreInDictionary);
                        purse_ops.push(PurseOperation {
                            function: func.name.clone(),
                            operation: operation.clone(),
                            is_in_dictionary: is_in_dict,
                        });
                    }
                    _ => {}
                }
            }
        }

        DataFlowAnalysis {
            storage_ops,
            tainted_vars,
            arithmetic_ops,
            uref_ops,
            purse_ops,
        }
    }

    fn analyze_entry_points(&self, contract: &ParsedContract) -> Vec<EntryPointAnalysis> {
        contract.entry_points.iter().map(|ep| {
            self.analyze_single_entry_point(ep, contract)
        }).collect()
    }

    fn analyze_single_entry_point(&self, ep: &EntryPoint, contract: &ParsedContract) -> EntryPointAnalysis {
        let func = contract.functions.iter()
            .find(|f| f.name == ep.function);

        let (has_access_control, access_control_type) = func
            .map(|f| self.detect_access_control(f))
            .unwrap_or((false, None));

        let has_reentrancy_guard = func
            .map(|f| self.has_reentrancy_guard(f))
            .unwrap_or(false);

        let complexity_score = func
            .map(|f| self.calculate_complexity(f))
            .unwrap_or(0);

        let is_init = self.is_init_entry_point(&ep.name, &ep.entry_point_type);

        let modifies_state = func.map(|f| {
            f.body.iter().any(|s| matches!(s, Statement::StorageAccess { is_write: true, .. }))
        }).unwrap_or(false);

        let has_external_calls = func.map(|f| {
            f.body.iter().any(|s| matches!(s, Statement::ExternalCall { .. }))
        }).unwrap_or(false);

        let uses_checked_arithmetic = func.map(|f| {
            f.patterns.uses_checked_arithmetic
        }).unwrap_or(false);

        EntryPointAnalysis {
            name: ep.name.clone(),
            has_access_control,
            access_control_type,
            has_reentrancy_guard,
            complexity_score,
            entry_point_type: ep.entry_point_type.clone(),
            is_init,
            modifies_state,
            has_external_calls,
            uses_checked_arithmetic,
        }
    }

    /// V6.0: Real access control detection
    fn detect_access_control(&self, func: &Function) -> (bool, Option<AccessControlType>) {
        // Check from parsed patterns first
        if func.patterns.has_access_control {
            // Find the type
            for stmt in &func.body {
                if let Statement::AccessControlCheck { check_type } = stmt {
                    return (true, Some(check_type.clone()));
                }
            }
            return (true, Some(AccessControlType::Other));
        }

        // Scan function body for access control patterns
        for stmt in &func.body {
            if let Statement::AccessControlCheck { check_type } = stmt {
                return (true, Some(check_type.clone()));
            }
        }

        // Check function name patterns
        let name_lower = func.name.to_lowercase();
        if name_lower.contains("only_owner") || name_lower.contains("require_owner") {
            return (true, Some(AccessControlType::OwnerCheck));
        }

        (false, None)
    }

    fn has_reentrancy_guard(&self, func: &Function) -> bool {
        // Check parsed patterns
        if func.patterns.has_reentrancy_guard {
            return true;
        }

        // Check for mutex/lock patterns in function body
        let func_str = format!("{:?}", func.body);
        func_str.to_lowercase().contains("lock") ||
        func_str.to_lowercase().contains("mutex") ||
        func_str.to_lowercase().contains("reentrancy") ||
        func_str.to_lowercase().contains("guard")
    }

    fn calculate_complexity(&self, func: &Function) -> u32 {
        let mut complexity: u32 = 1; // Base complexity

        for stmt in &func.body {
            match stmt {
                Statement::Conditional => complexity += 1,
                Statement::Loop { .. } => complexity += 2,
                Statement::ExternalCall { .. } => complexity += 1,
                _ => {}
            }
        }

        // Factor in number of statements
        complexity += (func.body.len() / 5) as u32;

        complexity
    }

    fn is_init_entry_point(&self, name: &str, ep_type: &EntryPointType) -> bool {
        matches!(ep_type, EntryPointType::OdraInit) ||
        name.to_lowercase() == "init" ||
        name.to_lowercase() == "constructor" ||
        name.to_lowercase() == "initialize" ||
        name.to_lowercase() == "call"
    }

    /// V6.0: Build real call graph
    fn build_call_graph(&self, contract: &ParsedContract) -> CallGraph {
        let mut edges = Vec::new();
        let mut entry_point_paths: HashMap<String, Vec<String>> = HashMap::new();

        // Build edges from function calls
        for func in &contract.functions {
            for stmt in &func.body {
                if let Statement::ExternalCall { target, method, .. } = stmt {
                    edges.push(CallEdge {
                        from: func.name.clone(),
                        to: format!("{}::{}", target, method),
                        is_external: true,
                    });
                }
            }
        }

        // Build entry point paths
        for ep in &contract.entry_points {
            let mut path = Vec::new();
            path.push(ep.name.clone());

            // Find all functions called from this entry point
            self.trace_calls(&ep.name, contract, &mut path, &mut HashSet::new());

            entry_point_paths.insert(ep.name.clone(), path);
        }

        // Calculate max depth
        let max_depth = entry_point_paths.values()
            .map(|p| p.len() as u32)
            .max()
            .unwrap_or(1);

        CallGraph {
            edges,
            entry_point_paths,
            max_depth,
        }
    }

    fn trace_calls(&self, func_name: &str, contract: &ParsedContract, path: &mut Vec<String>, visited: &mut HashSet<String>) {
        if visited.contains(func_name) {
            return; // Avoid infinite recursion
        }
        visited.insert(func_name.to_string());

        if let Some(func) = contract.functions.iter().find(|f| f.name == func_name) {
            for stmt in &func.body {
                if let Statement::ExternalCall { target, method, .. } = stmt {
                    let callee = format!("{}::{}", target, method);
                    if !path.contains(&callee) {
                        path.push(callee.clone());
                    }
                }
            }
        }
    }

    /// V6.0: Storage analysis
    fn analyze_storage(&self, contract: &ParsedContract) -> StorageAnalysis {
        let mut initialized_keys = HashSet::new();
        let mut read_keys = HashSet::new();
        let mut written_keys = HashSet::new();
        let mut init_function = None;

        // Find init function
        for func in &contract.functions {
            let name_lower = func.name.to_lowercase();
            if name_lower == "init" || name_lower == "constructor" || name_lower == "call" {
                init_function = Some(func.name.clone());

                // Keys written in init are initialized
                for stmt in &func.body {
                    if let Statement::StorageAccess { key, is_write: true, .. } = stmt {
                        initialized_keys.insert(key.clone());
                    }
                }
            }
        }

        // Track all storage operations
        for func in &contract.functions {
            for stmt in &func.body {
                if let Statement::StorageAccess { key, is_write, .. } = stmt {
                    if *is_write {
                        written_keys.insert(key.clone());
                    } else {
                        read_keys.insert(key.clone());
                    }
                }
            }
        }

        // Find read-before-write issues (excluding initialized keys)
        let read_before_write: Vec<String> = read_keys.iter()
            .filter(|k| !initialized_keys.contains(*k) && !written_keys.contains(*k))
            .cloned()
            .collect();

        // Find write-only keys
        let write_only_keys: Vec<String> = written_keys.iter()
            .filter(|k| !read_keys.contains(*k))
            .cloned()
            .collect();

        StorageAnalysis {
            initialized_keys,
            read_keys,
            written_keys,
            read_before_write,
            write_only_keys,
            init_function,
        }
    }

    /// V6.0: Detect security patterns
    fn detect_security_patterns(&self, contract: &ParsedContract) -> SecurityPatterns {
        let mut patterns = SecurityPatterns::default();

        for func in &contract.functions {
            // Check function patterns from parser
            if func.patterns.has_access_control {
                patterns.functions_with_access_control.push(func.name.clone());
            }
            if func.patterns.has_reentrancy_guard {
                patterns.functions_with_reentrancy_guards.push(func.name.clone());
            }
            if func.patterns.uses_checked_arithmetic {
                patterns.functions_with_checked_arithmetic.push(func.name.clone());
            }
            if func.patterns.uses_safe_unwrap {
                patterns.functions_with_safe_error_handling.push(func.name.clone());
            }

            // Check for unsafe unwrap
            let has_unsafe_unwrap = func.body.iter().any(|s| {
                matches!(s, Statement::ErrorHandling {
                    handling_type: ErrorHandlingType::Unwrap | ErrorHandlingType::Expect
                })
            });
            if has_unsafe_unwrap && !func.patterns.uses_safe_unwrap {
                patterns.functions_with_unsafe_unwrap.push(func.name.clone());
            }

            // Check for event emissions
            let emits_events = func.body.iter().any(|s| {
                matches!(s, Statement::EventEmission { .. })
            });
            if emits_events {
                patterns.functions_emitting_events.push(func.name.clone());
            }
        }

        patterns
    }

    /// V6.0: Casper-specific analysis
    fn analyze_casper_specific(&self, contract: &ParsedContract, call_graph: &CallGraph) -> CasperSpecificAnalysis {
        let mut analysis = CasperSpecificAnalysis::default();

        // Estimate call depth
        analysis.estimated_call_depth = call_graph.max_depth;

        // Check for URef usage
        for func in &contract.functions {
            for stmt in &func.body {
                match stmt {
                    Statement::URefOperation { operation, .. } => {
                        analysis.uses_urefs = true;
                        if matches!(operation, URefOpType::AccessRightsCheck) {
                            analysis.has_uref_access_checks = true;
                        }
                    }
                    Statement::PurseOperation { operation } => {
                        if matches!(operation, PurseOpType::StoreInDictionary) {
                            analysis.stores_purse_in_dictionary = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Check dictionary key lengths
        for storage_item in &contract.storage_items {
            if let Some(key_len) = storage_item.key_length {
                if key_len > 128 {
                    analysis.dictionary_key_issues.push(format!(
                        "Key '{}' exceeds 128 byte limit ({} bytes)",
                        storage_item.name, key_len
                    ));
                }
            }
        }

        // Check for init protection
        if let Some(init_name) = &contract.metadata.init_function_name {
            let init_func = contract.functions.iter().find(|f| &f.name == init_name);
            if let Some(func) = init_func {
                // Check if init has protection against re-initialization
                let has_init_check = func.body.iter().any(|s| {
                    matches!(s, Statement::StorageAccess { key, is_write: false, .. }
                        if key.to_lowercase().contains("init"))
                });
                analysis.has_init_protection = has_init_check || func.patterns.has_init_check;
            }
        }

        analysis
    }

    /// V6.0: Odra-specific analysis
    fn analyze_odra(&self, contract: &ParsedContract) -> Option<OdraAnalysis> {
        if !contract.metadata.is_odra_contract {
            return None;
        }

        let module = contract.odra_modules.first()?;

        Some(OdraAnalysis {
            module_name: module.name.clone(),
            has_init: module.has_init,
            storage_fields: module.storage_fields.iter().map(|f| f.name.clone()).collect(),
            uses_var: module.storage_fields.iter().any(|f| !f.is_mapping && !f.is_list),
            uses_mapping: module.storage_fields.iter().any(|f| f.is_mapping),
            uses_list: module.storage_fields.iter().any(|f| f.is_list),
        })
    }
}

impl Default for CasperAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
