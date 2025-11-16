//! Casper Contract Analyzer
//!
//! Analyzes parsed contracts to extract security-relevant information

use anyhow::Result;
use casper_parser::{ParsedContract, Function, EntryPoint};
use serde::{Deserialize, Serialize};

/// Analysis result for a contract
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
}

/// Control flow analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowAnalysis {
    /// Functions with loops
    pub functions_with_loops: Vec<String>,
    /// Functions with complex branching
    pub complex_branches: Vec<String>,
    /// Functions with external calls
    pub external_calls: Vec<ExternalCall>,
    /// Recursive functions
    pub recursive_functions: Vec<String>,
}

/// External call information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalCall {
    pub caller: String,
    pub callee: String,
    pub is_checked: bool,
}

/// Data flow analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowAnalysis {
    /// Storage operations
    pub storage_ops: Vec<StorageOperation>,
    /// Tainted variables (from external input)
    pub tainted_vars: Vec<String>,
    /// Arithmetic operations
    pub arithmetic_ops: Vec<ArithmeticOp>,
}

/// Storage operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageOperation {
    pub function: String,
    pub key: String,
    pub operation: StorageOpType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageOpType {
    Read,
    Write,
}

/// Arithmetic operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArithmeticOp {
    pub function: String,
    pub operation: String,
    pub is_checked: bool,
}

/// Entry point specific analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPointAnalysis {
    pub name: String,
    pub has_access_control: bool,
    pub has_reentrancy_guard: bool,
    pub complexity_score: u32,
}

/// Call graph representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    pub edges: Vec<CallEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub from: String,
    pub to: String,
}

/// Casper Contract Analyzer
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

        Ok(AnalysisResult {
            contract_path: contract.path.clone(),
            control_flow,
            data_flow,
            entry_points,
            call_graph,
        })
    }

    fn analyze_control_flow(&self, contract: &ParsedContract) -> ControlFlowAnalysis {
        let mut functions_with_loops = Vec::new();
        let mut complex_branches = Vec::new();
        let mut external_calls = Vec::new();
        let recursive_functions = Vec::new();

        // Analyze each function
        for func in &contract.functions {
            let mut has_loop = false;
            let mut has_branch = false;
            let mut func_external_calls = Vec::new();

            for stmt in &func.body {
                match stmt {
                    casper_parser::Statement::Loop => {
                        has_loop = true;
                    }
                    casper_parser::Statement::Conditional => {
                        has_branch = true;
                    }
                    casper_parser::Statement::ExternalCall { target, method } => {
                        func_external_calls.push(ExternalCall {
                            caller: func.name.clone(),
                            callee: format!("{}::{}", target, method),
                            is_checked: false, // Assume unchecked by default
                        });
                    }
                    _ => {}
                }
            }

            if has_loop {
                functions_with_loops.push(func.name.clone());
            }
            if has_branch {
                complex_branches.push(func.name.clone());
            }

            external_calls.extend(func_external_calls);
        }

        ControlFlowAnalysis {
            functions_with_loops,
            complex_branches,
            external_calls,
            recursive_functions,
        }
    }

    fn analyze_data_flow(&self, contract: &ParsedContract) -> DataFlowAnalysis {
        let mut storage_ops = Vec::new();
        let mut arithmetic_ops = Vec::new();

        // Analyze storage operations and arithmetic in functions
        for func in &contract.functions {
            for stmt in &func.body {
                match stmt {
                    casper_parser::Statement::StorageAccess { key, is_write } => {
                        storage_ops.push(StorageOperation {
                            function: func.name.clone(),
                            key: key.clone(),
                            operation: if *is_write {
                                StorageOpType::Write
                            } else {
                                StorageOpType::Read
                            },
                        });
                    }
                    casper_parser::Statement::ArithmeticOp { operation } => {
                        arithmetic_ops.push(ArithmeticOp {
                            function: func.name.clone(),
                            operation: operation.clone(),
                            is_checked: false, // Assume unchecked by default
                        });
                    }
                    _ => {}
                }
            }
        }

        DataFlowAnalysis {
            storage_ops,
            tainted_vars: Vec::new(),
            arithmetic_ops,
        }
    }

    fn analyze_entry_points(&self, contract: &ParsedContract) -> Vec<EntryPointAnalysis> {
        contract.entry_points.iter().map(|ep| {
            self.analyze_single_entry_point(ep, contract)
        }).collect()
    }

    fn analyze_single_entry_point(&self, ep: &EntryPoint, contract: &ParsedContract) -> EntryPointAnalysis {
        // Find the function for this entry point
        let func = contract.functions.iter()
            .find(|f| f.name == ep.function);

        let has_access_control = func
            .map(|f| self.has_access_control_check(f))
            .unwrap_or(false);

        let has_reentrancy_guard = func
            .map(|f| self.has_reentrancy_guard(f))
            .unwrap_or(false);

        let complexity_score = func
            .map(|f| self.calculate_complexity(f))
            .unwrap_or(0);

        EntryPointAnalysis {
            name: ep.name.clone(),
            has_access_control,
            has_reentrancy_guard,
            complexity_score,
        }
    }

    fn has_access_control_check(&self, _func: &Function) -> bool {
        // Check if function has access control (e.g., checks caller)
        // Simplified - would need to analyze function body
        false
    }

    fn has_reentrancy_guard(&self, _func: &Function) -> bool {
        // Check for reentrancy guard pattern
        false
    }

    fn calculate_complexity(&self, func: &Function) -> u32 {
        // Calculate cyclomatic complexity
        func.body.len() as u32
    }

    fn build_call_graph(&self, _contract: &ParsedContract) -> CallGraph {
        CallGraph {
            edges: Vec::new(),
        }
    }
}

impl Default for CasperAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
