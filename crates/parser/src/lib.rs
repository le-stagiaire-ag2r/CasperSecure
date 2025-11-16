//! Casper Smart Contract Parser
//!
//! Parses Rust source code of Casper smart contracts into an AST
//! that can be analyzed for security vulnerabilities.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use syn::{File, Item, ItemFn, ItemMod, Expr, Stmt, ExprBinary, BinOp};

/// Represents a parsed Casper smart contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedContract {
    /// Contract file path
    pub path: String,
    /// Entry points found in the contract
    pub entry_points: Vec<EntryPoint>,
    /// Storage items (named keys, dictionaries, etc.)
    pub storage_items: Vec<StorageItem>,
    /// All functions in the contract
    pub functions: Vec<Function>,
    /// Modules in the contract
    pub modules: Vec<Module>,
}

/// An entry point in a Casper contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPoint {
    /// Entry point name
    pub name: String,
    /// Function implementing the entry point
    pub function: String,
    /// Parameters
    pub parameters: Vec<Parameter>,
    /// Whether it's a public entry point
    pub is_public: bool,
}

/// A storage item (named key, dictionary, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageItem {
    /// Storage key name
    pub name: String,
    /// Type of storage
    pub storage_type: StorageType,
}

/// Type of storage in Casper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    NamedKey,
    Dictionary,
    URef,
}

/// A function in the contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    /// Function name
    pub name: String,
    /// Parameters
    pub parameters: Vec<Parameter>,
    /// Return type
    pub return_type: Option<String>,
    /// Whether function is public
    pub is_public: bool,
    /// Function body (simplified representation)
    pub body: Vec<Statement>,
}

/// Function parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub param_type: String,
}

/// Simplified statement representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Statement {
    ExternalCall { target: String, method: String },
    StorageAccess { key: String, is_write: bool },
    ArithmeticOp { operation: String },
    Conditional,
    Loop,
    Other,
}

/// A module in the contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub name: String,
    pub functions: Vec<String>,
}

/// Casper Contract Parser
pub struct CasperParser;

impl CasperParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse a Casper contract from a file
    pub fn parse_file<P: AsRef<Path>>(&self, path: P) -> Result<ParsedContract> {
        let content = fs::read_to_string(&path)
            .context("Failed to read contract file")?;

        self.parse_source(&content, path.as_ref().to_string_lossy().to_string())
    }

    /// Parse Casper contract from source code
    pub fn parse_source(&self, source: &str, path: String) -> Result<ParsedContract> {
        let syntax_tree: File = syn::parse_str(source)
            .context("Failed to parse Rust source code")?;

        let mut contract = ParsedContract {
            path,
            entry_points: Vec::new(),
            storage_items: Vec::new(),
            functions: Vec::new(),
            modules: Vec::new(),
        };

        for item in syntax_tree.items {
            match item {
                Item::Fn(func) => {
                    let function = self.parse_function(&func);

                    // Check if it's an entry point
                    if Self::is_entry_point(&func) {
                        contract.entry_points.push(EntryPoint {
                            name: function.name.clone(),
                            function: function.name.clone(),
                            parameters: function.parameters.clone(),
                            is_public: function.is_public,
                        });
                    }

                    contract.functions.push(function);
                }
                Item::Mod(module) => {
                    contract.modules.push(self.parse_module(&module));
                }
                _ => {}
            }
        }

        Ok(contract)
    }

    fn parse_function(&self, func: &ItemFn) -> Function {
        let name = func.sig.ident.to_string();

        let parameters: Vec<Parameter> = func.sig.inputs.iter()
            .filter_map(|arg| {
                if let syn::FnArg::Typed(pat_type) = arg {
                    Some(Parameter {
                        name: quote::quote!(#pat_type.pat).to_string(),
                        param_type: quote::quote!(#pat_type.ty).to_string(),
                    })
                } else {
                    None
                }
            })
            .collect();

        let is_public = matches!(func.vis, syn::Visibility::Public(_));

        // Parse function body for statements
        let body = self.parse_block(&func.block);

        Function {
            name,
            parameters,
            return_type: None,
            is_public,
            body,
        }
    }

    fn parse_block(&self, block: &syn::Block) -> Vec<Statement> {
        let mut statements = Vec::new();

        for stmt in &block.stmts {
            statements.extend(self.parse_stmt(stmt));
        }

        statements
    }

    fn parse_stmt(&self, stmt: &Stmt) -> Vec<Statement> {
        match stmt {
            Stmt::Expr(expr, _) => self.parse_expr(expr),
            Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    self.parse_expr(&init.expr)
                } else {
                    vec![]
                }
            }
            _ => vec![],
        }
    }

    fn parse_expr(&self, expr: &Expr) -> Vec<Statement> {
        let mut statements = Vec::new();

        match expr {
            // Detect external calls: runtime::call_contract(...), runtime::transfer_to_account(...)
            Expr::Call(call) => {
                let call_str = quote::quote!(#call).to_string();

                // Check if it's a runtime call (external call)
                if call_str.contains("runtime :: call_contract")
                    || call_str.contains("call_contract") {
                    statements.push(Statement::ExternalCall {
                        target: "external_contract".to_string(),
                        method: "call_contract".to_string(),
                    });
                } else if call_str.contains("transfer_to_account")
                    || call_str.contains("transfer") {
                    statements.push(Statement::ExternalCall {
                        target: "account".to_string(),
                        method: "transfer".to_string(),
                    });
                }

                // Also check for storage access
                if call_str.contains("get_key") || call_str.contains("get_balance")
                    || call_str.contains("read") {
                    statements.push(Statement::StorageAccess {
                        key: "storage_read".to_string(),
                        is_write: false,
                    });
                } else if call_str.contains("set_key") || call_str.contains("set_balance")
                    || call_str.contains("write") || call_str.contains("put_key") {
                    statements.push(Statement::StorageAccess {
                        key: "storage_write".to_string(),
                        is_write: true,
                    });
                }

                // Recursively analyze call arguments
                if let Expr::Call(c) = expr {
                    for arg in &c.args {
                        statements.extend(self.parse_expr(arg));
                    }
                }
            }

            // Detect arithmetic operations
            Expr::Binary(ExprBinary { left, op, right, .. }) => {
                let op_str = match op {
                    BinOp::Add(_) => "add",
                    BinOp::Sub(_) => "sub",
                    BinOp::Mul(_) => "mul",
                    BinOp::Div(_) => "div",
                    _ => "",
                };

                if !op_str.is_empty() {
                    statements.push(Statement::ArithmeticOp {
                        operation: op_str.to_string(),
                    });
                }

                // Recursively analyze operands
                statements.extend(self.parse_expr(left));
                statements.extend(self.parse_expr(right));
            }

            // Detect loops
            Expr::ForLoop(_) | Expr::While(_) | Expr::Loop(_) => {
                statements.push(Statement::Loop);
            }

            // Detect conditionals
            Expr::If(_) | Expr::Match(_) => {
                statements.push(Statement::Conditional);
            }

            // Detect blocks and recursively analyze
            Expr::Block(block) => {
                statements.extend(self.parse_block(&block.block));
            }

            // Other expressions - try to find nested expressions
            _ => {
                statements.push(Statement::Other);
            }
        }

        statements
    }

    fn parse_module(&self, _module: &ItemMod) -> Module {
        Module {
            name: _module.ident.to_string(),
            functions: Vec::new(),
        }
    }

    fn is_entry_point(func: &ItemFn) -> bool {
        // Check for #[no_mangle] attribute (common for Casper entry points)
        func.attrs.iter().any(|attr| {
            attr.path().is_ident("no_mangle")
        })
    }
}

impl Default for CasperParser {
    fn default() -> Self {
        Self::new()
    }
}
