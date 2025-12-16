//! Casper Smart Contract Parser V6.0
//!
//! Parses Rust source code of Casper smart contracts into an AST
//! that can be analyzed for security vulnerabilities.
//!
//! V6.0 Enhancements:
//! - Detection of checked/saturating arithmetic
//! - Odra 2.4.0 framework support
//! - Access control pattern recognition
//! - URef and storage pattern detection
//! - Improved call tracking

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use syn::{File, Item, ItemFn, ItemMod, ItemImpl, ItemStruct, Expr, Stmt, ExprBinary, BinOp, Attribute};

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
    /// V6.0: Odra module detection
    pub odra_modules: Vec<OdraModule>,
    /// V6.0: Contract metadata
    pub metadata: ContractMetadata,
}

/// V6.0: Contract metadata for better analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContractMetadata {
    /// Is this an Odra contract
    pub is_odra_contract: bool,
    /// Uses CEP-18 token standard
    pub uses_cep18: bool,
    /// Uses CEP-78 NFT standard
    pub uses_cep78: bool,
    /// Has init/constructor function
    pub has_init_function: bool,
    /// Init function name if found
    pub init_function_name: Option<String>,
    /// Detected framework version
    pub framework_version: Option<String>,
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
    /// V6.0: Entry point type
    pub entry_point_type: EntryPointType,
}

/// V6.0: Type of entry point
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EntryPointType {
    /// Standard Casper #[no_mangle]
    CasperNoMangle,
    /// Odra #[odra::entry_point]
    OdraEntryPoint,
    /// Odra init
    OdraInit,
    /// CEP-18 standard method
    Cep18Method,
    /// CEP-78 standard method
    Cep78Method,
    /// Unknown/Other
    Other,
}

/// A storage item (named key, dictionary, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageItem {
    /// Storage key name
    pub name: String,
    /// Type of storage
    pub storage_type: StorageType,
    /// V6.0: Key length (for dictionary key validation)
    pub key_length: Option<usize>,
    /// V6.0: Value type stored
    pub value_type: Option<String>,
}

/// Type of storage in Casper
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StorageType {
    NamedKey,
    Dictionary,
    URef,
    /// V6.0: Odra Var<T>
    OdraVar,
    /// V6.0: Odra Mapping<K, V>
    OdraMapping,
    /// V6.0: Odra List<T>
    OdraList,
    /// V6.0: Casper Purse
    Purse,
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
    /// V6.0: Function attributes
    pub attributes: Vec<FunctionAttribute>,
    /// V6.0: Detected patterns
    pub patterns: FunctionPatterns,
}

/// V6.0: Function attributes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FunctionAttribute {
    NoMangle,
    OdraEntryPoint,
    OdraInit,
    OdraExternalContract,
    Inline,
    Test,
    Other(String),
}

/// V6.0: Security-relevant patterns detected in function
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionPatterns {
    /// Has access control check (caller verification)
    pub has_access_control: bool,
    /// Has reentrancy guard
    pub has_reentrancy_guard: bool,
    /// Has initialization check
    pub has_init_check: bool,
    /// Uses checked arithmetic
    pub uses_checked_arithmetic: bool,
    /// Uses Result/Option properly
    pub uses_safe_unwrap: bool,
    /// Modifies owner/admin
    pub modifies_ownership: bool,
    /// Is a view/read-only function
    pub is_view_function: bool,
    /// Handles URef access rights
    pub handles_uref_access: bool,
}

/// Function parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub param_type: String,
    /// V6.0: Is this parameter from user input (tainted)
    pub is_user_input: bool,
}

/// Simplified statement representation - V6.0 Enhanced
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Statement {
    ExternalCall {
        target: String,
        method: String,
        /// V6.0: Is return value checked
        is_checked: bool,
    },
    StorageAccess {
        key: String,
        is_write: bool,
        /// V6.0: Storage type being accessed
        storage_type: Option<StorageType>,
    },
    ArithmeticOp {
        operation: String,
        /// V6.0: Is this checked arithmetic (checked_add, saturating_sub, etc.)
        is_checked: bool,
        /// V6.0: The method used (checked_add, saturating_mul, wrapping_sub, etc.)
        method: Option<String>,
    },
    Conditional,
    Loop {
        /// V6.0: Is loop bounded
        is_bounded: bool,
    },
    /// V6.0: Access control check
    AccessControlCheck {
        check_type: AccessControlType,
    },
    /// V6.0: URef operation
    URefOperation {
        operation: URefOpType,
        access_rights: Option<String>,
    },
    /// V6.0: Purse operation
    PurseOperation {
        operation: PurseOpType,
    },
    /// V6.0: Error handling (Result/Option)
    ErrorHandling {
        handling_type: ErrorHandlingType,
    },
    /// V6.0: Event emission
    EventEmission {
        event_name: String,
    },
    /// V6.0: Assertion/require
    Assertion,
    Other,
}

/// V6.0: Access control check types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccessControlType {
    CallerCheck,      // get_caller() == owner
    OwnerCheck,       // require_owner(), only_owner
    AdminCheck,       // is_admin(), require_admin
    RoleCheck,        // has_role(), require_role
    SignatureCheck,   // verify_signature
    MultiSigCheck,    // requires multiple signatures
    URefAccessCheck,  // checking URef access rights
    Other,
}

/// V6.0: URef operation types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum URefOpType {
    Create,           // new_uref()
    Read,             // storage::read()
    Write,            // storage::write()
    Add,              // storage::add()
    PassToContract,   // passing URef to another contract
    StoreInDictionary, // storing URef in dictionary (dangerous!)
    AccessRightsCheck, // checking access rights
}

/// V6.0: Purse operation types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PurseOpType {
    Create,           // system::create_purse()
    Transfer,         // system::transfer_from_purse_to_purse()
    GetBalance,       // system::get_purse_balance()
    TransferToAccount, // transfer_to_account()
    StoreInDictionary, // storing purse in dictionary (ERROR!)
}

/// V6.0: Error handling types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ErrorHandlingType {
    Unwrap,           // .unwrap() - dangerous
    UnwrapOr,         // .unwrap_or() - safe
    UnwrapOrDefault,  // .unwrap_or_default() - safe
    UnwrapOrElse,     // .unwrap_or_else() - safe
    Expect,           // .expect() - dangerous but documented
    QuestionMark,     // ? operator - safe propagation
    Match,            // match Result/Option - safe
    IfLet,            // if let Some/Ok - safe
    OkOr,             // .ok_or() - safe
    MapErr,           // .map_err() - safe
}

/// V6.0: Odra module representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OdraModule {
    pub name: String,
    pub storage_fields: Vec<OdraStorageField>,
    pub entry_points: Vec<String>,
    pub has_init: bool,
}

/// V6.0: Odra storage field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OdraStorageField {
    pub name: String,
    pub field_type: String,
    pub is_mapping: bool,
    pub is_list: bool,
}

/// A module in the contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub name: String,
    pub functions: Vec<String>,
}

/// Casper Contract Parser - V6.0
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
            odra_modules: Vec::new(),
            metadata: ContractMetadata::default(),
        };

        // First pass: detect contract type and metadata
        self.detect_contract_metadata(&syntax_tree, &mut contract);

        // Second pass: parse all items
        for item in &syntax_tree.items {
            match item {
                Item::Fn(func) => {
                    let function = self.parse_function(func, &contract.metadata);

                    // Check if it's an entry point
                    if self.is_entry_point(func, &contract.metadata) {
                        let ep_type = self.determine_entry_point_type(func, &contract.metadata);
                        contract.entry_points.push(EntryPoint {
                            name: function.name.clone(),
                            function: function.name.clone(),
                            parameters: function.parameters.clone(),
                            is_public: function.is_public,
                            entry_point_type: ep_type,
                        });

                        // Track init function
                        if self.is_init_function(&function.name, func) {
                            contract.metadata.has_init_function = true;
                            contract.metadata.init_function_name = Some(function.name.clone());
                        }
                    }

                    contract.functions.push(function);
                }
                Item::Mod(module) => {
                    contract.modules.push(self.parse_module(module));
                }
                Item::Impl(impl_block) => {
                    // Parse impl blocks for Odra modules
                    self.parse_impl_block(impl_block, &mut contract);
                }
                Item::Struct(struct_item) => {
                    // Check for Odra module structs
                    self.parse_struct_for_odra(struct_item, &mut contract);
                }
                _ => {}
            }
        }

        // Extract storage items from source patterns
        self.extract_storage_items(source, &mut contract);

        Ok(contract)
    }

    /// V6.0: Detect contract metadata and framework
    fn detect_contract_metadata(&self, syntax_tree: &File, contract: &mut ParsedContract) {
        let source = quote::quote!(#syntax_tree).to_string();

        // Detect Odra
        if source.contains("odra::") || source.contains("#[odra::module]") {
            contract.metadata.is_odra_contract = true;
        }

        // Detect CEP-18
        if source.contains("cep18") || source.contains("CEP18")
            || source.contains("transfer") && source.contains("approve") && source.contains("allowance") {
            contract.metadata.uses_cep18 = true;
        }

        // Detect CEP-78
        if source.contains("cep78") || source.contains("CEP78")
            || source.contains("mint") && source.contains("metadata") && source.contains("token_id") {
            contract.metadata.uses_cep78 = true;
        }
    }

    fn parse_function(&self, func: &ItemFn, metadata: &ContractMetadata) -> Function {
        let name = func.sig.ident.to_string();

        let parameters: Vec<Parameter> = func.sig.inputs.iter()
            .filter_map(|arg| {
                if let syn::FnArg::Typed(pat_type) = arg {
                    let param_name = quote::quote!(#pat_type.pat).to_string();
                    let param_type = quote::quote!(#pat_type.ty).to_string();

                    // V6.0: Detect if parameter is from user input
                    let is_user_input = self.is_user_input_param(&param_name, &param_type);

                    Some(Parameter {
                        name: param_name,
                        param_type,
                        is_user_input,
                    })
                } else {
                    None
                }
            })
            .collect();

        let is_public = matches!(func.vis, syn::Visibility::Public(_));

        // Parse function attributes
        let attributes = self.parse_function_attributes(&func.attrs);

        // Parse function body for statements
        let body = self.parse_block(&func.block, metadata);

        // V6.0: Detect function patterns
        let patterns = self.detect_function_patterns(&body, &name, &attributes);

        // Parse return type
        let return_type = match &func.sig.output {
            syn::ReturnType::Default => None,
            syn::ReturnType::Type(_, ty) => Some(quote::quote!(#ty).to_string()),
        };

        Function {
            name,
            parameters,
            return_type,
            is_public,
            body,
            attributes,
            patterns,
        }
    }

    /// V6.0: Parse function attributes
    fn parse_function_attributes(&self, attrs: &[Attribute]) -> Vec<FunctionAttribute> {
        attrs.iter().filter_map(|attr| {
            let path = attr.path();
            if path.is_ident("no_mangle") {
                Some(FunctionAttribute::NoMangle)
            } else if path.is_ident("inline") {
                Some(FunctionAttribute::Inline)
            } else if path.is_ident("test") {
                Some(FunctionAttribute::Test)
            } else {
                let path_str = quote::quote!(#path).to_string();
                if path_str.contains("odra") {
                    if path_str.contains("entry_point") || path_str.contains("entrypoint") {
                        Some(FunctionAttribute::OdraEntryPoint)
                    } else if path_str.contains("init") {
                        Some(FunctionAttribute::OdraInit)
                    } else if path_str.contains("external") {
                        Some(FunctionAttribute::OdraExternalContract)
                    } else {
                        Some(FunctionAttribute::Other(path_str))
                    }
                } else {
                    None
                }
            }
        }).collect()
    }

    /// V6.0: Detect security-relevant patterns in function
    fn detect_function_patterns(&self, body: &[Statement], func_name: &str, attrs: &[FunctionAttribute]) -> FunctionPatterns {
        let mut patterns = FunctionPatterns::default();

        // Check function name for patterns
        let name_lower = func_name.to_lowercase();
        if name_lower.contains("view") || name_lower.contains("get_") || name_lower.contains("query") {
            patterns.is_view_function = true;
        }
        if name_lower.contains("owner") || name_lower.contains("admin") || name_lower.contains("set_owner") {
            patterns.modifies_ownership = true;
        }

        // Analyze body statements
        for stmt in body {
            match stmt {
                Statement::AccessControlCheck { .. } => {
                    patterns.has_access_control = true;
                }
                Statement::ArithmeticOp { is_checked, .. } if *is_checked => {
                    patterns.uses_checked_arithmetic = true;
                }
                Statement::ErrorHandling { handling_type } => {
                    match handling_type {
                        ErrorHandlingType::UnwrapOr |
                        ErrorHandlingType::UnwrapOrDefault |
                        ErrorHandlingType::UnwrapOrElse |
                        ErrorHandlingType::QuestionMark |
                        ErrorHandlingType::Match |
                        ErrorHandlingType::IfLet |
                        ErrorHandlingType::OkOr |
                        ErrorHandlingType::MapErr => {
                            patterns.uses_safe_unwrap = true;
                        }
                        _ => {}
                    }
                }
                Statement::URefOperation { operation, .. } => {
                    if matches!(operation, URefOpType::AccessRightsCheck) {
                        patterns.handles_uref_access = true;
                    }
                }
                _ => {}
            }
        }

        // Check if it's an init function
        if attrs.contains(&FunctionAttribute::OdraInit) || name_lower == "init" || name_lower == "constructor" {
            patterns.has_init_check = true;
        }

        patterns
    }

    fn parse_block(&self, block: &syn::Block, metadata: &ContractMetadata) -> Vec<Statement> {
        let mut statements = Vec::new();

        for stmt in &block.stmts {
            statements.extend(self.parse_stmt(stmt, metadata));
        }

        statements
    }

    fn parse_stmt(&self, stmt: &Stmt, metadata: &ContractMetadata) -> Vec<Statement> {
        match stmt {
            Stmt::Expr(expr, _) => self.parse_expr(expr, metadata),
            Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    self.parse_expr(&init.expr, metadata)
                } else {
                    vec![]
                }
            }
            _ => vec![],
        }
    }

    fn parse_expr(&self, expr: &Expr, metadata: &ContractMetadata) -> Vec<Statement> {
        let mut statements = Vec::new();
        let expr_str = quote::quote!(#expr).to_string();

        match expr {
            // Detect method calls (V6.0 enhanced)
            Expr::MethodCall(method_call) => {
                let method_name = method_call.method.to_string();

                // V6.0: Detect checked/saturating arithmetic
                if self.is_checked_arithmetic(&method_name) {
                    let op = self.extract_arithmetic_op(&method_name);
                    statements.push(Statement::ArithmeticOp {
                        operation: op,
                        is_checked: true,
                        method: Some(method_name.clone()),
                    });
                }
                // V6.0: Detect error handling patterns
                else if let Some(handling_type) = self.detect_error_handling(&method_name) {
                    statements.push(Statement::ErrorHandling { handling_type });
                }
                // Detect external calls
                else if self.is_external_call_method(&method_name) {
                    statements.push(Statement::ExternalCall {
                        target: "external".to_string(),
                        method: method_name.clone(),
                        is_checked: expr_str.contains("?") || expr_str.contains("unwrap_or"),
                    });
                }

                // Recursively analyze receiver and arguments
                statements.extend(self.parse_expr(&method_call.receiver, metadata));
                for arg in &method_call.args {
                    statements.extend(self.parse_expr(arg, metadata));
                }
            }

            // Detect function calls
            Expr::Call(call) => {
                let call_str = quote::quote!(#call).to_string();

                // V6.0: Detect access control patterns
                if let Some(access_type) = self.detect_access_control(&call_str) {
                    statements.push(Statement::AccessControlCheck { check_type: access_type });
                }

                // V6.0: Detect URef operations
                if let Some(uref_stmt) = self.detect_uref_operation(&call_str) {
                    statements.push(uref_stmt);
                }

                // V6.0: Detect Purse operations
                if let Some(purse_stmt) = self.detect_purse_operation(&call_str) {
                    statements.push(purse_stmt);
                }

                // V6.0: Detect event emissions
                if call_str.contains("emit") || call_str.contains("event") || call_str.contains("Event") {
                    statements.push(Statement::EventEmission {
                        event_name: "event".to_string(),
                    });
                }

                // V6.0: Detect assertions
                if call_str.contains("assert") || call_str.contains("require") || call_str.contains("revert") {
                    statements.push(Statement::Assertion);
                }

                // Check if it's a runtime call (external call)
                if call_str.contains("runtime :: call_contract")
                    || call_str.contains("call_contract") {
                    statements.push(Statement::ExternalCall {
                        target: "external_contract".to_string(),
                        method: "call_contract".to_string(),
                        is_checked: call_str.contains("?") || call_str.contains("unwrap_or"),
                    });
                } else if call_str.contains("transfer_to_account")
                    || call_str.contains("transfer") {
                    statements.push(Statement::ExternalCall {
                        target: "account".to_string(),
                        method: "transfer".to_string(),
                        is_checked: call_str.contains("?"),
                    });
                }

                // V6.0: Enhanced storage access detection
                if let Some(storage_stmt) = self.detect_storage_access(&call_str, metadata) {
                    statements.push(storage_stmt);
                }

                // Recursively analyze call arguments
                for arg in &call.args {
                    statements.extend(self.parse_expr(arg, metadata));
                }
            }

            // Detect arithmetic operations (binary)
            Expr::Binary(ExprBinary { left, op, right, .. }) => {
                let op_str = match op {
                    BinOp::Add(_) => "add",
                    BinOp::Sub(_) => "sub",
                    BinOp::Mul(_) => "mul",
                    BinOp::Div(_) => "div",
                    BinOp::Rem(_) => "rem",
                    _ => "",
                };

                if !op_str.is_empty() {
                    // V6.0: Raw binary operations are unchecked
                    statements.push(Statement::ArithmeticOp {
                        operation: op_str.to_string(),
                        is_checked: false,
                        method: None,
                    });
                }

                // Recursively analyze operands
                statements.extend(self.parse_expr(left, metadata));
                statements.extend(self.parse_expr(right, metadata));
            }

            // Detect loops
            Expr::ForLoop(for_loop) => {
                // V6.0: Try to detect if loop is bounded
                let is_bounded = self.is_bounded_loop(&for_loop.expr);
                statements.push(Statement::Loop { is_bounded });
                statements.extend(self.parse_block(&for_loop.body, metadata));
            }
            Expr::While(while_loop) => {
                statements.push(Statement::Loop { is_bounded: false });
                statements.extend(self.parse_block(&while_loop.body, metadata));
            }
            Expr::Loop(loop_expr) => {
                statements.push(Statement::Loop { is_bounded: false });
                statements.extend(self.parse_block(&loop_expr.body, metadata));
            }

            // Detect conditionals
            Expr::If(if_expr) => {
                statements.push(Statement::Conditional);
                // Check condition for access control
                let cond_str = quote::quote!(#if_expr.cond).to_string();
                if let Some(access_type) = self.detect_access_control(&cond_str) {
                    statements.push(Statement::AccessControlCheck { check_type: access_type });
                }
                statements.extend(self.parse_block(&if_expr.then_branch, metadata));
                if let Some((_, else_branch)) = &if_expr.else_branch {
                    statements.extend(self.parse_expr(else_branch, metadata));
                }
            }
            Expr::Match(match_expr) => {
                statements.push(Statement::Conditional);
                // V6.0: Match on Result/Option is safe error handling
                let matched = quote::quote!(#match_expr.expr).to_string();
                if matched.contains("Result") || matched.contains("Option") {
                    statements.push(Statement::ErrorHandling {
                        handling_type: ErrorHandlingType::Match
                    });
                }
            }

            // V6.0: Detect ? operator (try expression)
            Expr::Try(try_expr) => {
                statements.push(Statement::ErrorHandling {
                    handling_type: ErrorHandlingType::QuestionMark,
                });
                statements.extend(self.parse_expr(&try_expr.expr, metadata));
            }

            // Detect blocks and recursively analyze
            Expr::Block(block) => {
                statements.extend(self.parse_block(&block.block, metadata));
            }

            // Other expressions
            _ => {
                // Still check the expression string for patterns
                if expr_str.contains("unwrap_or_default") {
                    statements.push(Statement::ErrorHandling {
                        handling_type: ErrorHandlingType::UnwrapOrDefault,
                    });
                } else if expr_str.contains("unwrap_or") {
                    statements.push(Statement::ErrorHandling {
                        handling_type: ErrorHandlingType::UnwrapOr,
                    });
                } else if expr_str.contains(".unwrap()") {
                    statements.push(Statement::ErrorHandling {
                        handling_type: ErrorHandlingType::Unwrap,
                    });
                }
            }
        }

        statements
    }

    /// V6.0: Check if method is checked arithmetic
    fn is_checked_arithmetic(&self, method: &str) -> bool {
        matches!(method,
            "checked_add" | "checked_sub" | "checked_mul" | "checked_div" | "checked_rem" |
            "saturating_add" | "saturating_sub" | "saturating_mul" | "saturating_div" |
            "wrapping_add" | "wrapping_sub" | "wrapping_mul" | "wrapping_div" |
            "overflowing_add" | "overflowing_sub" | "overflowing_mul" | "overflowing_div"
        )
    }

    /// V6.0: Extract arithmetic operation from method name
    fn extract_arithmetic_op(&self, method: &str) -> String {
        if method.contains("add") { "add".to_string() }
        else if method.contains("sub") { "sub".to_string() }
        else if method.contains("mul") { "mul".to_string() }
        else if method.contains("div") { "div".to_string() }
        else if method.contains("rem") { "rem".to_string() }
        else { "unknown".to_string() }
    }

    /// V6.0: Detect error handling method
    fn detect_error_handling(&self, method: &str) -> Option<ErrorHandlingType> {
        match method {
            "unwrap" => Some(ErrorHandlingType::Unwrap),
            "unwrap_or" => Some(ErrorHandlingType::UnwrapOr),
            "unwrap_or_default" => Some(ErrorHandlingType::UnwrapOrDefault),
            "unwrap_or_else" => Some(ErrorHandlingType::UnwrapOrElse),
            "expect" => Some(ErrorHandlingType::Expect),
            "ok_or" | "ok_or_else" => Some(ErrorHandlingType::OkOr),
            "map_err" => Some(ErrorHandlingType::MapErr),
            _ => None,
        }
    }

    /// V6.0: Detect access control patterns
    fn detect_access_control(&self, expr_str: &str) -> Option<AccessControlType> {
        let lower = expr_str.to_lowercase();

        if lower.contains("get_caller") && (lower.contains("==") || lower.contains("!=")) {
            Some(AccessControlType::CallerCheck)
        } else if lower.contains("only_owner") || lower.contains("require_owner") || lower.contains("is_owner") {
            Some(AccessControlType::OwnerCheck)
        } else if lower.contains("is_admin") || lower.contains("require_admin") || lower.contains("only_admin") {
            Some(AccessControlType::AdminCheck)
        } else if lower.contains("has_role") || lower.contains("require_role") || lower.contains("check_role") {
            Some(AccessControlType::RoleCheck)
        } else if lower.contains("verify_signature") || lower.contains("check_signature") {
            Some(AccessControlType::SignatureCheck)
        } else if lower.contains("access_rights") || lower.contains("accessrights") {
            Some(AccessControlType::URefAccessCheck)
        } else {
            None
        }
    }

    /// V6.0: Detect URef operations
    fn detect_uref_operation(&self, call_str: &str) -> Option<Statement> {
        let lower = call_str.to_lowercase();

        if lower.contains("new_uref") || lower.contains("storage::new") {
            Some(Statement::URefOperation {
                operation: URefOpType::Create,
                access_rights: None,
            })
        } else if lower.contains("storage::read") || lower.contains("read_from_key") {
            Some(Statement::URefOperation {
                operation: URefOpType::Read,
                access_rights: None,
            })
        } else if lower.contains("storage::write") || lower.contains("write_to_key") {
            Some(Statement::URefOperation {
                operation: URefOpType::Write,
                access_rights: None,
            })
        } else if lower.contains("storage::add") {
            Some(Statement::URefOperation {
                operation: URefOpType::Add,
                access_rights: None,
            })
        } else if lower.contains("dictionary") && lower.contains("uref") {
            Some(Statement::URefOperation {
                operation: URefOpType::StoreInDictionary,
                access_rights: None,
            })
        } else if lower.contains("access_rights") {
            Some(Statement::URefOperation {
                operation: URefOpType::AccessRightsCheck,
                access_rights: None,
            })
        } else {
            None
        }
    }

    /// V6.0: Detect Purse operations
    fn detect_purse_operation(&self, call_str: &str) -> Option<Statement> {
        let lower = call_str.to_lowercase();

        if lower.contains("create_purse") || lower.contains("new_purse") {
            Some(Statement::PurseOperation {
                operation: PurseOpType::Create,
            })
        } else if lower.contains("transfer_from_purse") {
            Some(Statement::PurseOperation {
                operation: PurseOpType::Transfer,
            })
        } else if lower.contains("get_purse_balance") || lower.contains("purse_balance") {
            Some(Statement::PurseOperation {
                operation: PurseOpType::GetBalance,
            })
        } else if lower.contains("transfer_to_account") {
            Some(Statement::PurseOperation {
                operation: PurseOpType::TransferToAccount,
            })
        } else if (lower.contains("dictionary") || lower.contains("dict")) && lower.contains("purse") {
            Some(Statement::PurseOperation {
                operation: PurseOpType::StoreInDictionary,
            })
        } else {
            None
        }
    }

    /// V6.0: Detect storage access with type
    fn detect_storage_access(&self, call_str: &str, metadata: &ContractMetadata) -> Option<Statement> {
        let lower = call_str.to_lowercase();

        // Odra storage patterns
        if metadata.is_odra_contract {
            if lower.contains(".get(") || lower.contains(".get_or_default") {
                return Some(Statement::StorageAccess {
                    key: "odra_storage".to_string(),
                    is_write: false,
                    storage_type: Some(StorageType::OdraVar),
                });
            } else if lower.contains(".set(") {
                return Some(Statement::StorageAccess {
                    key: "odra_storage".to_string(),
                    is_write: true,
                    storage_type: Some(StorageType::OdraVar),
                });
            }
        }

        // Standard Casper storage
        if lower.contains("get_key") || lower.contains("runtime::get_key") {
            Some(Statement::StorageAccess {
                key: "named_key".to_string(),
                is_write: false,
                storage_type: Some(StorageType::NamedKey),
            })
        } else if lower.contains("put_key") || lower.contains("runtime::put_key") {
            Some(Statement::StorageAccess {
                key: "named_key".to_string(),
                is_write: true,
                storage_type: Some(StorageType::NamedKey),
            })
        } else if lower.contains("dictionary_get") {
            Some(Statement::StorageAccess {
                key: "dictionary".to_string(),
                is_write: false,
                storage_type: Some(StorageType::Dictionary),
            })
        } else if lower.contains("dictionary_put") {
            Some(Statement::StorageAccess {
                key: "dictionary".to_string(),
                is_write: true,
                storage_type: Some(StorageType::Dictionary),
            })
        } else if lower.contains("storage::read") || lower.contains("read") && lower.contains("uref") {
            Some(Statement::StorageAccess {
                key: "uref".to_string(),
                is_write: false,
                storage_type: Some(StorageType::URef),
            })
        } else if lower.contains("storage::write") || lower.contains("write") && lower.contains("uref") {
            Some(Statement::StorageAccess {
                key: "uref".to_string(),
                is_write: true,
                storage_type: Some(StorageType::URef),
            })
        } else {
            None
        }
    }

    /// V6.0: Check if method is an external call
    fn is_external_call_method(&self, method: &str) -> bool {
        matches!(method.to_lowercase().as_str(),
            "call_contract" | "call_versioned_contract" | "transfer" |
            "transfer_to_account" | "delegate" | "call"
        )
    }

    /// V6.0: Check if parameter is from user input
    fn is_user_input_param(&self, name: &str, param_type: &str) -> bool {
        let name_lower = name.to_lowercase();
        let type_lower = param_type.to_lowercase();

        // Common user input parameter patterns
        name_lower.contains("amount") ||
        name_lower.contains("recipient") ||
        name_lower.contains("to") ||
        name_lower.contains("target") ||
        name_lower.contains("data") ||
        name_lower.contains("input") ||
        type_lower.contains("string") ||
        type_lower.contains("bytes") ||
        type_lower.contains("vec")
    }

    /// V6.0: Check if loop is bounded
    fn is_bounded_loop(&self, expr: &Expr) -> bool {
        let expr_str = quote::quote!(#expr).to_string();
        // Check for range patterns like 0..10 or 0..len where len is a constant
        expr_str.contains("..") &&
        (expr_str.chars().filter(|c| c.is_numeric()).count() > 0 ||
         expr_str.contains("len()"))
    }

    fn parse_module(&self, module: &ItemMod) -> Module {
        Module {
            name: module.ident.to_string(),
            functions: Vec::new(),
        }
    }

    /// V6.0: Parse impl block for Odra modules
    fn parse_impl_block(&self, impl_block: &ItemImpl, contract: &mut ParsedContract) {
        // Check if this is an Odra module impl
        let impl_str = quote::quote!(#impl_block).to_string();

        if impl_str.contains("odra") || impl_str.contains("#[odra::module]") {
            // Extract type name
            let type_name = quote::quote!(#impl_block.self_ty).to_string();

            // Check if we already have this module
            if !contract.odra_modules.iter().any(|m| m.name == type_name) {
                let mut odra_module = OdraModule {
                    name: type_name,
                    storage_fields: Vec::new(),
                    entry_points: Vec::new(),
                    has_init: false,
                };

                // Parse methods
                for item in &impl_block.items {
                    if let syn::ImplItem::Fn(method) = item {
                        let method_name = method.sig.ident.to_string();

                        // Check for init
                        if method_name == "init" || method.attrs.iter().any(|a| {
                            quote::quote!(#a).to_string().contains("init")
                        }) {
                            odra_module.has_init = true;
                        }

                        // Check for entry point attributes
                        let is_entry_point = method.attrs.iter().any(|a| {
                            let attr_str = quote::quote!(#a).to_string();
                            attr_str.contains("entry_point") || attr_str.contains("external")
                        });

                        if is_entry_point {
                            odra_module.entry_points.push(method_name);
                        }
                    }
                }

                contract.odra_modules.push(odra_module);
            }
        }
    }

    /// V6.0: Parse struct for Odra storage fields
    fn parse_struct_for_odra(&self, struct_item: &ItemStruct, contract: &mut ParsedContract) {
        let struct_str = quote::quote!(#struct_item).to_string();

        // Check for Odra module attribute
        let is_odra_module = struct_item.attrs.iter().any(|a| {
            quote::quote!(#a).to_string().contains("odra")
        });

        if is_odra_module || struct_str.contains("Var<") || struct_str.contains("Mapping<") {
            contract.metadata.is_odra_contract = true;

            // Find or create Odra module
            let struct_name = struct_item.ident.to_string();

            let module = contract.odra_modules.iter_mut()
                .find(|m| m.name == struct_name);

            let storage_fields: Vec<OdraStorageField> = struct_item.fields.iter()
                .filter_map(|field| {
                    let field_type = quote::quote!(#field.ty).to_string();
                    let field_name = field.ident.as_ref()?.to_string();

                    if field_type.contains("Var<") || field_type.contains("Mapping<") || field_type.contains("List<") {
                        // Add to storage items
                        let storage_type = if field_type.contains("Mapping<") {
                            StorageType::OdraMapping
                        } else if field_type.contains("List<") {
                            StorageType::OdraList
                        } else {
                            StorageType::OdraVar
                        };

                        contract.storage_items.push(StorageItem {
                            name: field_name.clone(),
                            storage_type,
                            key_length: Some(field_name.len()),
                            value_type: Some(field_type.clone()),
                        });

                        Some(OdraStorageField {
                            name: field_name,
                            field_type: field_type.clone(),
                            is_mapping: field_type.contains("Mapping<"),
                            is_list: field_type.contains("List<"),
                        })
                    } else {
                        None
                    }
                })
                .collect();

            if let Some(m) = module {
                m.storage_fields.extend(storage_fields);
            } else {
                contract.odra_modules.push(OdraModule {
                    name: struct_name,
                    storage_fields,
                    entry_points: Vec::new(),
                    has_init: false,
                });
            }
        }
    }

    /// V6.0: Extract storage items from source patterns
    fn extract_storage_items(&self, source: &str, contract: &mut ParsedContract) {
        // Look for storage key declarations
        for line in source.lines() {
            let lower = line.to_lowercase();

            // NamedKey patterns
            if lower.contains("const") && (lower.contains("_key") || lower.contains("key_")) {
                if let Some(key_name) = self.extract_string_literal(line) {
                    if !contract.storage_items.iter().any(|s| s.name == key_name) {
                        contract.storage_items.push(StorageItem {
                            name: key_name.clone(),
                            storage_type: StorageType::NamedKey,
                            key_length: Some(key_name.len()),
                            value_type: None,
                        });
                    }
                }
            }

            // Dictionary patterns
            if lower.contains("dictionary") || lower.contains("new_dictionary") {
                if let Some(dict_name) = self.extract_string_literal(line) {
                    if !contract.storage_items.iter().any(|s| s.name == dict_name) {
                        contract.storage_items.push(StorageItem {
                            name: dict_name.clone(),
                            storage_type: StorageType::Dictionary,
                            key_length: Some(dict_name.len()),
                            value_type: None,
                        });
                    }
                }
            }

            // Purse patterns
            if lower.contains("purse") && (lower.contains("const") || lower.contains("let")) {
                if let Some(purse_name) = self.extract_string_literal(line) {
                    if !contract.storage_items.iter().any(|s| s.name == purse_name) {
                        contract.storage_items.push(StorageItem {
                            name: purse_name,
                            storage_type: StorageType::Purse,
                            key_length: None,
                            value_type: None,
                        });
                    }
                }
            }
        }
    }

    /// Extract string literal from a line
    fn extract_string_literal(&self, line: &str) -> Option<String> {
        let start = line.find('"')?;
        let end = line[start + 1..].find('"')?;
        Some(line[start + 1..start + 1 + end].to_string())
    }

    fn is_entry_point(&self, func: &ItemFn, metadata: &ContractMetadata) -> bool {
        // Check for #[no_mangle] attribute (standard Casper)
        let has_no_mangle = func.attrs.iter().any(|attr| attr.path().is_ident("no_mangle"));

        // Check for Odra entry point attributes
        let has_odra_entry = func.attrs.iter().any(|attr| {
            let attr_str = quote::quote!(#attr).to_string();
            attr_str.contains("odra") && (
                attr_str.contains("entry_point") ||
                attr_str.contains("entrypoint") ||
                attr_str.contains("init")
            )
        });

        // Check for public visibility in Odra contracts
        let is_public_odra = metadata.is_odra_contract &&
            matches!(func.vis, syn::Visibility::Public(_));

        has_no_mangle || has_odra_entry || is_public_odra
    }

    fn determine_entry_point_type(&self, func: &ItemFn, metadata: &ContractMetadata) -> EntryPointType {
        let func_name = func.sig.ident.to_string().to_lowercase();

        // Check for Odra attributes
        for attr in &func.attrs {
            let attr_str = quote::quote!(#attr).to_string();
            if attr_str.contains("odra") {
                if attr_str.contains("init") {
                    return EntryPointType::OdraInit;
                }
                return EntryPointType::OdraEntryPoint;
            }
        }

        // Check for CEP-18 methods
        if metadata.uses_cep18 && matches!(func_name.as_str(),
            "transfer" | "approve" | "transfer_from" | "allowance" |
            "balance_of" | "total_supply" | "mint" | "burn") {
            return EntryPointType::Cep18Method;
        }

        // Check for CEP-78 methods
        if metadata.uses_cep78 && matches!(func_name.as_str(),
            "mint" | "burn" | "transfer" | "approve" | "set_approval_for_all" |
            "owner_of" | "metadata" | "token_metadata") {
            return EntryPointType::Cep78Method;
        }

        // Standard Casper
        if func.attrs.iter().any(|attr| attr.path().is_ident("no_mangle")) {
            return EntryPointType::CasperNoMangle;
        }

        EntryPointType::Other
    }

    fn is_init_function(&self, name: &str, func: &ItemFn) -> bool {
        let lower = name.to_lowercase();

        // Check name
        if lower == "init" || lower == "constructor" || lower == "initialize" || lower == "call" {
            return true;
        }

        // Check attributes
        func.attrs.iter().any(|attr| {
            let attr_str = quote::quote!(#attr).to_string().to_lowercase();
            attr_str.contains("init") || attr_str.contains("constructor")
        })
    }
}

impl Default for CasperParser {
    fn default() -> Self {
        Self::new()
    }
}
