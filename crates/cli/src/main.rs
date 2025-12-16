//! CasperSecure CLI V6.0
//!
//! Command-line interface for analyzing Casper smart contracts
//!
//! V6.0 Enhancements:
//! - 30 vulnerability detectors
//! - Casper-specific security checks
//! - Odra 2.4.0 framework support
//! - Improved detection accuracy

use anyhow::Result;
use casper_analyzer::CasperAnalyzer;
use casper_detector::{DetectionReport, Severity, VulnerabilityDetector, VulnCategory};
use casper_parser::CasperParser;
use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "casper-secure")]
#[command(about = "Security analyzer for Casper smart contracts", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a Casper smart contract for vulnerabilities
    Analyze {
        /// Path to the contract file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Minimum severity to report
        #[arg(short, long, default_value = "low")]
        severity: String,

        /// V6.0: Filter by category
        #[arg(short, long)]
        category: Option<String>,
    },

    /// Submit audit results to on-chain registry
    Submit {
        /// Path to the contract file that was audited
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Contract address/identifier to register
        #[arg(short, long)]
        contract_address: String,

        /// Registry contract hash (optional, uses default if not specified)
        #[arg(short, long)]
        registry: Option<String>,

        /// Network node RPC URL
        #[arg(short, long, default_value = "http://localhost:7777")]
        node_url: String,
    },

    /// List available vulnerability detectors
    Detectors,

    /// Show version information
    Version,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze { file, format, severity, category } => {
            analyze_contract(file, format, severity, category)?;
        }
        Commands::Submit { file, contract_address, registry, node_url } => {
            submit_audit_onchain(file, contract_address, registry, node_url)?;
        }
        Commands::Detectors => {
            list_detectors();
        }
        Commands::Version => {
            print_version();
        }
    }

    Ok(())
}

fn analyze_contract(file: PathBuf, format: String, min_severity: String, category: Option<String>) -> Result<()> {
    println!("{}", "CasperSecure V6.0 - Smart Contract Analyzer".bold().cyan());
    println!("{}", "30 Detectors | Casper-Specific | Odra 2.4.0 Support".bright_black());
    println!();

    // Parse the contract
    println!("{} {}", "Parsing contract:".bold(), file.display());
    let parser = CasperParser::new();
    let contract = parser.parse_file(&file)?;
    println!("  {} {} entry points found", "✓".green(), contract.entry_points.len());
    println!("  {} {} functions found", "✓".green(), contract.functions.len());

    // V6.0: Show contract metadata
    if contract.metadata.is_odra_contract {
        println!("  {} Odra framework detected", "●".cyan());
    }
    if contract.metadata.uses_cep18 {
        println!("  {} CEP-18 token contract detected", "●".cyan());
    }
    if contract.metadata.uses_cep78 {
        println!("  {} CEP-78 NFT contract detected", "●".cyan());
    }
    println!();

    // Analyze the contract
    println!("{}", "Analyzing contract...".bold());
    let analyzer = CasperAnalyzer::new();
    let analysis = analyzer.analyze(&contract)?;
    println!("  {} Control flow analysis complete", "✓".green());
    println!("  {} Data flow analysis complete", "✓".green());
    println!("  {} Storage analysis complete", "✓".green());
    println!("  {} Security patterns detected", "✓".green());

    // V6.0: Show Casper-specific analysis
    if analysis.casper_analysis.uses_urefs {
        if analysis.casper_analysis.has_uref_access_checks {
            println!("  {} URef access rights verified", "✓".green());
        } else {
            println!("  {} URef operations without access checks", "⚠".yellow());
        }
    }
    println!();

    // Detect vulnerabilities
    println!("{}", "Running 30 vulnerability detectors...".bold());
    let detector = VulnerabilityDetector::new();
    let report = detector.detect(&contract, &analysis)?;
    println!("  {} Detection complete", "✓".green());
    println!();

    // Filter by severity
    let min_sev = parse_severity(&min_severity);
    let mut filtered_report = filter_report(report, min_sev);

    // V6.0: Filter by category if specified
    if let Some(cat) = category {
        filtered_report = filter_by_category(filtered_report, &cat);
    }

    // Output results
    match format.as_str() {
        "json" => output_json(&filtered_report)?,
        _ => output_text(&filtered_report),
    }

    Ok(())
}

fn output_text(report: &DetectionReport) {
    println!("{}", "═".repeat(60).cyan());
    println!("{}", "SECURITY ANALYSIS REPORT".bold().cyan());
    println!("{}", "═".repeat(60).cyan());
    println!();

    // V6.0: Contract Info
    println!("{}", "Contract Info:".bold());
    println!("  Entry Points: {}", report.contract_info.entry_point_count);
    println!("  Functions: {}", report.contract_info.function_count);
    if report.contract_info.is_odra {
        println!("  Framework: {}", "Odra".cyan());
    }
    if report.contract_info.uses_cep18 {
        println!("  Standard: {}", "CEP-18 (Fungible Token)".cyan());
    }
    if report.contract_info.uses_cep78 {
        println!("  Standard: {}", "CEP-78 (NFT)".cyan());
    }
    println!();

    // Summary
    println!("{}", "Summary:".bold());
    println!("  Total vulnerabilities: {}", report.summary.total_vulns.to_string().bold());
    println!("  Detectors run: {}", report.summary.detectors_run);

    // Security Score & Grade
    let grade_colored = match report.summary.security_grade.as_str() {
        "A+" | "A" => report.summary.security_grade.as_str().green().bold(),
        "B" => report.summary.security_grade.as_str().yellow().bold(),
        "C" => report.summary.security_grade.as_str().yellow(),
        "D" => report.summary.security_grade.as_str().red(),
        "F" => report.summary.security_grade.as_str().red().bold(),
        _ => report.summary.security_grade.as_str().white(),
    };

    let score_colored = match report.summary.security_score {
        90..=100 => report.summary.security_score.to_string().green().bold(),
        70..=89 => report.summary.security_score.to_string().yellow(),
        _ => report.summary.security_score.to_string().red(),
    };

    println!("  {} {}/100", "Security Score:".bold(), score_colored);
    println!("  {} {}", "Security Grade:".bold(), grade_colored);
    println!();

    // Severity breakdown
    if report.summary.critical > 0 {
        println!("  Critical: {}", report.summary.critical.to_string().red().bold());
    }
    if report.summary.high > 0 {
        println!("  High:     {}", report.summary.high.to_string().bright_red());
    }
    if report.summary.medium > 0 {
        println!("  Medium:   {}", report.summary.medium.to_string().yellow());
    }
    if report.summary.low > 0 {
        println!("  Low:      {}", report.summary.low.to_string().bright_blue());
    }
    if report.summary.info > 0 {
        println!("  Info:     {}", report.summary.info.to_string().white());
    }
    println!();

    // V6.0: Grade explanation
    match report.summary.security_grade.as_str() {
        "A+" | "A" => println!("  {}", "Contract is well-secured.".green()),
        "B" => println!("  {}", "Contract has minor issues to address.".yellow()),
        "C" => println!("  {}", "Contract needs security improvements.".yellow()),
        "D" => println!("  {}", "Contract has significant security issues.".red()),
        "F" => println!("  {}", "CONTRACT IS DANGEROUS - DO NOT DEPLOY!".red().bold()),
        _ => {}
    }
    println!();

    // Vulnerabilities
    if !report.vulnerabilities.is_empty() {
        println!("{}", "Detected Vulnerabilities:".bold());
        println!("{}", "─".repeat(60));

        for (i, vuln) in report.vulnerabilities.iter().enumerate() {
            println!();
            println!("{}. {} [{}] [{}]",
                     (i + 1).to_string().bold(),
                     vuln.vuln_type.bold(),
                     severity_colored(&vuln.severity),
                     vuln.detector_id.bright_black());

            println!("   {} {}", "Category:".bright_black(), category_name(&vuln.category));
            println!("   {} {}", "Function:".bright_black(), vuln.location.function.italic());
            println!("   {}", vuln.description);
            println!("   {} {}", "Fix:".bold().green(), vuln.recommendation);
        }

        println!();
        println!("{}", "─".repeat(60));
    } else {
        println!("{}", "No vulnerabilities detected! ✓".green().bold());
    }

    println!();
    println!("{}", "Analysis complete.".italic());
}

fn category_name(category: &VulnCategory) -> ColoredString {
    match category {
        VulnCategory::Security => "Security".red(),
        VulnCategory::AccessControl => "Access Control".bright_red(),
        VulnCategory::Arithmetic => "Arithmetic".yellow(),
        VulnCategory::Reentrancy => "Reentrancy".red().bold(),
        VulnCategory::Storage => "Storage".cyan(),
        VulnCategory::Gas => "Gas".bright_blue(),
        VulnCategory::CodeQuality => "Code Quality".bright_black(),
        VulnCategory::CasperSpecific => "Casper-Specific".magenta(),
        VulnCategory::OdraSpecific => "Odra".cyan().bold(),
    }
}

fn output_json(report: &DetectionReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    println!("{}", json);
    Ok(())
}

fn severity_colored(severity: &Severity) -> ColoredString {
    match severity {
        Severity::Critical => severity.as_str().red().bold(),
        Severity::High => severity.as_str().bright_red(),
        Severity::Medium => severity.as_str().yellow(),
        Severity::Low => severity.as_str().bright_blue(),
        Severity::Info => severity.as_str().white(),
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn filter_report(mut report: DetectionReport, min_severity: Severity) -> DetectionReport {
    let min_level = match min_severity {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    };

    report.vulnerabilities.retain(|v| {
        let level = match v.severity {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        };
        level >= min_level
    });

    // Recalculate summary
    report.summary.total_vulns = report.vulnerabilities.len();
    report.summary.critical = report.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::Critical)).count();
    report.summary.high = report.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::High)).count();
    report.summary.medium = report.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::Medium)).count();
    report.summary.low = report.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::Low)).count();
    report.summary.info = report.vulnerabilities.iter().filter(|v| matches!(v.severity, Severity::Info)).count();

    report
}

fn filter_by_category(mut report: DetectionReport, category: &str) -> DetectionReport {
    let target_category = match category.to_lowercase().as_str() {
        "security" => Some(VulnCategory::Security),
        "access" | "access_control" | "accesscontrol" => Some(VulnCategory::AccessControl),
        "arithmetic" | "overflow" => Some(VulnCategory::Arithmetic),
        "reentrancy" => Some(VulnCategory::Reentrancy),
        "storage" => Some(VulnCategory::Storage),
        "gas" => Some(VulnCategory::Gas),
        "quality" | "code_quality" | "codequality" => Some(VulnCategory::CodeQuality),
        "casper" | "casper_specific" | "casperspecific" => Some(VulnCategory::CasperSpecific),
        "odra" | "odra_specific" | "odraspecific" => Some(VulnCategory::OdraSpecific),
        _ => None,
    };

    if let Some(cat) = target_category {
        report.vulnerabilities.retain(|v| v.category == cat);
        report.summary.total_vulns = report.vulnerabilities.len();
    }

    report
}

fn list_detectors() {
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_black());
    println!("{}", "  CasperSecure V6.0 - Vulnerability Detectors".bold().cyan());
    println!("{}", "  30 Detectors | Casper-Specific | Odra 2.4.0 Support".bright_black());
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_black());
    println!();

    let detectors = vec![
        // ===== ORIGINAL V0.2.0 (5) =====
        ("CSPR-001", "Reentrancy", "HIGH", "Reentrancy attack via external calls before state update", "V0.2.0"),
        ("CSPR-002", "Integer Overflow", "MED", "Unchecked arithmetic operations", "V0.2.0"),
        ("CSPR-003", "Access Control", "HIGH", "Missing access control in entry points", "V0.2.0"),
        ("CSPR-004", "Unchecked Calls", "MED", "External calls without error handling", "V0.2.0"),
        ("CSPR-005", "Storage Collision", "LOW", "Potential storage key collisions", "V0.2.0"),
        // ===== V0.3.0 (6) =====
        ("CSPR-006", "DOS Risk", "MED", "Unbounded loops with external calls", "V0.3.0"),
        ("CSPR-007", "Gas Limit Risk", "LOW", "Loops with excessive operations", "V0.3.0"),
        ("CSPR-008", "Uninitialized Storage", "MED", "Storage read before initialization", "V0.3.0"),
        ("CSPR-009", "Multiple External Calls", "LOW", "Functions with many external dependencies", "V0.3.0"),
        ("CSPR-010", "Complex Entry Point", "INFO", "High cyclomatic complexity", "V0.3.0"),
        ("CSPR-011", "Write-Only Storage", "INFO", "Storage written but never read", "V0.3.0"),
        // ===== V4.0 (9) =====
        ("CSPR-012", "Timestamp Manipulation", "MED", "Use of manipulable block timestamps", "V4.0"),
        ("CSPR-013", "Unchecked Return Values", "MED", "External calls with unchecked returns", "V4.0"),
        ("CSPR-014", "Dangerous Delegatecall", "HIGH", "Risky delegatecall usage", "V4.0"),
        ("CSPR-015", "Redundant Code", "INFO", "Duplicate or redundant patterns", "V4.0"),
        ("CSPR-016", "Dead Code", "INFO", "Unused private functions", "V4.0"),
        ("CSPR-017", "Magic Numbers", "INFO", "Hardcoded numbers without constants", "V4.0"),
        ("CSPR-018", "Unsafe Type Casting", "LOW", "Potentially unsafe type conversions", "V4.0"),
        ("CSPR-019", "Inefficient Storage", "MED", "Storage writes inside loops", "V4.0"),
        ("CSPR-020", "Missing Events", "LOW", "State changes without event emissions", "V4.0"),
        // ===== V6.0 NEW (10) - Casper-Specific =====
        ("CSPR-021", "URef Access Rights", "HIGH", "URef operations without access rights check (July 2024 $6.7M breach)", "V6.0"),
        ("CSPR-022", "Unprotected Init", "CRIT", "Init function callable multiple times (node doesn't enforce)", "V6.0"),
        ("CSPR-023", "Purse in Dictionary", "CRIT", "Storing purses in dictionaries (causes ForgedReference error)", "V6.0"),
        ("CSPR-024", "Call Stack Depth", "MED", "Cross-contract call depth approaching limit (max 10)", "V6.0"),
        ("CSPR-025", "Dictionary Key Length", "MED", "Dictionary keys exceeding 128 byte limit", "V6.0"),
        ("CSPR-026", "Unsafe Unwrap", "MED", "Using .unwrap()/.expect() which can panic", "V6.0"),
        ("CSPR-027", "Missing Caller Validation", "CRIT", "Ownership changes without caller verification", "V6.0"),
        ("CSPR-028", "Unbounded Loop", "MED", "while/loop without clear bounds", "V6.0"),
        ("CSPR-029", "CEP Compliance", "MED", "Missing required CEP-18/CEP-78 methods", "V6.0"),
        ("CSPR-030", "Odra Issues", "MED", "Odra module without proper init", "V6.0"),
    ];

    let total = detectors.len();

    // Group by version
    println!("{}", "  Original Detectors (V0.2.0 - V4.0):".bold());
    println!();

    for (id, name, severity, desc, version) in detectors.iter().take(20) {
        let severity_colored = match *severity {
            "CRIT" => severity.red().bold(),
            "HIGH" => severity.red(),
            "MED" => severity.yellow(),
            "LOW" => severity.cyan(),
            "INFO" => severity.bright_black(),
            _ => severity.white(),
        };

        println!("  {} {} [{}] {}", id.bright_black(), name.bold(), severity_colored, version.bright_black());
        println!("      {}", desc.bright_black());
    }

    println!();
    println!("{}", "  NEW V6.0 Casper-Specific Detectors:".bold().magenta());
    println!();

    for (id, name, severity, desc, version) in detectors.iter().skip(20) {
        let severity_colored = match *severity {
            "CRIT" => severity.red().bold(),
            "HIGH" => severity.red(),
            "MED" => severity.yellow(),
            "LOW" => severity.cyan(),
            "INFO" => severity.bright_black(),
            _ => severity.white(),
        };

        println!("  {} {} [{}] {}", id.magenta(), name.bold(), severity_colored, version.magenta());
        println!("      {}", desc.bright_black());
    }

    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_black());
    println!("  {} {}", "Total Detectors:".bold(), total.to_string().green().bold());
    println!("  {} {}", "New in V6.0:".bold(), "10 Casper-specific detectors".magenta());
    println!("  {} {}", "Categories:".bold(), "Security, Access Control, Arithmetic, Reentrancy,");
    println!("             Storage, Gas, Code Quality, Casper-Specific, Odra");
    println!("{}", "═══════════════════════════════════════════════════════════════════".bright_black());
}

fn submit_audit_onchain(
    file: PathBuf,
    contract_address: String,
    registry: Option<String>,
    node_url: String,
) -> Result<()> {
    println!("{}", "CasperSecure V6.0 - Submit Audit to On-Chain Registry".bold().cyan());
    println!();

    // First, analyze the contract to get the audit results
    println!("{} Analyzing contract: {}", "●".cyan(), file.display());
    let parser = CasperParser::new();
    let contract = parser.parse_file(&file)?;

    let analyzer = CasperAnalyzer::new();
    let analysis = analyzer.analyze(&contract)?;

    let detector = VulnerabilityDetector::new();
    let report = detector.detect(&contract, &analysis)?;

    println!("  {} Analysis complete (30 detectors)", "✓".green());
    println!();

    // Display audit summary
    println!("{}", "Audit Summary:".bold());
    println!("  Contract: {}", contract_address.bright_white());
    println!("  Security Score: {}/100", report.summary.security_score.to_string().bold());
    println!("  Security Grade: {}", report.summary.security_grade.bold());
    println!("  Detectors Run: {}", report.summary.detectors_run);
    println!();

    println!("  Vulnerabilities:");
    if report.summary.critical > 0 {
        println!("    Critical: {}", report.summary.critical.to_string().red().bold());
    }
    if report.summary.high > 0 {
        println!("    High:     {}", report.summary.high.to_string().bright_red());
    }
    if report.summary.medium > 0 {
        println!("    Medium:   {}", report.summary.medium.to_string().yellow());
    }
    if report.summary.low > 0 {
        println!("    Low:      {}", report.summary.low.to_string().bright_blue());
    }
    if report.summary.info > 0 {
        println!("    Info:     {}", report.summary.info.to_string().white());
    }
    println!();

    // Generate contract hash (MD5 of file contents)
    let contract_source = std::fs::read_to_string(&file)?;
    let contract_hash = format!("{:x}", md5::compute(contract_source.as_bytes()));

    println!("{}", "On-Chain Registration:".bold());
    println!("  Registry Contract: {}",
        registry.as_ref()
            .unwrap_or(&"default (to be deployed)".to_string())
            .bright_white()
    );
    println!("  Node URL: {}", node_url.bright_white());
    println!("  Contract Hash: {}", contract_hash.bright_black());
    println!();

    // Display submission preview
    println!("{}", "Submission Preview:".bold().yellow());
    println!();
    println!("  {}", "Contract Details:".bold());
    println!("    - Address: {}", contract_address);
    println!("    - Hash: {}", contract_hash);
    println!();
    println!("  {}", "Audit Results:".bold());
    println!("    - Security Score: {}", report.summary.security_score);
    println!("    - Security Grade: {}", report.summary.security_grade);
    println!("    - Critical: {}", report.summary.critical);
    println!("    - High: {}", report.summary.high);
    println!("    - Medium: {}", report.summary.medium);
    println!("    - Low: {}", report.summary.low);
    println!("    - Info: {}", report.summary.info);
    println!();

    println!("{}", "═".repeat(60).bright_black());
    println!();
    println!("{}", "Note:".bold().yellow());
    println!("  To submit this audit on-chain:");
    println!("  1. Deploy the audit registry contract to Casper network");
    println!("  2. Configure your Casper account keys");
    println!("  3. Provide the deployed registry contract hash");
    println!();
    println!("{}", "✓ Audit preview complete".green().bold());

    Ok(())
}

fn print_version() {
    println!("{} {}", "CasperSecure".bold().cyan(), env!("CARGO_PKG_VERSION"));
    println!("{}", "Advanced Security Analyzer for Casper Smart Contracts".bright_black());
    println!();
    println!("  {} 30 vulnerability detectors", "●".green());
    println!("  {} Casper-specific security checks", "●".green());
    println!("  {} Odra 2.4.0 framework support", "●".green());
    println!("  {} On-chain audit registry", "●".green());
    println!();
    println!("{}", "New in V6.0:".bold());
    println!("  - URef access rights detection (July 2024 breach)", );
    println!("  - Unprotected init detection");
    println!("  - Purse in dictionary detection");
    println!("  - Call stack depth analysis");
    println!("  - CEP-18/CEP-78 compliance checking");
    println!("  - Odra module analysis");
}
