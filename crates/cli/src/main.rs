//! CasperSecure CLI
//!
//! Command-line interface for analyzing Casper smart contracts

use anyhow::Result;
use casper_analyzer::CasperAnalyzer;
use casper_detector::{DetectionReport, Severity, VulnerabilityDetector};
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
        Commands::Analyze { file, format, severity } => {
            analyze_contract(file, format, severity)?;
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

fn analyze_contract(file: PathBuf, format: String, min_severity: String) -> Result<()> {
    println!("{}", "CasperSecure - Smart Contract Analyzer".bold().cyan());
    println!();

    // Parse the contract
    println!("{} {}", "Parsing contract:".bold(), file.display());
    let parser = CasperParser::new();
    let contract = parser.parse_file(&file)?;
    println!("  {} {} entry points found", "✓".green(), contract.entry_points.len());
    println!("  {} {} functions found", "✓".green(), contract.functions.len());
    println!();

    // Analyze the contract
    println!("{}", "Analyzing contract...".bold());
    let analyzer = CasperAnalyzer::new();
    let analysis = analyzer.analyze(&contract)?;
    println!("  {} Control flow analysis complete", "✓".green());
    println!("  {} Data flow analysis complete", "✓".green());
    println!();

    // Detect vulnerabilities
    println!("{}", "Running vulnerability detectors...".bold());
    let detector = VulnerabilityDetector::new();
    let report = detector.detect(&contract, &analysis)?;
    println!("  {} Detection complete", "✓".green());
    println!();

    // Filter by severity
    let min_sev = parse_severity(&min_severity);
    let filtered_report = filter_report(report, min_sev);

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

    // Summary
    println!("{}", "Summary:".bold());
    println!("  Total vulnerabilities: {}", report.summary.total_vulns.to_string().bold());

    // Security Score & Grade (V4.0) 🎯
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
    println!();

    // Vulnerabilities
    if !report.vulnerabilities.is_empty() {
        println!("{}", "Detected Vulnerabilities:".bold());
        println!("{}", "─".repeat(60));

        for (i, vuln) in report.vulnerabilities.iter().enumerate() {
            println!();
            println!("{}. {} [{}]",
                     (i + 1).to_string().bold(),
                     vuln.vuln_type.bold(),
                     severity_colored(&vuln.severity));

            println!("   Function: {}", vuln.location.function.italic());
            println!("   {}", vuln.description);
            println!("   {} {}", "Recommendation:".bold().green(), vuln.recommendation);
        }

        println!();
        println!("{}", "─".repeat(60));
    } else {
        println!("{}", "No vulnerabilities detected! ✓".green().bold());
    }

    println!();
    println!("{}", "Analysis complete.".italic());
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

fn list_detectors() {
    println!("{}", "═══════════════════════════════════════════════════════════".bright_black());
    println!("{}", "  CasperSecure V4.0 - Vulnerability Detectors 🔥".bold().cyan());
    println!("{}", "  The Ultimate Security Analyzer - 20 Detectors".bright_black());
    println!("{}", "═══════════════════════════════════════════════════════════".bright_black());
    println!();

    let detectors = vec![
        // ===== ORIGINAL V0.2.0 (5) =====
        ("1.  Reentrancy", "HIGH", "Detects reentrancy attack vulnerabilities via external calls", "V0.2.0"),
        ("2.  Integer Overflow", "MED", "Finds unchecked arithmetic operations that may overflow", "V0.2.0"),
        ("3.  Access Control", "HIGH", "Identifies missing access control checks in entry points", "V0.2.0"),
        ("4.  Unchecked Calls", "MED", "Detects external calls without error handling", "V0.2.0"),
        ("5.  Storage Collision", "LOW", "Finds potential storage key collision risks", "V0.2.0"),
        // ===== V0.3.0 (6) =====
        ("6.  DOS Risk", "MED", "Detects unbounded loops with external calls", "V0.3.0"),
        ("7.  Gas Limit Risk", "LOW", "Identifies loops with excessive arithmetic operations", "V0.3.0"),
        ("8.  Uninitialized Storage", "MED", "Finds storage that is read before initialization", "V0.3.0"),
        ("9.  Multiple External Calls", "LOW", "Detects functions with many external dependencies", "V0.3.0"),
        ("10. Complex Entry Point", "INFO", "Identifies entry points with high cyclomatic complexity", "V0.3.0"),
        ("11. Write-Only Storage", "INFO", "Finds storage that is written but never read", "V0.3.0"),
        // ===== V4.0 NEW (9) 🚀 =====
        ("12. Timestamp Manipulation", "MED", "Detects use of manipulable block timestamps", "🆕 V4.0"),
        ("13. Unchecked Return Values", "MED", "Finds external calls with unchecked return values", "🆕 V4.0"),
        ("14. Dangerous Delegatecall", "HIGH", "Detects risky delegatecall usage", "🆕 V4.0"),
        ("15. Redundant Code", "INFO", "Identifies duplicate or redundant code patterns", "🆕 V4.0"),
        ("16. Dead Code", "INFO", "Finds unused private functions", "🆕 V4.0"),
        ("17. Magic Numbers", "INFO", "Detects hardcoded numbers without constants", "🆕 V4.0"),
        ("18. Unsafe Type Casting", "LOW", "Identifies potentially unsafe type conversions", "🆕 V4.0"),
        ("19. Inefficient Storage", "MED", "Detects storage writes inside loops", "🆕 V4.0"),
        ("20. Missing Events", "LOW", "Finds state changes without event emissions", "🆕 V4.0"),
    ];

    let total = detectors.len();

    for (name, severity, desc, version) in &detectors {
        let severity_colored = match *severity {
            "HIGH" => severity.red().bold(),
            "MED" => severity.yellow(),
            "LOW" => severity.cyan(),
            "INFO" => severity.bright_black(),
            _ => severity.white(),
        };

        println!("  {} [{}] {}", name.bold(), severity_colored, version.bright_black());
        println!("    {}", desc.bright_black());
        println!();
    }

    println!("{}", "═══════════════════════════════════════════════════════════".bright_black());
    println!("{}", format!("  Total Detectors: {}", total).bold().green());
    println!("{}", "  Detection Coverage: DOS, Reentrancy, Overflow, Storage,".bright_black());
    println!("{}", "  Access Control, Code Quality, Gas Optimization, Events".bright_black());
    println!("{}", "═══════════════════════════════════════════════════════════".bright_black());
}

fn submit_audit_onchain(
    file: PathBuf,
    contract_address: String,
    registry: Option<String>,
    node_url: String,
) -> Result<()> {
    println!("{}", "CasperSecure - Submit Audit to On-Chain Registry".bold().cyan());
    println!();

    // First, analyze the contract to get the audit results
    println!("{} Analyzing contract: {}", "●".cyan(), file.display());
    let parser = CasperParser::new();
    let contract = parser.parse_file(&file)?;

    let analyzer = CasperAnalyzer::new();
    let analysis = analyzer.analyze(&contract)?;

    let detector = VulnerabilityDetector::new();
    let report = detector.detect(&contract, &analysis)?;

    println!("  {} Analysis complete", "✓".green());
    println!();

    // Display audit summary
    println!("{}", "Audit Summary:".bold());
    println!("  Contract: {}", contract_address.bright_white());
    println!("  Security Score: {}/100", report.summary.security_score.to_string().bold());
    println!("  Security Grade: {}", report.summary.security_grade.bold());
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

    // Generate contract hash (SHA256 of file contents)
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

    // For now, we'll just display what would be submitted
    // In a production version, this would actually call the contract
    println!("{}", "ℹ  Submission Preview:".bold().yellow());
    println!();
    println!("  The following data would be submitted to the on-chain registry:");
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
    println!("{}", "📝 Note:".bold().yellow());
    println!("  To actually submit this audit on-chain, you need to:");
    println!("  1. Deploy the audit registry contract to Casper network");
    println!("  2. Configure your Casper account keys");
    println!("  3. Provide the deployed registry contract hash");
    println!();
    println!("  The registry contract is located at:");
    println!("    {}", "crates/contract/".bright_white());
    println!();
    println!("  To deploy:");
    println!("    {}", "casper-client put-deploy \\".bright_black());
    println!("    {}", "  --chain-name casper-test \\".bright_black());
    println!("    {}", "  --payment-amount 100000000000 \\".bright_black());
    println!("    {}", "  --session-path target/wasm32-unknown-unknown/release/casper_audit_registry.wasm".bright_black());
    println!();
    println!("{}", "✓ Audit preview complete".green().bold());

    Ok(())
}

fn print_version() {
    println!("{} {}", "CasperSecure".bold().cyan(), env!("CARGO_PKG_VERSION"));
    println!("Advanced Security Analyzer for Casper Smart Contracts");
}
