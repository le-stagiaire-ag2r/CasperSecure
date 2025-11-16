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
    println!("{}", "CasperSecure Vulnerability Detectors".bold().cyan());
    println!();

    let detectors = vec![
        ("Reentrancy", "High", "Detects reentrancy attack vulnerabilities via external calls"),
        ("Integer Overflow", "Medium", "Finds unchecked arithmetic operations that may overflow"),
        ("Access Control", "High", "Identifies missing access control checks in entry points"),
        ("Unchecked Calls", "Medium", "Detects external calls without error handling"),
        ("Storage Collision", "Low", "Finds potential storage key collision risks"),
    ];

    for (name, severity, desc) in detectors {
        println!("• {} [{}]", name.bold(), severity.yellow());
        println!("  {}", desc);
        println!();
    }
}

fn print_version() {
    println!("{} {}", "CasperSecure".bold().cyan(), env!("CARGO_PKG_VERSION"));
    println!("Advanced Security Analyzer for Casper Smart Contracts");
}
