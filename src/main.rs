use clap::Parser;
use colored::*;
use std::fs;

use relgate::checker;
use relgate::policy;
use relgate::summary;

#[derive(Parser, Debug)]
#[command(name = "relgate")]
#[command(author = "raidshadowmc-sudo")]
#[command(version = "0.1.0")]
#[command(about = "Binary release security gate & mitigation regression auditor for CI/CD")]
struct Cli {
    /// Path to the compiled target binary to audit
    #[arg(short, long)]
    binary: String,

    /// Optional path to baseline binary for differential regression check
    #[arg(long)]
    baseline: Option<String>,

    /// Fail the gate if any security mitigation degraded from baseline (default: true)
    #[arg(long, default_value_t = true)]
    fail_on_degraded: bool,

    /// Require ASLR / PIE to be enabled on target binary (default: true)
    #[arg(long, default_value_t = true)]
    require_aslr: bool,

    /// Require DEP / NX to be enabled on target binary (default: true)
    #[arg(long, default_value_t = true)]
    require_dep: bool,

    /// Fail if target has any simultaneously writable and executable (RWX) sections (default: true)
    #[arg(long, default_value_t = true)]
    disallow_rwx: bool,

    /// Fail if Authenticode signature is tampered or digest mismatches (default: true)
    #[arg(long, default_value_t = true)]
    fail_on_tampered: bool,

    /// Require binary to be signed with Authenticode (default: false)
    #[arg(long, default_value_t = false)]
    require_authenticode: bool,

    /// Maximum permissible Shannon entropy before warning/failing (default: 7.5)
    #[arg(long)]
    max_entropy: Option<f64>,

    /// Optional path to YARA rules file (.yar, .yara) or rules directory
    #[arg(long)]
    yara_rules: Option<String>,

    /// Output path for SARIF v2.1.0 report
    #[arg(long, default_value = "relgate.sarif")]
    sarif_file: String,

    /// Optional output path for GitHub Step Summary markdown
    #[arg(long)]
    summary_file: Option<String>,

    /// Output full JSON evaluation to stdout
    #[arg(long)]
    json: bool,
}

fn main() {
    let cli = Cli::parse();

    let policy = policy::GatePolicy {
        fail_on_degraded: cli.fail_on_degraded,
        require_aslr: cli.require_aslr,
        require_dep: cli.require_dep,
        disallow_rwx: cli.disallow_rwx,
        fail_on_tampered: cli.fail_on_tampered,
        require_authenticode: cli.require_authenticode,
        max_entropy: cli.max_entropy.or(Some(7.5)),
        yara_rules: cli.yara_rules,
        ..Default::default()
    };

    let eval = match checker::evaluate_gate(&cli.binary, cli.baseline.as_deref(), &policy) {
        Ok(ev) => ev,
        Err(e) => {
            eprintln!("{} {}", "Error evaluating release gate:".red().bold(), e);
            std::process::exit(1);
        }
    };

    // Save SARIF file
    let sarif_json = match serde_json::to_string_pretty(&eval.sarif) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} {}", "Failed to serialize SARIF report:".red().bold(), e);
            std::process::exit(1);
        }
    };
    if let Err(e) = fs::write(&cli.sarif_file, sarif_json) {
        eprintln!("{} {}", "Failed to write SARIF file:".red().bold(), e);
    }

    // Markdown summary
    let summary_md = summary::render_markdown_summary(
        &eval.target_report,
        eval.baseline_report.as_ref(),
        eval.diff_report.as_ref(),
        &eval.findings,
        eval.passed,
    );

    // Write to GITHUB_STEP_SUMMARY if env variable is set or summary_file is provided
    if let Some(ref path) = cli.summary_file {
        let _ = fs::write(path, &summary_md);
    }
    if let Ok(github_summary_path) = std::env::var("GITHUB_STEP_SUMMARY") {
        if !github_summary_path.is_empty() {
            let _ = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&github_summary_path)
                .map(|mut f| {
                    use std::io::Write;
                    let _ = writeln!(f, "\n{}\n", summary_md);
                });
        }
    }

    if cli.json {
        let json_output = serde_json::json!({
            "passed": eval.passed,
            "target": eval.target_report,
            "baseline": eval.baseline_report,
            "diff": eval.diff_report,
            "findings": eval.findings.iter().map(|f| {
                serde_json::json!({
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json_output).unwrap());
    } else {
        // Pretty terminal output
        println!();
        println!(
            "{}",
            "══════════════════════════════════════════════════════════════════════".cyan()
        );
        println!(
            "{}",
            "       RELGATE — Binary Release Security Gate & Auditor"
                .bold()
                .cyan()
        );
        println!(
            "{}",
            "══════════════════════════════════════════════════════════════════════".cyan()
        );
        println!("  Target Asset   : {}", cli.binary.bold());
        if let Some(ref b) = cli.baseline {
            println!("  Baseline Asset : {}", b.bold());
        }
        println!(
            "  Format / Arch  : {} / {}",
            eval.target_report.format, eval.target_report.architecture
        );
        println!("  File Size      : {} bytes", eval.target_report.file_size);
        println!(
            "  Entropy        : {:.3} / 8.000",
            eval.target_report.overall_entropy
        );
        println!("  SARIF Report   : {}", cli.sarif_file.bold());
        println!(
            "{}",
            "──────────────────────────────────────────────────────────────────────".cyan()
        );

        if eval.findings.is_empty() {
            println!(
                "  {}",
                "✓ All security mitigations and policy gates passed with zero violations."
                    .green()
                    .bold()
            );
        } else {
            println!("  Policy Findings & Violations:");
            for f in &eval.findings {
                let badge = match f.severity.as_str() {
                    "error" => "FAIL".red().bold(),
                    "warning" => "WARN".yellow().bold(),
                    _ => "INFO".blue(),
                };
                println!("  [{}] {}: {}", badge, f.rule_id.bold(), f.title);
                println!("         └─ {}", f.description);
            }
        }

        println!(
            "{}",
            "══════════════════════════════════════════════════════════════════════".cyan()
        );
        if eval.passed {
            println!("  RESULT: {}", "RELEASE GATE PASSED 🟢".green().bold());
        } else {
            println!(
                "  RESULT: {}",
                "RELEASE GATE FAILED 🔴 (Blocked by security policy)"
                    .red()
                    .bold()
            );
        }
        println!(
            "{}",
            "══════════════════════════════════════════════════════════════════════".cyan()
        );
        println!();
    }

    if !eval.passed {
        std::process::exit(1);
    }
}
