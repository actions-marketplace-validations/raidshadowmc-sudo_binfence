use clap::Parser;
use colored::*;
use std::fs;

use binfence::checker;
use binfence::policy;
use binfence::summary;

#[derive(Parser, Debug)]
#[command(name = "binfence")]
#[command(author = "raidshadowmc-sudo")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Binary release security gate & mitigation regression auditor for CI/CD")]
struct Cli {
    /// Path to the compiled target binary to audit
    #[arg(short, long)]
    binary: String,

    /// Optional path to baseline binary for differential regression check
    #[arg(long)]
    baseline: Option<String>,

    /// Fail the gate if any security mitigation degraded from baseline
    #[arg(long, env = "BINFENCE_FAIL_ON_DEGRADED", default_value_t = true, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    fail_on_degraded: bool,

    /// Require ASLR / PIE to be enabled on target binary
    #[arg(long, env = "BINFENCE_REQUIRE_ASLR", default_value_t = true, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    require_aslr: bool,

    /// Require DEP / NX to be enabled on target binary
    #[arg(long, env = "BINFENCE_REQUIRE_DEP", default_value_t = true, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    require_dep: bool,

    /// Fail if target has any simultaneously writable and executable (RWX) sections
    #[arg(long, alias = "fail-on-rwx", env = "BINFENCE_DISALLOW_RWX", default_value_t = true, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    disallow_rwx: bool,

    /// Fail if Authenticode signature is tampered or digest mismatches
    #[arg(long, env = "BINFENCE_FAIL_ON_TAMPERED", default_value_t = true, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    fail_on_tampered: bool,

    /// Require binary to be signed with Authenticode
    #[arg(long, env = "BINFENCE_REQUIRE_AUTHENTICODE", default_value_t = false, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    require_authenticode: bool,

    /// Require Control Flow Guard (CFG) on Windows PE binaries
    #[arg(long, env = "BINFENCE_REQUIRE_CFG", default_value_t = false, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    require_cfg: bool,

    /// Require Stack Canary / /GS buffer security check
    #[arg(long, env = "BINFENCE_REQUIRE_STACK_CANARY", default_value_t = false, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    require_stack_canary: bool,

    /// Maximum permissible Shannon entropy before warning/failing (default: 7.5)
    #[arg(long, env = "BINFENCE_MAX_ENTROPY")]
    max_entropy: Option<String>,

    /// Maximum number of new section additions allowed compared to baseline
    #[arg(long, env = "BINFENCE_MAX_NEW_SECTIONS")]
    max_new_sections: Option<String>,

    /// Optional path to YARA rules file (.yar, .yara) or rules directory
    #[arg(long, env = "BINFENCE_YARA_RULES")]
    yara_rules: Option<String>,

    /// Output path for SARIF v2.1.0 report
    #[arg(long, env = "BINFENCE_SARIF_FILE", default_value = "binfence.sarif")]
    sarif_file: String,

    /// Optional output path for GitHub Step Summary markdown
    #[arg(long, env = "BINFENCE_SUMMARY_FILE")]
    summary_file: Option<String>,

    /// Automatically output rich Markdown report to GITHUB_STEP_SUMMARY
    #[arg(long, env = "BINFENCE_SUMMARY", default_value_t = true, num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    summary: bool,

    /// Output full JSON evaluation to stdout
    #[arg(long)]
    json: bool,
}

fn main() {
    let cli = Cli::parse();

    let max_entropy = match cli
        .max_entropy
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => match s.parse::<f64>() {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!(
                    "{}: invalid float for --max-entropy: {}",
                    "Error".red().bold(),
                    e
                );
                std::process::exit(1);
            }
        },
        None => Some(7.5),
    };

    let max_new_sections = match cli
        .max_new_sections
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => match s.parse::<usize>() {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!(
                    "{}: invalid integer for --max-new-sections: {}",
                    "Error".red().bold(),
                    e
                );
                std::process::exit(1);
            }
        },
        None => None,
    };

    let yara_rules = cli
        .yara_rules
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let baseline = cli
        .baseline
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let policy = policy::GatePolicy {
        fail_on_degraded: cli.fail_on_degraded,
        require_aslr: cli.require_aslr,
        require_dep: cli.require_dep,
        disallow_rwx: cli.disallow_rwx,
        fail_on_tampered: cli.fail_on_tampered,
        require_authenticode: cli.require_authenticode,
        require_cfg: cli.require_cfg,
        require_stack_canary: cli.require_stack_canary,
        max_entropy,
        max_new_sections,
        yara_rules,
    };

    let eval = match checker::evaluate_gate(&cli.binary, baseline.as_deref(), &policy) {
        Ok(ev) => ev,
        Err(e) => {
            eprintln!("{} {}", "Error evaluating release gate:".red().bold(), e);

            // Emit a minimal SARIF log so CI scanners never fail on missing files
            let mut err_sarif = binfence::sarif::SarifLog::new();
            err_sarif.add_rule(
                "BIN000-EVAL-ERROR",
                "EvaluationError",
                "Release gate failed to evaluate binary",
                Some("An I/O or parser error occurred while inspecting the target or baseline binary."),
                "error",
            );
            err_sarif.add_result(
                "BIN000-EVAL-ERROR",
                "error",
                &format!("Evaluation error: {}", e),
                &cli.binary,
            );
            if let Ok(s) = serde_json::to_string_pretty(&err_sarif) {
                let _ = fs::write(&cli.sarif_file, s);
            }

            // Write minimal step summary
            let summary_err = format!(
                "### 🔴 Binfence Security Gate: **FAILED (Evaluation Error)**\n\n**Error**: {}\n\nTarget Asset: `{}`\n",
                e, cli.binary
            );
            if let Some(ref path) = cli.summary_file {
                let _ = fs::write(path, &summary_err);
            }
            if let Ok(github_summary_path) = std::env::var("GITHUB_STEP_SUMMARY") {
                if !github_summary_path.is_empty() {
                    let _ = fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&github_summary_path)
                        .map(|mut f| {
                            use std::io::Write;
                            let _ = writeln!(f, "\n{}\n", summary_err);
                        });
                }
            }

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
    if cli.summary {
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
            "       BINFENCE — Binary Release Security Gate & Auditor"
                .bold()
                .cyan()
        );
        println!(
            "{}",
            "══════════════════════════════════════════════════════════════════════".cyan()
        );
        println!("  Target Asset   : {}", cli.binary.bold());
        if let Some(ref b) = baseline {
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
