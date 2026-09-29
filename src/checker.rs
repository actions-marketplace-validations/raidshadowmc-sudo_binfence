use crate::policy::GatePolicy;
use crate::sarif::SarifLog;
use crate::summary::{GateFinding, GateStatus};
use binlens::types::{BinaryReport, DiffReport};
use binlens::{diff, elf, macho, pe, strings, types, yara};
use std::fs;
use std::path::Path;

pub struct GateEvaluation {
    pub passed: bool,
    pub findings: Vec<GateFinding>,
    pub target_report: BinaryReport,
    pub baseline_report: Option<BinaryReport>,
    pub diff_report: Option<DiffReport>,
    pub sarif: SarifLog,
}

pub fn map_or_read_file(path_str: &str) -> Result<(Option<memmap2::Mmap>, Vec<u8>), String> {
    let path = Path::new(path_str);
    if !path.exists() {
        return Err(format!("File does not exist: {}", path_str));
    }
    let file =
        fs::File::open(path).map_err(|e| format!("Failed to open file '{}': {}", path_str, e))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Failed to get metadata: {}", e))?;

    if metadata.len() == 0 {
        return Ok((None, Vec::new()));
    }

    match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => Ok((Some(mmap), Vec::new())),
        Err(_) => {
            let data = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;
            Ok((None, data))
        }
    }
}

pub fn get_data_slice<'a>(mmap: &'a Option<memmap2::Mmap>, fallback: &'a [u8]) -> &'a [u8] {
    if let Some(m) = mmap { &m[..] } else { fallback }
}

pub fn analyze_binary(path_str: &str) -> Result<BinaryReport, String> {
    let (mmap, fallback) = map_or_read_file(path_str)?;
    let data = get_data_slice(&mmap, &fallback);

    let file_name = Path::new(path_str)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path_str.to_string());

    let mut report = if let Some(pe_report) = pe::parse_pe(data, &file_name) {
        pe_report
    } else if let Some(elf_report) = elf::parse_elf(data, &file_name) {
        elf_report
    } else if let Some(macho_report) = macho::parse_macho(data, &file_name) {
        macho_report
    } else {
        return Err(format!(
            "Unsupported or unrecognized binary format: {}",
            path_str
        ));
    };

    report.interesting_strings = strings::extract_strings(data, 4);
    Ok(report)
}

pub fn evaluate_gate(
    target_path: &str,
    baseline_path: Option<&str>,
    policy: &GatePolicy,
) -> Result<GateEvaluation, String> {
    let target_report = analyze_binary(target_path)?;
    let mut findings = Vec::new();
    let mut sarif = SarifLog::new();

    // Baseline & Diff analysis if provided
    let (baseline_report, diff_report) = if let Some(base_p) = baseline_path {
        let base_rep = analyze_binary(base_p)?;
        let diff_rep = diff::generate_diff_report(&base_rep, &target_report);
        (Some(base_rep), Some(diff_rep))
    } else {
        (None, None)
    };

    // 1. Check for mitigation degradations against baseline
    if policy.fail_on_degraded {
        if let Some(ref d) = diff_report {
            for m in &d.mitigations_drift {
                if m.status == "degraded" {
                    let sanitized_name: String = m
                        .mitigation
                        .chars()
                        .map(|c| {
                            if c.is_alphanumeric() {
                                c.to_ascii_uppercase()
                            } else {
                                '-'
                            }
                        })
                        .collect();
                    let rule_id = format!("REL001-{}", sanitized_name.trim_matches('-'));

                    findings.push(GateFinding {
                        rule_id: rule_id.clone(),
                        title: format!("Mitigation Degraded: {}", m.mitigation),
                        description: format!(
                            "Security mitigation '{}' was enabled in baseline but was stripped or disabled in target.",
                            m.mitigation
                        ),
                        status: GateStatus::Degraded,
                        severity: "error".to_string(),
                    });

                    sarif.add_rule(
                        &rule_id,
                        "SecurityMitigationDegraded",
                        &format!("Security mitigation '{}' degraded", m.mitigation),
                        Some("A security hardening mitigation was active in the baseline binary but is missing in the new build."),
                        "error",
                    );
                    sarif.add_result(
                        &rule_id,
                        "error",
                        &format!(
                            "Mitigation '{}' degraded from enabled to disabled",
                            m.mitigation
                        ),
                        target_path,
                    );
                }
            }
        }
    }

    // 2. Absolute Check: ASLR / PIE
    if policy.require_aslr {
        let aslr_ok = target_report.mitigations.aslr || target_report.mitigations.pie;
        if !aslr_ok {
            findings.push(GateFinding {
                rule_id: "REL002-NO-ASLR".to_string(),
                title: "ASLR / PIE Not Enabled".to_string(),
                description: "Target binary was compiled without Address Space Layout Randomization (ASLR / PIE)."
                    .to_string(),
                status: GateStatus::Failed,
                severity: "error".to_string(),
            });

            sarif.add_rule(
                "REL002-NO-ASLR",
                "RequireASLR",
                "ASLR or PIE mitigation is missing",
                Some("Binaries must be linked with dynamic base / PIE enabled to randomize memory layout."),
                "error",
            );
            sarif.add_result(
                "REL002-NO-ASLR",
                "error",
                "Binary missing ASLR/PIE mitigation",
                target_path,
            );
        }
    }

    // 3. Absolute Check: DEP / NX
    if policy.require_dep {
        if !target_report.mitigations.dep_nx {
            findings.push(GateFinding {
                rule_id: "REL003-NO-DEP".to_string(),
                title: "DEP / NX Not Enabled".to_string(),
                description: "Target binary does not enforce Data Execution Prevention / No-Execute stack protection."
                    .to_string(),
                status: GateStatus::Failed,
                severity: "error".to_string(),
            });

            sarif.add_rule(
                "REL003-NO-DEP",
                "RequireDEP",
                "DEP/NX mitigation is missing",
                Some("Binaries must enable NX_COMPAT or PT_GNU_STACK non-executable stack protection."),
                "error",
            );
            sarif.add_result(
                "REL003-NO-DEP",
                "error",
                "Binary missing DEP/NX non-executable memory protection",
                target_path,
            );
        }
    }

    // 4. Absolute Check: W^X (No RWX sections)
    if policy.disallow_rwx {
        if target_report.mitigations.has_rwx_sections {
            let rwx_names: Vec<String> = target_report
                .sections
                .iter()
                .filter(|s| s.is_rwx)
                .map(|s| s.name.clone())
                .collect();

            findings.push(GateFinding {
                rule_id: "REL004-RWX-SECTION".to_string(),
                title: "W^X Violation: RWX Section Present".to_string(),
                description: format!(
                    "Binary contains simultaneously writable and executable sections: [{}]",
                    rwx_names.join(", ")
                ),
                status: GateStatus::Failed,
                severity: "error".to_string(),
            });

            sarif.add_rule(
                "REL004-RWX-SECTION",
                "DisallowRWXSections",
                "Simultaneously writable and executable section detected",
                Some("Writable and executable (RWX) sections violate W^X policy and introduce severe code injection risks."),
                "error",
            );
            sarif.add_result(
                "REL004-RWX-SECTION",
                "error",
                &format!("RWX section detected: {}", rwx_names.join(", ")),
                target_path,
            );
        }
    }

    let is_pe = matches!(
        target_report.format,
        types::BinaryFormat::PE32 | types::BinaryFormat::PE64
    );

    // 5. Authenticode Integrity Check (PE only)
    if let Some(ref auth) = target_report.authenticode {
        if policy.fail_on_tampered {
            match auth.status {
                types::AuthenticodeStatus::DigestMismatch => {
                    findings.push(GateFinding {
                        rule_id: "REL005-AUTHENTICODE-TAMPERED".to_string(),
                        title: "Authenticode Digest Mismatch (Tampering Detected)".to_string(),
                        description: format!(
                            "Calculated {} digest ({}) does not match SpcIndirectDataContent digest ({})",
                            auth.digest_algorithm, auth.calculated_digest, auth.expected_digest
                        ),
                        status: GateStatus::Failed,
                        severity: "error".to_string(),
                    });

                    sarif.add_rule(
                        "REL005-AUTHENTICODE-TAMPERED",
                        "AuthenticodeDigestMismatch",
                        "Binary Authenticode digest does not match embedded signature",
                        Some("The PE image hash does not match the embedded PKCS#7 SpcIndirectDataContent digest, indicating tampering."),
                        "error",
                    );
                    sarif.add_result(
                        "REL005-AUTHENTICODE-TAMPERED",
                        "error",
                        "Authenticode digest mismatch: image has been tampered with or modified post-signing",
                        target_path,
                    );
                }
                types::AuthenticodeStatus::Malformed => {
                    findings.push(GateFinding {
                        rule_id: "REL005-AUTHENTICODE-MALFORMED".to_string(),
                        title: "Authenticode Structure Malformed".to_string(),
                        description: "Embedded PKCS#7 Authenticode structure is corrupt or failed ASN.1 DER decoding.".to_string(),
                        status: GateStatus::Failed,
                        severity: "error".to_string(),
                    });

                    sarif.add_rule(
                        "REL005-AUTHENTICODE-MALFORMED",
                        "AuthenticodeMalformed",
                        "Authenticode certificate structure is malformed",
                        Some("ASN.1 DER parsing failed on embedded certificate table."),
                        "error",
                    );
                    sarif.add_result(
                        "REL005-AUTHENTICODE-MALFORMED",
                        "error",
                        "Malformed Authenticode ASN.1 structure",
                        target_path,
                    );
                }
                _ => {}
            }
        }
    } else if policy.require_authenticode && is_pe {
        findings.push(GateFinding {
            rule_id: "REL006-UNSIGNED-BINARY".to_string(),
            title: "Binary is Unsigned".to_string(),
            description: "Policy requires a valid Authenticode signature, but binary has no embedded signature.".to_string(),
            status: GateStatus::Failed,
            severity: "error".to_string(),
        });

        sarif.add_rule(
            "REL006-UNSIGNED-BINARY",
            "RequireAuthenticode",
            "Binary is not signed",
            Some(
                "Release policy mandates an embedded Authenticode signature on release artifacts.",
            ),
            "error",
        );
        sarif.add_result(
            "REL006-UNSIGNED-BINARY",
            "error",
            "Artifact is missing an Authenticode signature",
            target_path,
        );
    }

    // 6. Optional Check: Control Flow Guard (CFG, PE only)
    if policy.require_cfg && is_pe && !target_report.mitigations.cfg {
        findings.push(GateFinding {
            rule_id: "REL009-NO-CFG".to_string(),
            title: "Control Flow Guard (CFG) Not Enabled".to_string(),
            description:
                "Target Windows PE binary does not have Control Flow Guard (CFG) mitigation active."
                    .to_string(),
            status: GateStatus::Failed,
            severity: "error".to_string(),
        });

        sarif.add_rule(
            "REL009-NO-CFG",
            "RequireControlFlowGuard",
            "Control Flow Guard mitigation is missing",
            Some("Binaries must be compiled with /guard:cf to protect indirect call targets."),
            "error",
        );
        sarif.add_result(
            "REL009-NO-CFG",
            "error",
            "Binary missing Control Flow Guard protection",
            target_path,
        );
    }

    // 7. Optional Check: Stack Canary / /GS Buffer Security Check
    let supports_canary = matches!(
        target_report.format,
        types::BinaryFormat::PE32
            | types::BinaryFormat::PE64
            | types::BinaryFormat::ELF32
            | types::BinaryFormat::ELF64
    );
    if policy.require_stack_canary && supports_canary && !target_report.mitigations.stack_canary {
        findings.push(GateFinding {
            rule_id: "REL010-NO-STACK-CANARY".to_string(),
            title: "Stack Canary Not Enabled".to_string(),
            description:
                "Target binary does not contain stack smash protection (/GS or __stack_chk_fail)."
                    .to_string(),
            status: GateStatus::Failed,
            severity: "error".to_string(),
        });

        sarif.add_rule(
            "REL010-NO-STACK-CANARY",
            "RequireStackCanary",
            "Stack smash protection is missing",
            Some("Binaries must be compiled with stack buffer security checks (-fstack-protector or /GS)."),
            "error",
        );
        sarif.add_result(
            "REL010-NO-STACK-CANARY",
            "error",
            "Binary missing stack buffer protection",
            target_path,
        );
    }

    // 8. Section Additions Check
    if let (Some(max_new), Some(d)) = (policy.max_new_sections, diff_report.as_ref()) {
        let added_count = d
            .section_deltas
            .iter()
            .filter(|s| s.action == "added")
            .count();
        if added_count > max_new {
            findings.push(GateFinding {
                rule_id: "REL011-EXCESS-NEW-SECTIONS".to_string(),
                title: "Excessive Section Additions".to_string(),
                description: format!(
                    "Binary added {} new sections, exceeding allowable policy limit of {}.",
                    added_count, max_new
                ),
                status: GateStatus::Failed,
                severity: "error".to_string(),
            });

            sarif.add_rule(
                "REL011-EXCESS-NEW-SECTIONS",
                "ExcessiveNewSections",
                "Added sections exceed threshold",
                Some("Unexpected section additions can indicate packing, payload embedding, or build script tampering."),
                "error",
            );
            sarif.add_result(
                "REL011-EXCESS-NEW-SECTIONS",
                "error",
                &format!(
                    "New sections ({}) > maximum allowable ({})",
                    added_count, max_new
                ),
                target_path,
            );
        }
    }

    // 8. Shannon Entropy Threshold
    if let Some(max_ent) = policy.max_entropy {
        if target_report.overall_entropy > max_ent {
            findings.push(GateFinding {
                rule_id: "REL007-HIGH-ENTROPY".to_string(),
                title: "Abnormally High Shannon Entropy".to_string(),
                description: format!(
                    "Overall binary entropy ({:.3}) exceeds allowable threshold ({:.3}). Possible unexpected packing or crypto payload.",
                    target_report.overall_entropy, max_ent
                ),
                status: GateStatus::Warning,
                severity: "warning".to_string(),
            });

            sarif.add_rule(
                "REL007-HIGH-ENTROPY",
                "HighEntropyWarning",
                "Binary entropy exceeds threshold",
                Some("High entropy across the binary can signify unexpected compression, packing, or encryption."),
                "warning",
            );
            sarif.add_result(
                "REL007-HIGH-ENTROPY",
                "warning",
                &format!(
                    "Overall entropy {:.3} > threshold {:.3}",
                    target_report.overall_entropy, max_ent
                ),
                target_path,
            );
        }
    }

    // 7. YARA scanning if rules provided
    if let Some(ref yara_path) = policy.yara_rules {
        let (mmap, fallback) = map_or_read_file(target_path)?;
        let data = get_data_slice(&mmap, &fallback);
        match yara::compile_rules_from_path(Path::new(yara_path)) {
            Ok(scanner) => {
                if let Ok(yara_matches) = yara::scan_bytes_with_scanner(data, &scanner) {
                    for m in yara_matches.rules_matched {
                        findings.push(GateFinding {
                            rule_id: format!("REL008-YARA-{}", m.name),
                            title: format!("YARA Rule Match: {}", m.name),
                            description: format!(
                                "Binary matched YARA rule '{}' with {} string match instances.",
                                m.name,
                                m.matches.len()
                            ),
                            status: GateStatus::Failed,
                            severity: "error".to_string(),
                        });

                        sarif.add_rule(
                            &format!("REL008-YARA-{}", m.name),
                            "YaraSignatureMatch",
                            &format!("Binary matched YARA rule {}", m.name),
                            Some("A prohibited pattern or signature was identified by the YARA scanning engine."),
                            "error",
                        );
                        sarif.add_result(
                            &format!("REL008-YARA-{}", m.name),
                            "error",
                            &format!("Matched signature rule {}", m.name),
                            target_path,
                        );
                    }
                }
            }
            Err(e) => {
                return Err(format!(
                    "Failed to compile YARA rules at '{}': {}",
                    yara_path, e
                ));
            }
        }
    }

    // Release gate passes ONLY if there are no findings with severity "error"
    let passed = !findings.iter().any(|f| f.severity == "error");

    Ok(GateEvaluation {
        passed,
        findings,
        target_report,
        baseline_report,
        diff_report,
        sarif,
    })
}
