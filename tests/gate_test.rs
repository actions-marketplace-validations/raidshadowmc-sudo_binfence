use relgate::checker::evaluate_gate;
use relgate::policy::GatePolicy;

use std::fs;

#[test]
fn test_evaluate_gate_on_binlens_release() {
    let binary_path = "../binlens/target/release/binlens.exe";
    if !std::path::Path::new(binary_path).exists() {
        return;
    }

    let policy = GatePolicy {
        fail_on_degraded: true,
        require_aslr: true,
        require_dep: true,
        disallow_rwx: true,
        fail_on_tampered: true,
        require_authenticode: false,
        ..Default::default()
    };

    let eval = evaluate_gate(binary_path, None, &policy).expect("evaluation should succeed");
    assert!(
        eval.passed,
        "binlens.exe should pass default security gates"
    );
    assert!(
        eval.findings.is_empty(),
        "expected 0 findings on hardened binlens.exe"
    );
    assert_eq!(eval.sarif.runs[0].results.len(), 0);
}

#[test]
fn test_evaluate_gate_detects_mitigation_degradation() {
    let binary_path = "../binlens/target/release/binlens.exe";
    if !std::path::Path::new(binary_path).exists() {
        return;
    }

    // Read genuine binlens.exe
    let mut data = fs::read(binary_path).expect("read binlens.exe");

    // Patch PE header to strip ASLR (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040)
    // Find PE offset at 0x3C
    let pe_offset = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    // Optional Header DllCharacteristics offset: PE + 4 (signature) + 20 (COFF header) + 70 (DllCharacteristics in PE32+)
    let dll_chars_offset = pe_offset + 4 + 20 + 70;
    let old_chars = u16::from_le_bytes(
        data[dll_chars_offset..dll_chars_offset + 2]
            .try_into()
            .unwrap(),
    );
    let stripped_chars = old_chars & !0x0040; // clear DYNAMIC_BASE
    data[dll_chars_offset..dll_chars_offset + 2].copy_from_slice(&stripped_chars.to_le_bytes());

    let degraded_file = "target/test_degraded_binlens.exe";
    fs::write(degraded_file, &data).expect("write degraded binary");

    let policy = GatePolicy {
        fail_on_degraded: true,
        require_aslr: true,
        require_dep: true,
        disallow_rwx: true,
        ..Default::default()
    };

    let eval =
        evaluate_gate(degraded_file, Some(binary_path), &policy).expect("evaluation should run");
    assert!(!eval.passed, "gate should FAIL on degraded ASLR");
    assert!(eval.findings.iter().any(|f| f.rule_id.contains("ASLR")));
    assert!(
        !eval.sarif.runs[0].results.is_empty(),
        "SARIF should report the degradation"
    );

    let _ = fs::remove_file(degraded_file);
}

#[test]
fn test_evaluate_gate_detects_rwx_section() {
    let binary_path = "../binlens/target/release/binlens.exe";
    if !std::path::Path::new(binary_path).exists() {
        return;
    }

    let mut data = fs::read(binary_path).expect("read binlens.exe");
    let pe_offset = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    let opt_size =
        u16::from_le_bytes(data[pe_offset + 20..pe_offset + 22].try_into().unwrap()) as usize;
    let first_section_offset = pe_offset + 24 + opt_size;
    // Characteristics is at offset 36 in Section Header (40 bytes total)
    let char_offset = first_section_offset + 36;
    let old_chars = u32::from_le_bytes(data[char_offset..char_offset + 4].try_into().unwrap());
    // Add MEM_WRITE (0x80000000) and MEM_EXECUTE (0x20000000)
    let rwx_chars = old_chars | 0x80000000 | 0x20000000;
    data[char_offset..char_offset + 4].copy_from_slice(&rwx_chars.to_le_bytes());

    let rwx_file = "target/test_rwx_binlens.exe";
    fs::write(rwx_file, &data).expect("write rwx binary");

    let policy = GatePolicy {
        disallow_rwx: true,
        ..Default::default()
    };

    let eval = evaluate_gate(rwx_file, None, &policy).expect("evaluation should run");
    assert!(!eval.passed, "gate should FAIL on RWX section");
    assert!(
        eval.findings
            .iter()
            .any(|f| f.rule_id == "REL004-RWX-SECTION")
    );

    let _ = fs::remove_file(rwx_file);
}
