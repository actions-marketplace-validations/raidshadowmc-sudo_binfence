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

fn create_synthetic_elf(has_nx: bool, is_pie: bool) -> Vec<u8> {
    let mut data = vec![0u8; 512];
    data[0..4].copy_from_slice(b"\x7FELF");
    data[4] = 2; // 64-bit
    data[5] = 1; // Little-endian
    data[6] = 1; // ELF version
    data[7] = 0; // System V ABI
    let e_type: u16 = if is_pie { 3 } else { 2 }; // ET_DYN or ET_EXEC
    data[16..18].copy_from_slice(&e_type.to_le_bytes());
    data[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    data[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
    data[24..32].copy_from_slice(&0x1000u64.to_le_bytes()); // e_entry
    data[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff = 64
    data[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    data[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    data[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum = 2

    // PH 0: PT_LOAD
    data[64..68].copy_from_slice(&1u32.to_le_bytes());
    data[68..72].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    data[72..80].copy_from_slice(&0u64.to_le_bytes());
    data[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
    data[88..96].copy_from_slice(&0x1000u64.to_le_bytes());
    data[96..104].copy_from_slice(&512u64.to_le_bytes());
    data[104..112].copy_from_slice(&512u64.to_le_bytes());
    data[112..120].copy_from_slice(&0x1000u64.to_le_bytes());

    // PH 1: PT_GNU_STACK
    let p_flags = if has_nx { 6u32 } else { 7u32 }; // RW vs RWX
    let ph1 = 64 + 56;
    data[ph1..ph1 + 4].copy_from_slice(&0x6474e551u32.to_le_bytes());
    data[ph1 + 4..ph1 + 8].copy_from_slice(&p_flags.to_le_bytes());
    data
}

#[test]
fn test_evaluate_gate_on_synthetic_elf() {
    let hardened_elf = create_synthetic_elf(true, true);
    let target_file = "target/test_hardened.elf";
    fs::write(target_file, &hardened_elf).expect("write hardened elf");

    let policy = GatePolicy {
        require_aslr: true,
        require_dep: true,
        disallow_rwx: true,
        ..Default::default()
    };

    let eval = evaluate_gate(target_file, None, &policy).expect("evaluation should run");
    assert!(eval.passed, "synthetic hardened ELF must pass release gate");
    assert_eq!(eval.findings.len(), 0);

    let _ = fs::remove_file(target_file);
}

#[test]
fn test_evaluate_gate_detects_synthetic_degradation() {
    let baseline_elf = create_synthetic_elf(true, true);
    let degraded_elf = create_synthetic_elf(false, false);

    let baseline_file = "target/test_base.elf";
    let degraded_file = "target/test_degraded.elf";
    fs::write(baseline_file, &baseline_elf).expect("write base elf");
    fs::write(degraded_file, &degraded_elf).expect("write degraded elf");

    let policy = GatePolicy {
        fail_on_degraded: true,
        require_aslr: true,
        require_dep: true,
        ..Default::default()
    };

    let eval =
        evaluate_gate(degraded_file, Some(baseline_file), &policy).expect("evaluation should run");
    assert!(!eval.passed, "degraded ELF must FAIL release gate");
    assert!(eval.findings.iter().any(|f| f.rule_id.contains("ASLR")));
    assert!(eval.findings.iter().any(|f| f.rule_id.contains("DEP")));

    let _ = fs::remove_file(baseline_file);
    let _ = fs::remove_file(degraded_file);
}
