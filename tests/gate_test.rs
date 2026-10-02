use binfence::checker::evaluate_gate;
use binfence::policy::GatePolicy;

use std::fs;

#[test]
fn test_evaluate_gate_on_pe_fixture() {
    let binary_path = "tests/fixtures/sample_pe.exe";
    assert!(
        std::path::Path::new(binary_path).exists(),
        "required PE fixture is missing: {}",
        binary_path
    );

    let policy = GatePolicy {
        fail_on_degraded: true,
        require_aslr: true,
        require_dep: true,
        require_cfg: true,
        disallow_rwx: true,
        fail_on_tampered: true,
        require_authenticode: false,
        ..Default::default()
    };

    let eval = evaluate_gate(binary_path, None, &policy).expect("evaluation should succeed");
    assert!(
        eval.passed,
        "sample_pe.exe should pass default security gates"
    );
    assert!(
        eval.findings.is_empty(),
        "expected 0 findings on hardened sample_pe.exe"
    );
    assert_eq!(eval.sarif.runs[0].results.len(), 0);
}

#[test]
fn test_evaluate_gate_detects_mitigation_degradation() {
    let binary_path = "tests/fixtures/sample_pe.exe";
    assert!(
        std::path::Path::new(binary_path).exists(),
        "required PE fixture is missing: {}",
        binary_path
    );

    // Read genuine sample_pe.exe
    let mut data = fs::read(binary_path).expect("read sample_pe.exe");

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

    let degraded_file = "target/test_degraded_sample_pe.exe";
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
    let binary_path = "tests/fixtures/sample_pe.exe";
    assert!(
        std::path::Path::new(binary_path).exists(),
        "required PE fixture is missing: {}",
        binary_path
    );

    let mut data = fs::read(binary_path).expect("read sample_pe.exe");
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

    let rwx_file = "target/test_rwx_sample_pe.exe";
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
            .any(|f| f.rule_id == "BIN004-RWX-SECTION")
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

fn create_synthetic_pe(
    aslr: bool,
    dep: bool,
    cfg: bool,
    rwx: bool,
    extra_sections: usize,
) -> Vec<u8> {
    let mut data = vec![0u8; 2048 + extra_sections * 40];
    data[0..2].copy_from_slice(b"MZ");
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew

    let pe = 0x80;
    data[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff = pe + 4;
    data[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    let num_sections = (1 + extra_sections) as u16;
    data[coff + 2..coff + 4].copy_from_slice(&num_sections.to_le_bytes());
    data[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
    data[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes()); // EXECUTABLE | LARGE_ADDRESS

    let opt = coff + 20;
    data[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
    data[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    data[opt + 24..opt + 32].copy_from_slice(&0x0000000140000000u64.to_le_bytes());
    data[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    data[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    data[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes());
    data[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
    data[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());

    let mut dll_chars = 0u16;
    if aslr {
        dll_chars |= 0x0040; // DYNAMIC_BASE
        dll_chars |= 0x0020; // HIGH_ENTROPY_VA
    }
    if dep {
        dll_chars |= 0x0100; // NX_COMPAT
    }
    if cfg {
        dll_chars |= 0x4000; // GUARD_CF
    }
    data[opt + 70..opt + 72].copy_from_slice(&dll_chars.to_le_bytes());
    data[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

    // Load Config Directory entry (Index 10: offset 112 + 10 * 8 = 192)
    if cfg {
        let load_config_rva = 0x1080u32;
        let load_config_size = 128u32;
        data[opt + 192..opt + 196].copy_from_slice(&load_config_rva.to_le_bytes());
        data[opt + 196..opt + 200].copy_from_slice(&load_config_size.to_le_bytes());

        // Place Load Config Directory at raw offset 0x280 (inside .text, diff 0x80 from RVA 0x1000)
        let lc_off = 0x280;
        data[lc_off..lc_off + 4].copy_from_slice(&load_config_size.to_le_bytes()); // Size
        data[lc_off + 88..lc_off + 96].copy_from_slice(&0x140002000u64.to_le_bytes()); // SecurityCookie
        data[lc_off + 112..lc_off + 120].copy_from_slice(&0x140001000u64.to_le_bytes()); // GuardCFCheckFunctionPointer
    }

    // Primary Section: .text
    let sec0 = opt + 240;
    data[sec0..sec0 + 8].copy_from_slice(b".text\0\0\0");
    data[sec0 + 8..sec0 + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
    data[sec0 + 12..sec0 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    data[sec0 + 16..sec0 + 20].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfRawData
    data[sec0 + 20..sec0 + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
    let mut sec_chars = 0x60000020u32; // CODE | EXECUTE | READ
    if rwx {
        sec_chars |= 0x80000000; // MEM_WRITE
    }
    data[sec0 + 36..sec0 + 40].copy_from_slice(&sec_chars.to_le_bytes());

    // Optional extra sections
    for i in 0..extra_sections {
        let sec_i = sec0 + 40 * (i + 1);
        let name = format!(".data{}\0", i);
        let name_bytes = name.as_bytes();
        data[sec_i..sec_i + name_bytes.len().min(8)]
            .copy_from_slice(&name_bytes[..name_bytes.len().min(8)]);
        data[sec_i + 8..sec_i + 12].copy_from_slice(&0x100u32.to_le_bytes());
        let va = 0x2000u32 + (i as u32 * 0x1000);
        data[sec_i + 12..sec_i + 16].copy_from_slice(&va.to_le_bytes());
        data[sec_i + 16..sec_i + 20].copy_from_slice(&0x200u32.to_le_bytes());
        let raw_ptr = 0x600u32 + (i as u32 * 0x200);
        data[sec_i + 20..sec_i + 24].copy_from_slice(&raw_ptr.to_le_bytes());
        data[sec_i + 36..sec_i + 40].copy_from_slice(&0xC0000040u32.to_le_bytes()); // INITIALIZED_DATA | READ | WRITE
    }

    data
}

#[test]
fn test_evaluate_gate_on_synthetic_pe() {
    let hardened_pe = create_synthetic_pe(true, true, true, false, 0);
    let target_file = "target/test_hardened.exe";
    fs::write(target_file, &hardened_pe).expect("write hardened pe");

    let policy = GatePolicy {
        require_aslr: true,
        require_dep: true,
        require_cfg: true,
        disallow_rwx: true,
        ..Default::default()
    };

    let eval = evaluate_gate(target_file, None, &policy).expect("evaluation should run");
    assert!(eval.passed, "synthetic hardened PE must pass gate");
    assert_eq!(eval.findings.len(), 0);

    let _ = fs::remove_file(target_file);
}

#[test]
fn test_evaluate_gate_detects_synthetic_pe_degradation() {
    let baseline_pe = create_synthetic_pe(true, true, true, false, 0);
    let degraded_pe = create_synthetic_pe(false, false, false, false, 0);

    let baseline_file = "target/test_base.exe";
    let degraded_file = "target/test_degraded.exe";
    fs::write(baseline_file, &baseline_pe).expect("write base pe");
    fs::write(degraded_file, &degraded_pe).expect("write degraded pe");

    let policy = GatePolicy {
        fail_on_degraded: true,
        require_aslr: true,
        require_dep: true,
        require_cfg: true,
        ..Default::default()
    };

    let eval =
        evaluate_gate(degraded_file, Some(baseline_file), &policy).expect("evaluation should run");
    assert!(!eval.passed, "degraded PE must FAIL release gate");
    assert!(eval.findings.iter().any(|f| f.rule_id.contains("ASLR")));
    assert!(eval.findings.iter().any(|f| f.rule_id.contains("DEP")));
    assert!(eval.findings.iter().any(|f| f.rule_id.contains("CFG")));

    let _ = fs::remove_file(baseline_file);
    let _ = fs::remove_file(degraded_file);
}

#[test]
fn test_evaluate_gate_detects_synthetic_pe_rwx() {
    let rwx_pe = create_synthetic_pe(true, true, true, true, 0);
    let target_file = "target/test_rwx.exe";
    fs::write(target_file, &rwx_pe).expect("write rwx pe");

    let policy = GatePolicy {
        disallow_rwx: true,
        ..Default::default()
    };

    let eval = evaluate_gate(target_file, None, &policy).expect("evaluation should run");
    assert!(!eval.passed, "synthetic PE with RWX must FAIL release gate");
    assert!(
        eval.findings
            .iter()
            .any(|f| f.rule_id == "BIN004-RWX-SECTION")
    );

    let _ = fs::remove_file(target_file);
}

#[test]
fn test_evaluate_gate_detects_excess_new_sections() {
    let baseline_pe = create_synthetic_pe(true, true, true, false, 0); // 1 section (.text)
    let target_pe = create_synthetic_pe(true, true, true, false, 3); // 4 sections (3 new)

    let baseline_file = "target/test_sections_base.exe";
    let target_file = "target/test_sections_target.exe";
    fs::write(baseline_file, &baseline_pe).expect("write base pe");
    fs::write(target_file, &target_pe).expect("write target pe");

    let policy = GatePolicy {
        max_new_sections: Some(1),
        ..Default::default()
    };

    let eval =
        evaluate_gate(target_file, Some(baseline_file), &policy).expect("evaluation should run");
    assert!(
        !eval.passed,
        "target exceeding max_new_sections must FAIL gate"
    );
    assert!(
        eval.findings
            .iter()
            .any(|f| f.rule_id == "BIN011-EXCESS-NEW-SECTIONS")
    );

    let _ = fs::remove_file(baseline_file);
    let _ = fs::remove_file(target_file);
}
