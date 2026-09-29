use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatePolicy {
    /// Fail if any mitigation transitioned from true to false compared to baseline
    #[serde(default = "default_true")]
    pub fail_on_degraded: bool,

    /// Require ASLR / PIE to be enabled on target binary
    #[serde(default = "default_true")]
    pub require_aslr: bool,

    /// Require DEP / NX to be enabled on target binary
    #[serde(default = "default_true")]
    pub require_dep: bool,

    /// Fail if any section is simultaneously writable and executable (W^X violation)
    #[serde(default = "default_true")]
    pub disallow_rwx: bool,

    /// Fail if Authenticode signature is present but digest does not match (tampering)
    #[serde(default = "default_true")]
    pub fail_on_tampered: bool,

    /// Require binary to have an Authenticode signature (default: false, opt-in for Windows release binaries)
    #[serde(default)]
    pub require_authenticode: bool,

    /// Maximum permissible Shannon entropy (e.g. 7.2) before flagging suspicious packing/obfuscation
    pub max_entropy: Option<f64>,

    /// Require Stack Canary / /GS cookie if supported
    #[serde(default)]
    pub require_stack_canary: bool,

    /// Require Control Flow Guard on Windows PE
    #[serde(default)]
    pub require_cfg: bool,

    /// Maximum number of new section additions allowed compared to baseline
    pub max_new_sections: Option<usize>,

    /// Path to YARA rules file or directory to scan target against
    pub yara_rules: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self {
            fail_on_degraded: true,
            require_aslr: true,
            require_dep: true,
            disallow_rwx: true,
            fail_on_tampered: true,
            require_authenticode: false,
            max_entropy: Some(7.5),
            require_stack_canary: false,
            require_cfg: false,
            max_new_sections: None,
            yara_rules: None,
        }
    }
}
