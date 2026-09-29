use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription", skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifReportingConfiguration,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReportingConfiguration {
    pub level: String, // "error", "warning", "note"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String, // "error", "warning", "note"
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

impl Default for SarifLog {
    fn default() -> Self {
        Self::new()
    }
}

impl SarifLog {
    pub fn new() -> Self {

        Self {
            schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "relgate".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://github.com/raidshadowmc-sudo/relgate".to_string(),
                        rules: Vec::new(),
                    },
                },
                results: Vec::new(),
            }],
        }
    }

    pub fn add_rule(
        &mut self,
        id: &str,
        name: &str,
        short_desc: &str,
        full_desc: Option<&str>,
        default_level: &str,
    ) {
        let driver = &mut self.runs[0].tool.driver;
        if !driver.rules.iter().any(|r| r.id == id) {
            driver.rules.push(SarifRule {
                id: id.to_string(),
                name: name.to_string(),
                short_description: SarifMessage {
                    text: short_desc.to_string(),
                },
                full_description: full_desc.map(|d| SarifMessage {
                    text: d.to_string(),
                }),
                default_configuration: SarifReportingConfiguration {
                    level: default_level.to_string(),
                },
                help_uri: Some(
                    "https://github.com/raidshadowmc-sudo/relgate#security-rules".to_string(),
                ),
            });
        }
    }

    pub fn add_result(&mut self, rule_id: &str, level: &str, message: &str, file_uri: &str) {
        let normalized_uri = file_uri.replace('\\', "/");
        self.runs[0].results.push(SarifResult {
            rule_id: rule_id.to_string(),
            level: level.to_string(),
            message: SarifMessage {
                text: message.to_string(),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: normalized_uri,
                    },
                },
            }],
        });
    }
}
