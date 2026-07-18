use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixBundle {
    #[serde(rename = "type")]
    pub bundle_type: String,
    pub id: String,
    pub objects: Vec<StixObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixObject {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "pattern")]
    pub pattern: Option<String>,
    #[serde(rename = "pattern_type")]
    pub pattern_type: Option<String>,
    pub labels: Option<Vec<String>>,
    pub valid_from: Option<DateTime<Utc>>,
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainPhase {
    pub kill_chain_name: String,
    pub phase_name: String,
}

impl StixBundle {
    pub fn parse(json: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let bundle: StixBundle = serde_json::from_str(json)?;
        Ok(bundle)
    }

    pub fn indicators(&self) -> Vec<&StixObject> {
        self.objects
            .iter()
            .filter(|o| o.object_type == "indicator")
            .collect()
    }
}
