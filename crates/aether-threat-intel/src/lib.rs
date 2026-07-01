//! Threat intelligence feeds and nation-state APT attribution.
//!
//! TIER 14a: Real-time threat feeds (CISA, FBI, MITRE ATT&CK, VirusTotal)
//! TIER 14b: APT attribution (nation-state targeting detection, C2 detection)

use serde::{Deserialize, Serialize};

pub mod feeds;
pub mod apt;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatLevel {
    Critical,
    High,
    #[default]
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub threat_level: ThreatLevel,
    pub source: String,
    pub last_seen: String,
    pub malware_families: Vec<String>,
    pub campaign_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IndicatorType {
    Ipv4,
    Ipv6,
    Domain,
    FileHash,
    Url,
    EmailAddress,
    FileSize,
    Filename,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisaAdvisory {
    pub cisa_id: String,
    pub title: String,
    pub description: String,
    pub cvss_score: Option<f64>,
    pub affected_products: Vec<String>,
    pub remediation: String,
    pub known_exploited: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AptGroup {
    pub name: String,
    pub nation_state: String,
    pub founded: Option<String>,
    pub known_targets: Vec<String>,
    pub c2_infrastructure: Vec<String>,
    pub malware_tools: Vec<String>,
    pub ttps: Vec<String>, // MITRE ATT&CK TTPs
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReport {
    pub id: String,
    pub timestamp: String,
    pub indicators: Vec<ThreatIndicator>,
    pub related_cisa: Vec<CisaAdvisory>,
    pub attributed_apt: Option<AptGroup>,
    pub confidence_score: f64,
    pub summary: String,
}


impl ThreatReport {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            indicators: Vec::new(),
            related_cisa: Vec::new(),
            attributed_apt: None,
            confidence_score: 0.0,
            summary: String::new(),
        }
    }

    pub fn add_indicator(&mut self, indicator: ThreatIndicator) {
        self.indicators.push(indicator);
    }

    pub fn add_cisa(&mut self, advisory: CisaAdvisory) {
        self.related_cisa.push(advisory);
    }

    pub fn set_apt_attribution(&mut self, apt: AptGroup, confidence: f64) {
        self.attributed_apt = Some(apt);
        self.confidence_score = confidence;
    }
}
