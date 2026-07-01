//! Threat feed integrations: CISA, VirusTotal, abuse.ch, Shodan.

use crate::{CisaAdvisory, ThreatIndicator, ThreatLevel};
use anyhow::{anyhow, Result};

/// Fetch CISA Known Exploited Vulnerabilities
pub async fn fetch_cisa_kev() -> Result<Vec<CisaAdvisory>> {
    let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .header("User-Agent", "aether-threat-intel/0.35.0")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow!("CISA KEV fetch failed: {}", response.status()));
    }

    let data: serde_json::Value = response.json().await?;
    let mut advisories = Vec::new();

    if let Some(vulns) = data.get("vulnerabilities").and_then(|v| v.as_array()) {
        for vuln in vulns {
            if let Some(cisa_id) = vuln.get("cveID").and_then(|v| v.as_str()) {
                let advisory = CisaAdvisory {
                    cisa_id: cisa_id.to_string(),
                    title: vuln.get("shortDescription")
                        .and_then(|v| v.as_str())
                        .unwrap_or("N/A")
                        .to_string(),
                    description: vuln.get("shortDescription")
                        .and_then(|v| v.as_str())
                        .unwrap_or("N/A")
                        .to_string(),
                    cvss_score: None,
                    affected_products: vec![],
                    remediation: "See CISA website".to_string(),
                    known_exploited: true,
                };
                advisories.push(advisory);
            }
        }
    }

    Ok(advisories)
}

/// Check indicator against VirusTotal (mock for offline support)
pub async fn check_virustotal(indicator: &str, _api_key: Option<&str>) -> Result<Option<ThreatIndicator>> {
    // In production, this would call VirusTotal API if api_key provided
    // For now, return mock data or None if no API key

    if _api_key.is_none() {
        return Ok(None);
    }

    // Mock detection database
    let known_bad = vec![
        ("trojan.generi", ThreatLevel::Critical),
        ("backdoor.apt28", ThreatLevel::Critical),
        ("worm.emotet", ThreatLevel::High),
    ];

    for (sig, level) in known_bad {
        if indicator.to_lowercase().contains(sig) {
            return Ok(Some(ThreatIndicator {
                indicator_type: crate::IndicatorType::Filename,
                value: indicator.to_string(),
                threat_level: level,
                source: "VirusTotal".to_string(),
                last_seen: chrono::Utc::now().to_rfc3339(),
                malware_families: vec![sig.to_string()],
                campaign_ids: vec![],
            }));
        }
    }

    Ok(None)
}

/// Check for malware signatures from abuse.ch
pub fn check_abuse_ch(hash: &str) -> Result<Option<ThreatIndicator>> {
    // Mock urlhaus database (in production, query https://urlhaus-api.abuse.ch/v1/urls/recent/)

    let known_hashes = vec![
        ("d41d8cd98f00b204e9800998ecf8427e", "emotet_dropper"),
        ("e3b0c44298fc1c149afbf4c8996fb924", "qbot_loader"),
    ];

    for (stored_hash, family) in known_hashes {
        if hash.to_lowercase() == stored_hash {
            return Ok(Some(ThreatIndicator {
                indicator_type: crate::IndicatorType::FileHash,
                value: hash.to_string(),
                threat_level: ThreatLevel::Critical,
                source: "abuse.ch".to_string(),
                last_seen: chrono::Utc::now().to_rfc3339(),
                malware_families: vec![family.to_string()],
                campaign_ids: vec![],
            }));
        }
    }

    Ok(None)
}

/// Check for C2 infrastructure from open threat feeds (mock)
pub fn check_c2_infrastructure(domain: &str) -> Result<Option<ThreatIndicator>> {
    // Mock C2 domain database
    let c2_domains = vec![
        "malicious-c2.ru",
        "apt28-server.net",
        "lazarus-beacon.top",
    ];

    for c2_domain in c2_domains {
        if domain.to_lowercase().contains(c2_domain) {
            return Ok(Some(ThreatIndicator {
                indicator_type: crate::IndicatorType::Domain,
                value: domain.to_string(),
                threat_level: ThreatLevel::Critical,
                source: "C2 Infrastructure Tracker".to_string(),
                last_seen: chrono::Utc::now().to_rfc3339(),
                malware_families: vec!["apt28".to_string()],
                campaign_ids: vec!["operation-stealth".to_string()],
            }));
        }
    }

    Ok(None)
}

/// Query Shodan for exposed services (mock -- requires Shodan API key in production)
pub async fn query_shodan(query: &str, _api_key: Option<&str>) -> Result<Vec<String>> {
    // In production: https://api.shodan.io/shodan/host/search?key=KEY&query=QUERY
    // For now, return mock results

    if _api_key.is_none() {
        return Ok(vec![]);
    }

    let mock_results = if query.contains("RDP") {
        vec!["192.168.1.100:3389", "10.0.0.50:3389"]
            .iter().map(|s| s.to_string()).collect()
    } else if query.contains("SSH") {
        vec!["203.0.113.10:22", "198.51.100.20:22"]
            .iter().map(|s| s.to_string()).collect()
    } else {
        vec![]
    };

    Ok(mock_results)
}

/// Fetch exploit-db exploits by CVE
pub async fn fetch_exploitdb_by_cve(cve_id: &str) -> Result<Vec<String>> {
    // Mock exploit database
    let exploits = match cve_id {
        "CVE-2024-1234" => vec![
            "PoC available on GitHub".to_string(),
            "Metasploit module exists".to_string(),
        ],
        "CVE-2023-5678" => vec![
            "Public exploit code published".to_string(),
        ],
        _ => vec![],
    };

    Ok(exploits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_abuse_ch() {
        let result = check_abuse_ch("d41d8cd98f00b204e9800998ecf8427e").unwrap();
        assert!(result.is_some());
        let indicator = result.unwrap();
        assert_eq!(indicator.malware_families[0], "emotet_dropper");
    }

    #[test]
    fn test_check_c2_infrastructure() {
        let result = check_c2_infrastructure("apt28-server.net").unwrap();
        assert!(result.is_some());
        let indicator = result.unwrap();
        assert_eq!(indicator.threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn test_fetch_exploitdb() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(fetch_exploitdb_by_cve("CVE-2024-1234")).unwrap();
        assert!(!result.is_empty());
    }
}
