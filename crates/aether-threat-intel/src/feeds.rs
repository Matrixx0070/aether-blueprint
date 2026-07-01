//! Threat feed integrations: CISA, VirusTotal, abuse.ch, ThreatFox, Shodan, CIRCL CVE.
//!
//! All external-API functions degrade gracefully:
//!   - Functions requiring an API key return Ok(None) / Ok(vec![]) when the key
//!     is absent (check `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`).
//!   - Functions backed by free public APIs (abuse.ch, ThreatFox, CIRCL) make
//!     real HTTP calls; network errors are surfaced as Err.

use crate::{CisaAdvisory, ThreatIndicator, ThreatLevel};
use anyhow::{anyhow, Result};

// ── CISA KEV ─────────────────────────────────────────────────────────────────

/// Fetch CISA Known Exploited Vulnerabilities catalog.
pub async fn fetch_cisa_kev() -> Result<Vec<CisaAdvisory>> {
    let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .header("User-Agent", "aether-threat-intel/0.36.0")
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

// ── VirusTotal v3 ─────────────────────────────────────────────────────────────

/// Check a file hash or domain/IP against VirusTotal v3.
///
/// Reads `VIRUSTOTAL_API_KEY` env var if `api_key` param is None.
/// Returns `Ok(None)` when no key is configured or the indicator is clean.
pub async fn check_virustotal(
    indicator: &str,
    api_key: Option<&str>,
) -> Result<Option<ThreatIndicator>> {
    let key_owned = api_key
        .map(|k| k.to_string())
        .or_else(|| std::env::var("VIRUSTOTAL_API_KEY").ok());
    let Some(key) = key_owned else {
        return Ok(None);
    };

    // Route by indicator type: 32/40/64 hex chars → file hash; otherwise domain
    let indicator_type;
    let url = if indicator.len() == 32 || indicator.len() == 40 || indicator.len() == 64 {
        indicator_type = crate::IndicatorType::FileHash;
        format!("https://www.virustotal.com/api/v3/files/{indicator}")
    } else if indicator.contains('.') && !indicator.starts_with("http") {
        indicator_type = crate::IndicatorType::Domain;
        format!("https://www.virustotal.com/api/v3/domains/{indicator}")
    } else {
        indicator_type = crate::IndicatorType::Ipv4;
        format!("https://www.virustotal.com/api/v3/ip_addresses/{indicator}")
    };

    let client = reqwest::Client::new();
    let resp = client.get(&url).header("x-apikey", &key).send().await?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(anyhow!("VirusTotal API error: {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await?;
    let stats = data
        .pointer("/data/attributes/last_analysis_stats")
        .cloned()
        .unwrap_or_default();
    let malicious = stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0);
    if malicious == 0 {
        return Ok(None);
    }

    let threat_level = if malicious > 10 {
        ThreatLevel::Critical
    } else if malicious > 5 {
        ThreatLevel::High
    } else {
        ThreatLevel::Medium
    };

    let families: Vec<String> = data
        .pointer("/data/attributes/popular_threat_classification/popular_threat_category")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("value").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(Some(ThreatIndicator {
        indicator_type,
        value: indicator.to_string(),
        threat_level,
        source: "VirusTotal".to_string(),
        last_seen: chrono::Utc::now().to_rfc3339(),
        malware_families: families,
        campaign_ids: vec![],
    }))
}

// ── abuse.ch URLHaus ──────────────────────────────────────────────────────────

/// Look up a file hash (MD5 or SHA256) against the abuse.ch URLHaus payload database.
///
/// No API key required. Uses the free public URLHaus API.
/// `query_status == "is_listed"` → returns ThreatIndicator; `"not_listed"` → None.
pub fn check_abuse_ch(hash: &str) -> Result<Option<ThreatIndicator>> {
    let resp = ureq::post("https://urlhaus-api.abuse.ch/v1/payload/")
        .send_form(&[("hash", hash)])?;
    let body: serde_json::Value = resp.into_json()?;

    let status = body.get("query_status").and_then(|v| v.as_str()).unwrap_or("");
    if status != "is_listed" {
        return Ok(None);
    }

    let family = body
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let urls_count = body.get("urls_count").and_then(|v| v.as_u64()).unwrap_or(0);
    let threat_level = if urls_count > 10 { ThreatLevel::Critical } else { ThreatLevel::High };

    Ok(Some(ThreatIndicator {
        indicator_type: crate::IndicatorType::FileHash,
        value: hash.to_string(),
        threat_level,
        source: "abuse.ch URLHaus".to_string(),
        last_seen: chrono::Utc::now().to_rfc3339(),
        malware_families: vec![family],
        campaign_ids: vec![],
    }))
}

// ── abuse.ch ThreatFox ────────────────────────────────────────────────────────

/// Check a domain/IP/URL against ThreatFox (abuse.ch).
///
/// No API key required. Returns the first matching IOC entry, if any.
pub fn check_c2_infrastructure(ioc: &str) -> Result<Option<ThreatIndicator>> {
    let payload = serde_json::json!({
        "query": "search_ioc",
        "search_term": ioc
    });
    let resp = ureq::post("https://threatfox-api.abuse.ch/api/v1/")
        .set("Content-Type", "application/json")
        .send_json(&payload)?;
    let body: serde_json::Value = resp.into_json()?;

    let query_status = body.get("query_status").and_then(|v| v.as_str()).unwrap_or("");
    if query_status != "ok" {
        return Ok(None);
    }
    let data = match body.get("data").and_then(|v| v.as_array()) {
        Some(arr) if !arr.is_empty() => arr,
        _ => return Ok(None),
    };

    let entry = &data[0];
    let threat_type = entry
        .get("threat_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let malware = entry
        .get("malware")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let confidence = entry
        .get("confidence_level")
        .and_then(|v| v.as_u64())
        .unwrap_or(50);
    let threat_level = if confidence >= 80 {
        ThreatLevel::Critical
    } else if confidence >= 50 {
        ThreatLevel::High
    } else {
        ThreatLevel::Medium
    };
    let ioc_type = entry
        .get("ioc_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let indicator_type = match ioc_type {
        "domain" => crate::IndicatorType::Domain,
        "ip:port" | "ip" => crate::IndicatorType::Ipv4,
        "url" => crate::IndicatorType::Url,
        "md5_hash" | "sha256_hash" => crate::IndicatorType::FileHash,
        _ => crate::IndicatorType::Domain,
    };

    Ok(Some(ThreatIndicator {
        indicator_type,
        value: ioc.to_string(),
        threat_level,
        source: "ThreatFox (abuse.ch)".to_string(),
        last_seen: chrono::Utc::now().to_rfc3339(),
        malware_families: vec![malware.to_string()],
        campaign_ids: vec![threat_type.to_string()],
    }))
}

// ── Shodan ────────────────────────────────────────────────────────────────────

/// Search Shodan for exposed hosts matching `query`.
///
/// Reads `SHODAN_API_KEY` env var if `api_key` param is None.
/// Returns `Ok(vec![])` when no key is configured.
pub async fn query_shodan(query: &str, api_key: Option<&str>) -> Result<Vec<String>> {
    let key_owned = api_key
        .map(|k| k.to_string())
        .or_else(|| std::env::var("SHODAN_API_KEY").ok());
    let Some(key) = key_owned else {
        eprintln!("[aether-threat-intel] SHODAN_API_KEY not set — Shodan search skipped");
        return Ok(vec![]);
    };

    let url = format!(
        "https://api.shodan.io/shodan/host/search?key={}&query={}&minify=true",
        key,
        urlencoding(query),
    );
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("User-Agent", "aether-threat-intel/0.36.0")
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("Shodan API error: {}", resp.status()));
    }
    let data: serde_json::Value = resp.json().await?;
    let hosts: Vec<String> = data
        .get("matches")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    let ip = m.get("ip_str").and_then(|v| v.as_str())?;
                    let port = m.get("port").and_then(|v| v.as_u64())?;
                    Some(format!("{ip}:{port}"))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(hosts)
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                vec![c]
            } else {
                format!("%{:02X}", c as u32).chars().collect::<Vec<_>>()
            }
        })
        .collect()
}

// ── CIRCL CVE / ExploitDB ────────────────────────────────────────────────────

/// Fetch known exploit references for a CVE via the CIRCL CVE API (free, no key).
///
/// Returns URLs of known exploit write-ups or PoC references from NVD/CVE metadata.
pub async fn fetch_exploitdb_by_cve(cve_id: &str) -> Result<Vec<String>> {
    let url = format!("https://cve.circl.lu/api/cve/{cve_id}");
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("User-Agent", "aether-threat-intel/0.36.0")
        .send()
        .await?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(vec![]);
    }
    if !resp.status().is_success() {
        return Err(anyhow!("CIRCL CVE API error: {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await?;
    let exploit_keywords = ["exploit", "poc", "proof-of-concept", "metasploit", "github.com/"];

    let refs: Vec<String> = data
        .get("references")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| r.as_str().map(String::from))
                .filter(|url| {
                    let lower = url.to_lowercase();
                    exploit_keywords.iter().any(|kw| lower.contains(kw))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoding_spaces_and_colons() {
        let encoded = urlencoding("RDP port:3389");
        assert!(encoded.contains("%20") || !encoded.contains(' '));
        assert!(!encoded.contains(':') || encoded.contains("%3A"));
    }

    #[test]
    fn check_virustotal_no_key_returns_none() {
        // Without an API key and with no VIRUSTOTAL_API_KEY env var, should return None.
        // We temporarily clear the env var for this test.
        std::env::remove_var("VIRUSTOTAL_API_KEY");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(check_virustotal("abc123", None)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn query_shodan_no_key_returns_empty() {
        std::env::remove_var("SHODAN_API_KEY");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(query_shodan("RDP", None)).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    #[ignore = "requires network: abuse.ch URLHaus"]
    fn check_abuse_ch_unknown_hash_not_listed() {
        // A known-clean hash (SHA256 of "hello") should not be in URLHaus.
        let result = check_abuse_ch(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    #[ignore = "requires network: ThreatFox"]
    fn check_c2_unknown_domain_not_listed() {
        let result = check_c2_infrastructure("example.com").unwrap();
        // example.com is unlikely to be in ThreatFox
        assert!(result.is_none());
    }

    #[test]
    #[ignore = "requires network: CIRCL CVE API"]
    fn fetch_exploitdb_unknown_cve_returns_empty() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(fetch_exploitdb_by_cve("CVE-0000-00000")).unwrap();
        assert!(result.is_empty());
    }
}
