//! APT nation-state attribution, targeting detection, and C2 identification.

use crate::{AptGroup, ThreatLevel, ThreatIndicator};

/// Known APT groups and their targeting patterns
pub fn get_apt_database() -> Vec<AptGroup> {
    vec![
        AptGroup {
            name: "APT28".to_string(),
            nation_state: "Russia (FSB/GRU)".to_string(),
            founded: Some("2007".to_string()),
            known_targets: vec![
                "Defense contractors".to_string(),
                "Government agencies".to_string(),
                "Think tanks".to_string(),
                "NATO members".to_string(),
            ],
            c2_infrastructure: vec![
                "apt28-server.net".to_string(),
                "stealth-beacon.ru".to_string(),
            ],
            malware_tools: vec![
                "CHOPSTICK".to_string(),
                "JHUHUGIT".to_string(),
                "CORESHELL".to_string(),
            ],
            ttps: vec![
                "T1566.002".to_string(), // Phishing: Spearphishing Link
                "T1566.001".to_string(), // Phishing: Spearphishing Attachment
                "T1087.004".to_string(), // Account Discovery: Domain Account
                "T1087.001".to_string(), // Account Discovery: Local Account
            ],
        },
        AptGroup {
            name: "Lazarus".to_string(),
            nation_state: "North Korea (DPRK)".to_string(),
            founded: Some("2009".to_string()),
            known_targets: vec![
                "Financial institutions".to_string(),
                "Cryptocurrency exchanges".to_string(),
                "Sony Pictures".to_string(),
                "US government".to_string(),
            ],
            c2_infrastructure: vec![
                "lazarus-beacon.top".to_string(),
                "dprk-command-center.com".to_string(),
            ],
            malware_tools: vec![
                "DESTOVER".to_string(),
                "HANG FISH".to_string(),
                "MATA".to_string(),
            ],
            ttps: vec![
                "T1486".to_string(), // Data Encrypted for Impact
                "T1565.001".to_string(), // Data Destruction: Stored Data Destruction
                "T1561.002".to_string(), // Disk Wipe: Disk Structure Wipe
            ],
        },
        AptGroup {
            name: "APT1 (Comment Crew)".to_string(),
            nation_state: "China (PLA Unit 61398)".to_string(),
            founded: Some("2006".to_string()),
            known_targets: vec![
                "Intellectual property theft".to_string(),
                "Defense contractors".to_string(),
                "Energy sector".to_string(),
                "Technology companies".to_string(),
            ],
            c2_infrastructure: vec![
                "apt1-infrastructure.cn".to_string(),
            ],
            malware_tools: vec![
                "POISON IVY".to_string(),
                "WEBC2".to_string(),
            ],
            ttps: vec![
                "T1041".to_string(), // Exfiltration Over C2 Channel
                "T1074.001".to_string(), // Data Staged: Local Data Staging
            ],
        },
    ]
}

/// Analyze targeting patterns and return confidence score
pub fn analyze_targeting(
    victim_org: &str,
    victim_sector: &str,
    _sample_behavior: &str,
) -> (Option<String>, f64) {
    // Simplified targeting pattern matcher
    let high_value_targets = vec![
        ("defense", "defense contractor"),
        ("government", "us government"),
        ("state department", "us government"),
        ("nato", "nato member"),
        ("finance", "financial institution"),
        ("bank", "financial institution"),
        ("energy", "energy sector"),
        ("power plant", "energy sector"),
    ];

    let victim_lower = format!("{} {}", victim_org, victim_sector).to_lowercase();

    for (pattern, _description) in high_value_targets {
        if victim_lower.contains(pattern) {
            return (Some("APT1".to_string()), 0.75); // Simple heuristic
        }
    }

    (None, 0.0)
}

/// Detect C2 beaconing behavior from network logs
pub fn detect_c2_beaconing(network_flows: &[(String, u16, String)]) -> Vec<(String, f64)> {
    // Mock C2 detection: look for suspicious patterns
    // Format: (destination_ip, destination_port, protocol)

    let mut suspects = Vec::new();

    for (dest_ip, port, protocol) in network_flows {
        // Known C2 infrastructure
        if dest_ip.contains("apt28-server") || dest_ip.contains("lazarus-beacon") {
            suspects.push((dest_ip.clone(), 0.95));
        }

        // Suspicious port patterns
        if *port == 8080 || *port == 8443 || *port == 4444 {
            if protocol == "TCP" {
                suspects.push((dest_ip.clone(), 0.65));
            }
        }

        // Rare ports that indicate custom C2
        if *port > 10000 && protocol == "TCP" {
            suspects.push((dest_ip.clone(), 0.55));
        }
    }

    suspects
}

/// Score malware family based on prevalence and sophistication
pub fn score_malware_threat(family: &str) -> (ThreatLevel, f64) {
    match family.to_lowercase().as_str() {
        "emotet" => (ThreatLevel::Critical, 0.95),
        "dridex" => (ThreatLevel::Critical, 0.90),
        "apt28" => (ThreatLevel::Critical, 0.92),
        "lazarus" => (ThreatLevel::Critical, 0.93),
        "trickbot" => (ThreatLevel::High, 0.85),
        "qbot" => (ThreatLevel::High, 0.80),
        _ => (ThreatLevel::Medium, 0.50),
    }
}

/// Correlate multiple indicators to generate confidence score
pub fn correlate_indicators(indicators: &[&ThreatIndicator]) -> f64 {
    if indicators.is_empty() {
        return 0.0;
    }

    let mut score: f64 = 0.0;
    let mut count: f64 = 0.0;

    for indicator in indicators {
        match indicator.threat_level {
            ThreatLevel::Critical => score += 0.95,
            ThreatLevel::High => score += 0.75,
            ThreatLevel::Medium => score += 0.50,
            ThreatLevel::Low => score += 0.25,
            ThreatLevel::Info => score += 0.10,
        }
        count += 1.0;

        // Multiple malware families increases confidence
        score += (indicator.malware_families.len() as f64) * 0.1;

        // Campaign attribution increases confidence
        score += (indicator.campaign_ids.len() as f64) * 0.15;
    }

    // Normalize and cap at 1.0
    ((score / count.max(1.0)).min(1.0) * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_apt_database() {
        let apts = get_apt_database();
        assert!(apts.len() >= 3);
        assert!(apts.iter().any(|a| a.name == "APT28"));
    }

    #[test]
    fn test_analyze_targeting() {
        let (_apt, score) = analyze_targeting("US Defense", "contractor", "");
        assert!(score > 0.0);
    }

    #[test]
    fn test_detect_c2_beaconing() {
        let flows = vec![
            ("apt28-server.net".to_string(), 443, "TCP".to_string()),
            ("203.0.113.1".to_string(), 15000, "TCP".to_string()),
        ];
        let suspects = detect_c2_beaconing(&flows);
        assert!(!suspects.is_empty());
    }

    #[test]
    fn test_score_malware_threat() {
        let (level, score) = score_malware_threat("emotet");
        assert_eq!(level, ThreatLevel::Critical);
        assert!(score > 0.9);
    }

    #[test]
    fn test_correlate_indicators() {
        let indicator = ThreatIndicator {
            indicator_type: crate::IndicatorType::Domain,
            value: "test.com".to_string(),
            threat_level: ThreatLevel::Critical,
            source: "test".to_string(),
            last_seen: "2024-01-01".to_string(),
            malware_families: vec!["apt28".to_string()],
            campaign_ids: vec!["op1".to_string()],
        };
        let indicators = vec![&indicator];
        let score = correlate_indicators(&indicators);
        assert!(score > 0.0 && score <= 1.0);
    }
}
