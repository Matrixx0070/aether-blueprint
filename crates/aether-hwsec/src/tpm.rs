//! TPM 2.0 detection, PCR management, and attestation.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmInfo {
    pub version: String,
    pub firmware: Option<String>,
    pub spec_version: String,
    pub manufacturer: String,
    pub model: String,
    pub handles: Vec<TpmHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmHandle {
    pub handle: String,
    pub type_field: String,
    pub name: String,
    pub persistent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrBank {
    pub bank: String,
    pub pcr_values: Vec<(u32, String)>, // (PCR index, hex hash)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmAttestation {
    pub pcr_quote: String,
    pub nonce: String,
    pub signature: String,
    pub verified: bool,
    pub pcr_banks: Vec<PcrBank>,
}

pub fn detect_tpm() -> Option<TpmInfo> {
    // Check for TPM 2.0 device on Linux
    let tpm_paths = vec![
        "/dev/tpm0",
        "/dev/tpmrm0",
        "/sys/class/tpm/tpm0",
    ];

    for path in tpm_paths {
        if Path::new(path).exists() {
            // Found TPM device
            return Some(TpmInfo {
                version: "2.0".to_string(),
                firmware: Some("2.0".to_string()),
                spec_version: "1.59".to_string(),
                manufacturer: "Generic".to_string(),
                model: "TPM2.0".to_string(),
                handles: vec![],
            });
        }
    }

    None
}

pub fn read_tpm_handles() -> Vec<TpmHandle> {
    // Mock: in production, use tpm2-tools to list handles
    vec![
        TpmHandle {
            handle: "0x81000001".to_string(),
            type_field: "Persistent".to_string(),
            name: "Primary Key".to_string(),
            persistent: true,
        },
        TpmHandle {
            handle: "0x02000001".to_string(),
            type_field: "Transient".to_string(),
            name: "Encryption Key".to_string(),
            persistent: false,
        },
    ]
}

pub fn read_pcr_values() -> Vec<PcrBank> {
    // Mock PCR bank data
    vec![
        PcrBank {
            bank: "SHA256".to_string(),
            pcr_values: vec![
                (0, "0000000000000000000000000000000000000000000000000000000000000000".to_string()),
                (1, "b3b0e4d39ff475abe5812f7c17dc3b1e4a2e9b4a1c3f5d7e9f2a4c6e8b0d2f4".to_string()),
                (2, "e5f5c5d5c5d5c5d5c5d5c5d5c5d5c5d5c5d5c5d5c5d5c5d5c5d5c5d5c5d5c5".to_string()),
            ],
        },
        PcrBank {
            bank: "SHA1".to_string(),
            pcr_values: vec![
                (0, "0000000000000000000000000000000000000000".to_string()),
                (1, "b1234567890abcdef1234567890abcdef1234567".to_string()),
            ],
        },
    ]
}

pub fn generate_pcr_quote(nonce: &str) -> Result<TpmAttestation, String> {
    let pcr_banks = read_pcr_values();

    Ok(TpmAttestation {
        pcr_quote: format!("quote_for_{}", nonce),
        nonce: nonce.to_string(),
        signature: "mock_signature_bytes".to_string(),
        verified: false,
        pcr_banks,
    })
}

pub fn verify_pcr_quote(quote: &TpmAttestation, expected_pcrs: &[(u32, String)]) -> bool {
    // Simplified verification: check that at least one PCR bank matches
    for bank in &quote.pcr_banks {
        for (expected_idx, expected_value) in expected_pcrs {
            if let Some((_idx, actual_value)) = bank.pcr_values.iter()
                .find(|(idx, _)| idx == expected_idx)
            {
                if actual_value == &expected_value.to_lowercase() {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_tpm_handles() {
        let handles = read_tpm_handles();
        assert!(!handles.is_empty());
        assert!(handles.iter().any(|h| h.persistent));
    }

    #[test]
    fn test_read_pcr_values() {
        let banks = read_pcr_values();
        assert!(!banks.is_empty());
        assert!(banks.iter().any(|b| b.bank == "SHA256"));
    }

    #[test]
    fn test_generate_pcr_quote() {
        let quote = generate_pcr_quote("test_nonce").unwrap();
        assert_eq!(quote.nonce, "test_nonce");
        assert!(!quote.pcr_banks.is_empty());
    }
}
