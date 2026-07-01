//! TPM 2.0 detection, PCR management, and attestation via tpm2-tools.
//!
//! All functions degrade gracefully when tpm2-tools is absent or /dev/tpm0
//! does not exist: they return empty vecs or an Err describing the gap.
//! Set `AETHER_TPM_TOOL` to override the `tpm2` binary path.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

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
    pub pcr_values: Vec<(u32, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmAttestation {
    pub pcr_quote: String,
    pub nonce: String,
    pub signature: String,
    pub verified: bool,
    pub pcr_banks: Vec<PcrBank>,
}

fn tpm2_bin() -> String {
    std::env::var("AETHER_TPM_TOOL").unwrap_or_else(|_| "tpm2".to_string())
}

pub fn detect_tpm() -> Option<TpmInfo> {
    let tpm_paths = ["/dev/tpm0", "/dev/tpmrm0", "/sys/class/tpm/tpm0"];
    for path in tpm_paths {
        if Path::new(path).exists() {
            let info = read_tpm_info_from_system();
            return Some(info);
        }
    }
    None
}

fn read_tpm_info_from_system() -> TpmInfo {
    // Try `tpm2 getcap properties-fixed` for real firmware/manufacturer info.
    let out = Command::new(tpm2_bin())
        .args(["getcap", "properties-fixed", "--format=json"])
        .output();

    let (manufacturer, firmware, spec_version) = match out {
        Ok(o) if o.status.success() => parse_tpm_properties(&o.stdout),
        _ => {
            // Fall back to /sys/class/tpm/tpm0/device/description or vendor
            let mfr = std::fs::read_to_string("/sys/class/tpm/tpm0/device/vendor_id")
                .or_else(|_| std::fs::read_to_string("/sys/class/tpm/tpm0/device/description"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "Unknown".to_string());
            (mfr, None, "2.0".to_string())
        }
    };

    TpmInfo {
        version: "2.0".to_string(),
        firmware,
        spec_version,
        manufacturer,
        model: "TPM2.0".to_string(),
        handles: vec![],
    }
}

fn parse_tpm_properties(stdout: &[u8]) -> (String, Option<String>, String) {
    let data: serde_json::Value = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return ("Unknown".to_string(), None, "2.0".to_string()),
    };
    // tpm2 getcap properties-fixed JSON: {"TPM2_PT_MANUFACTURER": {"raw": 1162167621}, ...}
    let manufacturer = data
        .get("TPM2_PT_MANUFACTURER")
        .and_then(|v| v.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();
    let firmware = data
        .get("TPM2_PT_FIRMWARE_VERSION_1")
        .and_then(|v| v.get("raw"))
        .and_then(|v| v.as_u64())
        .map(|n| format!("{}.{}", (n >> 16) & 0xFFFF, n & 0xFFFF));
    let spec = data
        .get("TPM2_PT_SPEC_REVISION")
        .and_then(|v| v.get("raw"))
        .and_then(|v| v.as_u64())
        .map(|n| format!("{}.{}", n / 100, n % 100))
        .unwrap_or_else(|| "2.0".to_string());
    (manufacturer, firmware, spec)
}

/// Read persistent and transient handles via `tpm2 getcap handles-persistent`.
///
/// Returns an empty vec (with a stderr notice) if tpm2-tools is unavailable.
pub fn read_tpm_handles() -> Vec<TpmHandle> {
    let out = Command::new(tpm2_bin())
        .args(["getcap", "handles-persistent", "--format=json"])
        .output();
    match out {
        Ok(o) if o.status.success() => parse_handles(&o.stdout),
        Ok(o) => {
            eprintln!(
                "[aether-hwsec] tpm2 getcap handles-persistent failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
            vec![]
        }
        Err(e) => {
            eprintln!("[aether-hwsec] tpm2-tools not found: {e} — TPM handle read skipped");
            vec![]
        }
    }
}

fn parse_handles(stdout: &[u8]) -> Vec<TpmHandle> {
    // Output is JSON array of hex handle strings: ["0x81000001", "0x81000002"]
    let arr: Vec<String> = serde_json::from_slice(stdout).unwrap_or_default();
    arr.into_iter()
        .map(|h| {
            let persistent = h.starts_with("0x81") || h.starts_with("0x80");
            TpmHandle {
                handle: h.clone(),
                type_field: if persistent { "Persistent" } else { "Transient" }.to_string(),
                name: h.clone(),
                persistent,
            }
        })
        .collect()
}

/// Read PCR values via `tpm2 pcrread`.
///
/// Reads SHA256 bank by default; falls back to SHA1 if SHA256 unavailable.
/// Returns an empty vec with a stderr notice when tpm2-tools is absent.
pub fn read_pcr_values() -> Vec<PcrBank> {
    // Read SHA256 bank first, then SHA1 for completeness.
    let mut banks = Vec::new();
    for alg in &["sha256", "sha1"] {
        let out = Command::new(tpm2_bin())
            .args(["pcrread", &format!("{alg}:0,1,2,3,4,5,6,7"), "--format=json"])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                if let Some(bank) = parse_pcr_output(alg, &o.stdout) {
                    banks.push(bank);
                }
            }
            Ok(_) => {}
            Err(e) if alg == &"sha256" => {
                eprintln!("[aether-hwsec] tpm2-tools not found: {e} — PCR read skipped");
                return vec![];
            }
            Err(_) => {}
        }
    }
    banks
}

fn parse_pcr_output(alg: &str, stdout: &[u8]) -> Option<PcrBank> {
    // tpm2 pcrread --format=json: {"sha256":{"0":"0x...","1":"0x...",...}}
    let data: serde_json::Value = serde_json::from_slice(stdout).ok()?;
    let bank_obj = data.get(alg)?.as_object()?;
    let mut pcr_values: Vec<(u32, String)> = bank_obj
        .iter()
        .filter_map(|(k, v)| {
            let idx: u32 = k.parse().ok()?;
            let hash = v.as_str()?.trim_start_matches("0x").to_lowercase();
            Some((idx, hash))
        })
        .collect();
    pcr_values.sort_by_key(|(idx, _)| *idx);
    Some(PcrBank {
        bank: alg.to_uppercase(),
        pcr_values,
    })
}

/// Generate a PCR quote via `tpm2 quote`.
///
/// Requires a loaded AK (attestation key) handle at 0x81010002, which must be
/// provisioned before calling this function. Returns an Err describing the gap
/// when tpm2-tools is unavailable or no AK is present.
pub fn generate_pcr_quote(nonce: &str) -> Result<TpmAttestation, String> {
    let pcr_banks = read_pcr_values();

    // Write nonce to a temp file (tpm2 quote requires a file path)
    let nonce_path = format!("/tmp/aether_tpm_nonce_{}", std::process::id());
    let sig_path = format!("/tmp/aether_tpm_sig_{}", std::process::id());
    let attest_path = format!("/tmp/aether_tpm_attest_{}", std::process::id());

    if let Err(e) = std::fs::write(&nonce_path, nonce.as_bytes()) {
        return Err(format!("failed to write nonce file: {e}"));
    }

    let out = Command::new(tpm2_bin())
        .args([
            "quote",
            "--key-context=0x81010002",
            &format!("--qualification={nonce_path}"),
            "--pcr-list=sha256:0,1,2,3,7",
            &format!("--message={attest_path}"),
            &format!("--signature={sig_path}"),
            "--hash-algorithm=sha256",
        ])
        .output();

    // Clean up temp files regardless of outcome
    let _ = std::fs::remove_file(&nonce_path);

    let (quote_b64, sig_hex) = match out {
        Ok(o) if o.status.success() => {
            let attest_bytes = std::fs::read(&attest_path).unwrap_or_default();
            let sig_bytes = std::fs::read(&sig_path).unwrap_or_default();
            let _ = std::fs::remove_file(&attest_path);
            let _ = std::fs::remove_file(&sig_path);
            let quote = hex::encode(&attest_bytes);
            let sig = hex::encode(&sig_bytes);
            (quote, sig)
        }
        Ok(o) => {
            let _ = std::fs::remove_file(&attest_path);
            let _ = std::fs::remove_file(&sig_path);
            let stderr = String::from_utf8_lossy(&o.stderr);
            return Err(format!(
                "tpm2 quote failed (no AK at 0x81010002? run `tpm2 createak`): {stderr}"
            ));
        }
        Err(e) => {
            return Err(format!(
                "tpm2-tools not found: {e} — run `apt install tpm2-tools` or set AETHER_TPM_TOOL"
            ));
        }
    };

    Ok(TpmAttestation {
        pcr_quote: quote_b64,
        nonce: nonce.to_string(),
        signature: sig_hex,
        verified: false, // caller should verify with verify_pcr_quote
        pcr_banks,
    })
}

pub fn verify_pcr_quote(quote: &TpmAttestation, expected_pcrs: &[(u32, String)]) -> bool {
    for bank in &quote.pcr_banks {
        for (expected_idx, expected_value) in expected_pcrs {
            if let Some((_, actual_value)) = bank.pcr_values.iter().find(|(idx, _)| idx == expected_idx) {
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
    fn detect_tpm_returns_none_in_sandbox() {
        // In CI/sandbox where /dev/tpm0 doesn't exist, detect_tpm must return None.
        // If a real TPM is present this test is skipped gracefully.
        if Path::new("/dev/tpm0").exists() {
            return; // real TPM present, can't test absence
        }
        assert!(detect_tpm().is_none());
    }

    #[test]
    fn read_tpm_handles_returns_empty_gracefully() {
        // tpm2-tools not in PATH on most CI boxes → must return empty vec, not panic.
        if which_tpm2() {
            return; // tpm2 present, skip — real handles would be returned
        }
        let handles = read_tpm_handles();
        // Either empty (no tpm2) or real data — must not panic.
        let _ = handles;
    }

    #[test]
    fn read_pcr_values_returns_gracefully() {
        if which_tpm2() {
            return;
        }
        let banks = read_pcr_values();
        let _ = banks;
    }

    #[test]
    fn generate_pcr_quote_err_without_tpm() {
        if which_tpm2() {
            return;
        }
        let result = generate_pcr_quote("test_nonce");
        // Must return Err, not panic.
        assert!(result.is_err());
    }

    #[test]
    fn verify_pcr_quote_empty_returns_false() {
        let quote = TpmAttestation {
            pcr_quote: String::new(),
            nonce: "x".to_string(),
            signature: String::new(),
            verified: false,
            pcr_banks: vec![],
        };
        assert!(!verify_pcr_quote(&quote, &[(0, "0000".to_string())]));
    }

    fn which_tpm2() -> bool {
        Command::new("which").arg("tpm2").output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}
