//! Hardware security: TPM 2.0, Intel SGX, AMD SEV-SNP, Secure Enclave, TrustZone.
//!
//! TIER 15a: Hardware-backed cryptography (TPM, SGX, SEV-SNP, etc.)
//! TIER 15b: Side-channel resistance (timing attacks, cache attacks)

use serde::{Deserialize, Serialize};

pub mod tpm;
pub mod tee;
pub mod sidechannel;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HardwareSecurityCapability {
    Tpm2_0,
    IntelSgx,
    IntelTdx,
    AmdSevSnp,
    ArmTrustZone,
    AppleSecureEnclave,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSecurityProfile {
    pub device: String,
    pub capabilities: Vec<HardwareSecurityCapability>,
    pub tpm_present: bool,
    pub tpm_version: Option<String>,
    pub tee_type: Option<String>,
    pub secure_boot_enabled: bool,
    pub dma_protection: bool,
    pub iommu_enabled: bool,
    pub kernel_integrity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideChannelRisk {
    pub attack_type: String,
    pub severity: String,
    pub affected_operation: String,
    pub mitigation: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptographicSecurityCert {
    pub algorithm: String,
    pub key_size: u32,
    pub implementation: String,
    pub side_channel_resistant: bool,
    pub fips_approved: bool,
    pub post_quantum_candidate: bool,
    pub audit_timestamp: String,
}

impl HardwareSecurityProfile {
    pub fn new(device: impl Into<String>) -> Self {
        Self {
            device: device.into(),
            capabilities: Vec::new(),
            tpm_present: false,
            tpm_version: None,
            tee_type: None,
            secure_boot_enabled: false,
            dma_protection: false,
            iommu_enabled: false,
            kernel_integrity: false,
        }
    }

    pub fn add_capability(&mut self, cap: HardwareSecurityCapability) {
        if !self.capabilities.contains(&cap) {
            self.capabilities.push(cap);
        }
    }

    pub fn has_capability(&self, cap: &HardwareSecurityCapability) -> bool {
        self.capabilities.contains(cap)
    }

    pub fn security_score(&self) -> f64 {
        let mut score = 0.0;

        // Hardware capabilities (40% of score)
        score += (self.capabilities.len() as f64) * 8.0;

        // Platform features
        if self.tpm_present { score += 10.0; }
        if self.secure_boot_enabled { score += 10.0; }
        if self.dma_protection { score += 10.0; }
        if self.iommu_enabled { score += 10.0; }
        if self.kernel_integrity { score += 10.0; }

        score.min(100.0)
    }
}
