pub mod prelude;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmStatus {
    pub version: String,
    pub manufacturer: String,
    pub pcr_bank: String,
    pub sealed_keys: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedKey {
    pub key_id: String,
    pub pcr_mask: Vec<u32>,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    pub index: u32,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    pub nonce: Vec<u8>,
    pub pcr_values: Vec<PcrValue>,
    pub signature: String,
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmGuardError {
    pub message: String,
    pub code: u32,
}

pub struct TpmGuard {
    status: TpmStatus,
    sealed_keys: HashMap<String, SealedKey>,
    pcr_snapshot: Vec<PcrValue>,
    detection_count: u64,
}

impl TpmGuard {
    pub fn new() -> Self {
        info!("Initializing TPM Guard");
        let status = TpmStatus {
            version: "2.0".to_string(),
            manufacturer: "IFX".to_string(),
            pcr_bank: "SHA-256".to_string(),
            sealed_keys: 0,
        };

        let pcr_snapshot = (0..24)
            .map(|i| PcrValue {
                index: i,
                hash: format!("{:064x}", (i as u64).wrapping_mul(0xabcdef1234567890)),
            })
            .collect();

        Self {
            status,
            sealed_keys: HashMap::new(),
            pcr_snapshot,
            detection_count: 0,
        }
    }

    pub fn check_status(&self) -> TpmStatus {
        TpmStatus {
            version: self.status.version.clone(),
            manufacturer: self.status.manufacturer.clone(),
            pcr_bank: self.status.pcr_bank.clone(),
            sealed_keys: self.sealed_keys.len() as u32,
        }
    }

    pub fn seal_key(&mut self, key_id: &str, pcr_mask: Vec<u32>) -> bool {
        if self.sealed_keys.contains_key(key_id) {
            warn!(key_id = key_id, "Key already sealed");
            return false;
        }

        let sealed = SealedKey {
            key_id: key_id.to_string(),
            pcr_mask,
            created: Utc::now(),
        };

        info!(key_id = key_id, "Key sealed successfully");
        self.sealed_keys.insert(key_id.to_string(), sealed);
        self.status.sealed_keys = self.sealed_keys.len() as u32;
        true
    }

    pub fn unseal_key(&mut self, key_id: &str, pcr_values: &[PcrValue]) -> Option<Vec<u8>> {
        let sealed = match self.sealed_keys.get(key_id) {
            Some(k) => k.clone(),
            None => {
                warn!(key_id = key_id, "Key not found for unsealing");
                return None;
            }
        };

        let mut pcr_match = true;
        for &idx in &sealed.pcr_mask {
            if let Some(pcr) = pcr_values.iter().find(|p| p.index == idx) {
                if let Some(current) = self.pcr_snapshot.iter().find(|p| p.index == idx) {
                    if pcr.hash != current.hash {
                        pcr_match = false;
                        break;
                    }
                }
            }
        }

        if !pcr_match {
            warn!(key_id = key_id, "PCR values mismatch, unsealing denied");
            self.detection_count += 1;
            return None;
        }

        info!(key_id = key_id, "Key unsealed successfully");
        let key_material = key_id.as_bytes().to_vec();
        self.sealed_keys.remove(key_id);
        self.status.sealed_keys = self.sealed_keys.len() as u32;
        Some(key_material)
    }

    pub fn verify_attestation(&self, nonce: &[u8]) -> Option<AttestationReport> {
        if nonce.is_empty() {
            warn!("Empty nonce provided for attestation");
            return None;
        }

        let pcr_values = self.pcr_snapshot.clone();
        let signature = format!(
            "tpm_quote_{:064x}",
            nonce.iter().fold(0u64, |acc, &b| acc.wrapping_mul(31).wrapping_add(b as u64))
        );

        info!("TPM attestation report generated");
        Some(AttestationReport {
            nonce: nonce.to_vec(),
            pcr_values,
            signature,
            valid: true,
        })
    }

    pub fn detection_count(&self) -> u64 {
        self.detection_count
    }

    pub fn detect_pcr_tampering(&mut self, old: &[PcrValue], new: &[PcrValue]) -> bool {
        let mut tampered = false;

        for old_pcr in old {
            if let Some(new_pcr) = new.iter().find(|p| p.index == old_pcr.index) {
                if old_pcr.hash != new_pcr.hash {
                    warn!(
                        pcr_index = old_pcr.index,
                        old_hash = %old_pcr.hash,
                        new_hash = %new_pcr.hash,
                        "PCR tampering detected"
                    );
                    tampered = true;
                    self.detection_count += 1;
                }
            }
        }

        tampered
    }
}

impl Default for TpmGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpm_guard_new() {
        let guard = TpmGuard::new();
        let status = guard.check_status();
        assert_eq!(status.version, "2.0");
        assert_eq!(status.manufacturer, "IFX");
        assert_eq!(status.sealed_keys, 0);
    }

    #[test]
    fn test_seal_key() {
        let mut guard = TpmGuard::new();
        assert!(guard.seal_key("test-key-1", vec![0, 1, 2]));
        assert_eq!(guard.check_status().sealed_keys, 1);
        assert!(!guard.seal_key("test-key-1", vec![0, 1, 2]));
    }

    #[test]
    fn test_unseal_key_success() {
        let mut guard = TpmGuard::new();
        guard.seal_key("key1", vec![0, 1]);

        let pcr_values: Vec<PcrValue> = guard.pcr_snapshot.iter().cloned().collect();
        let result = guard.unseal_key("key1", &pcr_values);
        assert!(result.is_some());
        assert_eq!(guard.check_status().sealed_keys, 0);
    }

    #[test]
    fn test_unseal_key_pcr_mismatch() {
        let mut guard = TpmGuard::new();
        guard.seal_key("key2", vec![0]);

        let mut bad_pcr = guard.pcr_snapshot.clone();
        bad_pcr[0].hash = "tampered".to_string();

        let result = guard.unseal_key("key2", &bad_pcr);
        assert!(result.is_none());
        assert_eq!(guard.detection_count(), 1);
    }

    #[test]
    fn test_unseal_nonexistent_key() {
        let mut guard = TpmGuard::new();
        let result = guard.unseal_key("nonexistent", &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_verify_attestation() {
        let guard = TpmGuard::new();
        let report = guard.verify_attestation(b"test_nonce_123");
        assert!(report.is_some());
        let report = report.unwrap();
        assert!(report.valid);
        assert_eq!(report.nonce, b"test_nonce_123");
        assert_eq!(report.pcr_values.len(), 24);
    }

    #[test]
    fn test_verify_attestation_empty_nonce() {
        let guard = TpmGuard::new();
        assert!(guard.verify_attestation(b"").is_none());
    }

    #[test]
    fn test_detect_pcr_tampering() {
        let mut guard = TpmGuard::new();
        let old: Vec<PcrValue> = guard.pcr_snapshot.iter().cloned().collect();

        let mut new = old.clone();
        new[3].hash = "tampered_hash_value".to_string();

        assert!(guard.detect_pcr_tampering(&old, &new));
        assert_eq!(guard.detection_count(), 1);
    }

    #[test]
    fn test_no_tampering() {
        let mut guard = TpmGuard::new();
        let snapshot: Vec<PcrValue> = guard.pcr_snapshot.iter().cloned().collect();
        assert!(!guard.detect_pcr_tampering(&snapshot, &snapshot));
        assert_eq!(guard.detection_count(), 0);
    }
}
