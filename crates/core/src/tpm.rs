use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use tracing::info;

#[derive(Debug)]
pub enum TpmError {
    TpmNotAvailable,
    SealFailed(String),
    UnsealFailed(String),
    PcrMismatch {
        expected: Vec<u8>,
        actual: Vec<u8>,
    },
    AttestationFailed(String),
    IoError(std::io::Error),
}

impl std::fmt::Display for TpmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TpmNotAvailable => write!(f, "TPM is not available"),
            Self::SealFailed(msg) => write!(f, "seal failed: {msg}"),
            Self::UnsealFailed(msg) => write!(f, "unseal failed: {msg}"),
            Self::PcrMismatch { expected, actual } => {
                write!(
                    f,
                    "PCR mismatch: expected {expected:02x?}, got {actual:02x?}"
                )
            }
            Self::AttestationFailed(msg) => write!(f, "attestation failed: {msg}"),
            Self::IoError(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for TpmError {}

impl From<std::io::Error> for TpmError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmStatus {
    Available,
    Unavailable,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlob {
    pub key_id: String,
    pub pcr_selection: Vec<u8>,
    pub sealed_data: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

pub struct TpmManager {
    pcr_values: HashMap<u8, Vec<u8>>,
    sealed_keys: HashMap<String, SealedBlob>,
    status: TpmStatus,
}

impl TpmManager {
    pub fn new() -> Self {
        let status = Self::detect_tpm();
        let mut pcr_values = HashMap::new();
        for i in 0..16u8 {
            pcr_values.insert(i, Self::compute_pcr_hash(&[i]));
        }
        info!(status = ?status, "TpmManager initialised");
        Self {
            pcr_values,
            sealed_keys: HashMap::new(),
            status,
        }
    }

    fn detect_tpm() -> TpmStatus {
        #[cfg(target_os = "windows")]
        {
            if std::path::Path::new("\\\\.\\TPM").exists() {
                return TpmStatus::Available;
            }
        }
        #[cfg(target_os = "linux")]
        {
            if std::path::Path::new("/dev/tpm0").exists() {
                return TpmStatus::Available;
            }
        }
        TpmStatus::Unavailable
    }

    pub fn is_available(&self) -> bool {
        self.status == TpmStatus::Available
    }

    pub fn read_pcr(&self, register: u8) -> Result<Vec<u8>, TpmError> {
        self.pcr_values
            .get(&register)
            .cloned()
            .ok_or(TpmError::TpmNotAvailable)
    }

    pub fn set_pcr(&mut self, register: u8, value: Vec<u8>) {
        self.pcr_values.insert(register, value);
    }

    fn build_pcr_binding(&self, pcr_selection: &[u8]) -> Result<Vec<u8>, TpmError> {
        let mut binding = Vec::new();
        for &reg in pcr_selection {
            let val = self
                .pcr_values
                .get(&reg)
                .ok_or_else(|| TpmError::SealFailed(format!("PCR register {reg} not found")))?;
            binding.extend_from_slice(val);
        }
        Ok(binding)
    }

    pub fn seal_key(
        &mut self,
        key_id: &str,
        key_data: &[u8],
        pcr_selection: &[u8],
    ) -> Result<SealedBlob, TpmError> {
        if pcr_selection.is_empty() {
            return Err(TpmError::SealFailed(
                "PCR selection cannot be empty".into(),
            ));
        }
        let pcr_binding = self.build_pcr_binding(pcr_selection)?;
        let pcr_hash = Self::compute_pcr_hash(&pcr_binding);

        let mut sealed = Vec::with_capacity(key_data.len() + 32);
        sealed.extend_from_slice(key_data);
        sealed.extend_from_slice(&pcr_hash);

        let blob = SealedBlob {
            key_id: key_id.to_string(),
            pcr_selection: pcr_selection.to_vec(),
            sealed_data: sealed,
            created_at: Utc::now(),
        };
        info!(key_id, "key sealed to TPM");
        self.sealed_keys
            .insert(key_id.to_string(), blob.clone());
        Ok(blob)
    }

    pub fn unseal_key(&mut self, key_id: &str) -> Result<SealedBlob, TpmError> {
        let blob = self
            .sealed_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| TpmError::UnsealFailed(format!("key '{key_id}' not found")))?;

        if blob.sealed_data.len() < 32 {
            return Err(TpmError::UnsealFailed(
                "sealed data is corrupted".into(),
            ));
        }

        let stored_pcr_hash = &blob.sealed_data[blob.sealed_data.len() - 32..];
        let current_pcr_binding = self.build_pcr_binding(&blob.pcr_selection)?;
        let current_pcr_hash = Self::compute_pcr_hash(&current_pcr_binding);

        if stored_pcr_hash != current_pcr_hash.as_slice() {
            return Err(TpmError::PcrMismatch {
                expected: stored_pcr_hash.to_vec(),
                actual: current_pcr_hash,
            });
        }

        let key_data = blob.sealed_data[..blob.sealed_data.len() - 32].to_vec();
        let unsealed = SealedBlob {
            key_id: blob.key_id,
            pcr_selection: blob.pcr_selection,
            sealed_data: key_data,
            created_at: blob.created_at,
        };
        info!(key_id, "key unsealed from TPM");
        Ok(unsealed)
    }

    pub fn verify_pcr_integrity(&self) -> Result<(), TpmError> {
        for (key_id, blob) in &self.sealed_keys {
            if blob.sealed_data.len() < 32 {
                return Err(TpmError::UnsealFailed(format!(
                    "sealed blob for '{key_id}' is corrupted"
                )));
            }
            let stored_pcr_hash = &blob.sealed_data[blob.sealed_data.len() - 32..];
            let current_pcr_binding = self.build_pcr_binding(&blob.pcr_selection)?;
            let current_pcr_hash = Self::compute_pcr_hash(&current_pcr_binding);
            if stored_pcr_hash != current_pcr_hash.as_slice() {
                return Err(TpmError::PcrMismatch {
                    expected: stored_pcr_hash.to_vec(),
                    actual: current_pcr_hash,
                });
            }
        }
        Ok(())
    }

    pub fn get_sealed_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.sealed_keys.keys().cloned().collect();
        keys.sort();
        keys
    }

    pub fn get_status(&self) -> TpmStatus {
        self.status.clone()
    }

    pub fn compute_pcr_hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

impl Default for TpmManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpm_manager_new() {
        let mgr = TpmManager::new();
        assert_eq!(mgr.get_status(), TpmStatus::Unavailable);
        assert!(!mgr.is_available());
    }

    #[test]
    fn test_compute_pcr_hash_deterministic() {
        let h1 = TpmManager::compute_pcr_hash(b"test");
        let h2 = TpmManager::compute_pcr_hash(b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_pcr_hash_different_inputs() {
        let h1 = TpmManager::compute_pcr_hash(b"alpha");
        let h2 = TpmManager::compute_pcr_hash(b"beta");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_pcr_hash_length() {
        let h = TpmManager::compute_pcr_hash(b"data");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_read_pcr_default() {
        let mgr = TpmManager::new();
        let pcr0 = mgr.read_pcr(0).unwrap();
        assert_eq!(pcr0.len(), 32);
    }

    #[test]
    fn test_read_pcr_invalid_register() {
        let mgr = TpmManager::new();
        assert!(mgr.read_pcr(200).is_err());
    }

    #[test]
    fn test_seal_key_basic() {
        let mut mgr = TpmManager::new();
        let blob = mgr.seal_key("test-key", b"secret", &[0, 1]).unwrap();
        assert_eq!(blob.key_id, "test-key");
        assert_eq!(blob.pcr_selection, vec![0, 1]);
        assert!(!blob.sealed_data.is_empty());
    }

    #[test]
    fn test_seal_empty_pcr_selection_fails() {
        let mut mgr = TpmManager::new();
        let err = mgr.seal_key("k", b"d", &[]).unwrap_err();
        assert!(matches!(err, TpmError::SealFailed(_)));
    }

    #[test]
    fn test_unseal_key_with_matching_pcrs() {
        let mut mgr = TpmManager::new();
        mgr.seal_key("rk", b"mysecret", &[0]).unwrap();
        let unsealed = mgr.unseal_key("rk").unwrap();
        assert_eq!(unsealed.sealed_data, b"mysecret");
    }

    #[test]
    fn test_unseal_key_with_mismatched_pcrs() {
        let mut mgr = TpmManager::new();
        mgr.seal_key("rk2", b"data", &[0]).unwrap();
        mgr.set_pcr(0, vec![0xff; 32]);
        let err = mgr.unseal_key("rk2").unwrap_err();
        assert!(matches!(err, TpmError::PcrMismatch { .. }));
    }

    #[test]
    fn test_unseal_nonexistent_key() {
        let mut mgr = TpmManager::new();
        let err = mgr.unseal_key("nope").unwrap_err();
        assert!(matches!(err, TpmError::UnsealFailed(_)));
    }

    #[test]
    fn test_verify_pcr_integrity_clean() {
        let mgr = TpmManager::new();
        assert!(mgr.verify_pcr_integrity().is_ok());
    }

    #[test]
    fn test_verify_pcr_integrity_with_sealed() {
        let mut mgr = TpmManager::new();
        mgr.seal_key("v1", b"d", &[0, 1]).unwrap();
        assert!(mgr.verify_pcr_integrity().is_ok());
    }

    #[test]
    fn test_verify_pcr_integrity_fails_after_tamper() {
        let mut mgr = TpmManager::new();
        mgr.seal_key("v2", b"d", &[0]).unwrap();
        mgr.set_pcr(0, vec![0xab; 32]);
        assert!(mgr.verify_pcr_integrity().is_err());
    }

    #[test]
    fn test_get_sealed_keys() {
        let mut mgr = TpmManager::new();
        mgr.seal_key("a", b"1", &[0]).unwrap();
        mgr.seal_key("b", b"2", &[1]).unwrap();
        let keys = mgr.get_sealed_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"a".to_string()));
        assert!(keys.contains(&"b".to_string()));
    }

    #[test]
    fn test_seal_unseal_roundtrip() {
        let mut mgr = TpmManager::new();
        let secret = b"top-secret-key-material";
        let blob = mgr.seal_key("roundtrip", secret, &[2, 5, 10]).unwrap();
        assert_eq!(blob.key_id, "roundtrip");
        let unsealed = mgr.unseal_key("roundtrip").unwrap();
        assert_eq!(unsealed.sealed_data, secret);
    }
}
