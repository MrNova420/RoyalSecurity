use std::path::Path;

use royalsecurity_core::tpm::{SealedBlob, TpmError, TpmManager};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::CryptoVault;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealStatus {
    Sealed,
    Unsealed,
    UnsealedWithWarning,
    TpmUnavailable,
}

pub struct TpmSealedVault {
    vault: CryptoVault,
    tpm: TpmManager,
    status: SealStatus,
    master_key_sealed: Option<SealedBlob>,
}

impl TpmSealedVault {
    pub fn new(vault: CryptoVault) -> Self {
        let tpm = TpmManager::new();
        let status = if tpm.is_available() {
            SealStatus::Unsealed
        } else {
            SealStatus::TpmUnavailable
        };
        Self {
            vault,
            tpm,
            status,
            master_key_sealed: None,
        }
    }

    pub fn seal_master_key(&mut self, pcr_selection: &[u8]) -> Result<SealStatus, TpmError> {
        if !self.tpm.is_available() {
            warn!("TPM unavailable, cannot seal master key");
            return Ok(SealStatus::TpmUnavailable);
        }
        let master_key = self.vault.master_key.clone();
        let blob = self
            .tpm
            .seal_key("vault-master-key", &master_key, pcr_selection)?;
        self.master_key_sealed = Some(blob);
        self.status = SealStatus::Sealed;
        info!("vault master key sealed to TPM");
        Ok(SealStatus::Sealed)
    }

    pub fn unseal_master_key(&mut self) -> Result<SealStatus, TpmError> {
        if self.master_key_sealed.is_none() {
            return Ok(SealStatus::Unsealed);
        }
        let unsealed = self.tpm.unseal_key("vault-master-key")?;
        if unsealed.sealed_data == self.vault.master_key {
            self.status = SealStatus::Unsealed;
            info!("vault master key verified and unsealed");
        } else {
            self.status = SealStatus::UnsealedWithWarning;
            warn!("vault master key unsealed but data mismatch detected");
        }
        Ok(self.status.clone())
    }

    pub fn get_seal_status(&self) -> SealStatus {
        self.status.clone()
    }

    pub fn rotate_sealed_key(&mut self, key_id: &str) -> Result<String, TpmError> {
        let new_id = self
            .vault
            .rotate_key(key_id)
            .map_err(|e| TpmError::SealFailed(e.to_string()))?;

        if let Some(blob) = &self.master_key_sealed {
            let pcr_selection = blob.pcr_selection.clone();
            let master_key = self.vault.master_key.clone();
            let new_blob = self
                .tpm
                .seal_key("vault-master-key", &master_key, &pcr_selection)?;
            self.master_key_sealed = Some(new_blob);
        }

        info!(key_id, new_id = %new_id, "sealed key rotated");
        Ok(new_id)
    }

    pub fn export_sealed_data(&self, path: &Path) -> Result<(), TpmError> {
        let data = ExportedSealedData {
            sealed_keys: self.tpm.get_sealed_keys(),
            master_key_blob: self.master_key_sealed.clone(),
            status: self.status.clone(),
        };
        let json = serde_json::to_string_pretty(&data).map_err(|e| {
            TpmError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        std::fs::write(path, json).map_err(TpmError::IoError)?;
        info!(path = %path.display(), "sealed data exported");
        Ok(())
    }

    pub fn import_sealed_data(&mut self, path: &Path) -> Result<(), TpmError> {
        let json =
            std::fs::read_to_string(path).map_err(TpmError::IoError)?;
        let data: ExportedSealedData = serde_json::from_str(&json).map_err(|e| {
            TpmError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        self.master_key_sealed = data.master_key_blob;
        self.status = data.status;
        info!(path = %path.display(), "sealed data imported");
        Ok(())
    }

    pub fn vault(&self) -> &CryptoVault {
        &self.vault
    }

    pub fn vault_mut(&mut self) -> &mut CryptoVault {
        &mut self.vault
    }
}

#[derive(Serialize, Deserialize)]
struct ExportedSealedData {
    sealed_keys: Vec<String>,
    master_key_blob: Option<SealedBlob>,
    status: SealStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpm_sealed_vault_new() {
        let vault = CryptoVault::new();
        let sv = TpmSealedVault::new(vault);
        assert_eq!(sv.get_seal_status(), SealStatus::TpmUnavailable);
    }

    #[test]
    fn test_seal_master_key_tpm_unavailable() {
        let vault = CryptoVault::new();
        let mut sv = TpmSealedVault::new(vault);
        let status = sv.seal_master_key(&[0, 1]).unwrap();
        assert_eq!(status, SealStatus::TpmUnavailable);
    }

    #[test]
    fn test_unseal_without_prior_seal() {
        let vault = CryptoVault::new();
        let mut sv = TpmSealedVault::new(vault);
        let status = sv.unseal_master_key().unwrap();
        assert_eq!(status, SealStatus::Unsealed);
    }

    #[test]
    fn test_get_seal_status() {
        let vault = CryptoVault::new();
        let sv = TpmSealedVault::new(vault);
        assert_eq!(sv.get_seal_status(), SealStatus::TpmUnavailable);
    }

    #[test]
    fn test_vault_accessors() {
        let vault = CryptoVault::new();
        let sv = TpmSealedVault::new(vault);
        assert_eq!(sv.vault().master_key.len(), 32);
    }

    #[test]
    fn test_export_sealed_data() {
        let vault = CryptoVault::new();
        let sv = TpmSealedVault::new(vault);
        let dir = std::env::temp_dir().join("rs_tpm_test_export");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sealed.json");
        sv.export_sealed_data(&path).unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("TpmUnavailable"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_import_sealed_data() {
        let vault = CryptoVault::new();
        let sv = TpmSealedVault::new(vault);
        let dir = std::env::temp_dir().join("rs_tpm_test_import");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sealed.json");
        sv.export_sealed_data(&path).unwrap();

        let vault2 = CryptoVault::new();
        let mut sv2 = TpmSealedVault::new(vault2);
        sv2.import_sealed_data(&path).unwrap();
        assert_eq!(sv2.get_seal_status(), SealStatus::TpmUnavailable);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_rotate_sealed_key_without_sealing() {
        let vault = CryptoVault::new();
        let mut sv = TpmSealedVault::new(vault);
        let new_id = sv.rotate_sealed_key("default-encryption").unwrap();
        assert_ne!(new_id, "default-encryption");
    }

    #[test]
    fn test_export_import_roundtrip_preserves_status() {
        let vault = CryptoVault::new();
        let sv = TpmSealedVault::new(vault);
        let dir = std::env::temp_dir().join("rs_tpm_test_roundtrip");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sealed_rt.json");

        sv.export_sealed_data(&path).unwrap();

        let vault2 = CryptoVault::new();
        let mut sv2 = TpmSealedVault::new(vault2);
        assert_eq!(sv2.get_seal_status(), SealStatus::TpmUnavailable);
        sv2.import_sealed_data(&path).unwrap();
        assert_eq!(sv2.get_seal_status(), sv.get_seal_status());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
