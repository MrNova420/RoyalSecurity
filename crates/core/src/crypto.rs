use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305 as ChaCha};
use sha2::{Sha256, Digest};
use rand::{RngCore, thread_rng};
use serde::{Serialize, Deserialize};
use tracing::info;
use std::collections::HashMap;
use std::error::Error as StdError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultKey {
    pub id: String,
    pub algorithm: KeyAlgorithm,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub rotated_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub struct CryptoVault {
    keys: HashMap<String, VaultKey>,
    master_key: Vec<u8>,
}

impl CryptoVault {
    pub fn new() -> Self {
        let mut master_key = vec![0u8; 32];
        thread_rng().fill_bytes(&mut master_key);
        Self {
            keys: HashMap::new(),
            master_key,
        }
    }

    pub fn encrypt_aes256(&self, plaintext: &[u8], key_id: &str) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
        let key = self.derive_key(key_id)?;
        let cipher = Aes256Gcm::new_from_slice(&key)?;
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| -> Box<dyn StdError + Send + Sync> { format!("AES encrypt error: {e}").into() })?;
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    pub fn decrypt_aes256(&self, ciphertext: &[u8], key_id: &str) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
        if ciphertext.len() < 12 {
            return Err("Ciphertext too short".into());
        }
        let key = self.derive_key(key_id)?;
        let cipher = Aes256Gcm::new_from_slice(&key)?;
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let plaintext = cipher.decrypt(nonce, &ciphertext[12..])
            .map_err(|e| -> Box<dyn StdError + Send + Sync> { format!("AES decrypt error: {e}").into() })?;
        Ok(plaintext)
    }

    pub fn encrypt_chacha20(&self, plaintext: &[u8], key_id: &str) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
        let key = self.derive_key(key_id)?;
        let cipher = ChaCha::new_from_slice(&key)?;
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| -> Box<dyn StdError + Send + Sync> { format!("ChaCha encrypt error: {e}").into() })?;
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);
        Ok(result)
    }

    pub fn decrypt_chacha20(&self, ciphertext: &[u8], key_id: &str) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
        if ciphertext.len() < 12 {
            return Err("Ciphertext too short".into());
        }
        let key = self.derive_key(key_id)?;
        let cipher = ChaCha::new_from_slice(&key)?;
        let nonce = chacha20poly1305::Nonce::from_slice(&ciphertext[..12]);
        let plaintext = cipher.decrypt(nonce, &ciphertext[12..])
            .map_err(|e| -> Box<dyn StdError + Send + Sync> { format!("ChaCha decrypt error: {e}").into() })?;
        Ok(plaintext)
    }

    pub fn hash_sha256(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    pub fn generate_key(&mut self, name: &str, algorithm: KeyAlgorithm) -> VaultKey {
        let key = VaultKey {
            id: name.to_string(),
            algorithm,
            created_at: chrono::Utc::now(),
            expires_at: None,
            rotated_count: 0,
        };
        self.keys.insert(name.to_string(), key.clone());
        info!(key = %name, "Generated new vault key");
        key
    }

    pub fn rotate_key(&mut self, name: &str) -> Result<VaultKey, Box<dyn StdError + Send + Sync>> {
        if let Some(key) = self.keys.get_mut(name) {
            key.rotated_count += 1;
            key.created_at = chrono::Utc::now();
            info!(key = %name, count = key.rotated_count, "Key rotated");
            Ok(key.clone())
        } else {
            Err(format!("Key '{}' not found", name).into())
        }
    }

    fn derive_key(&self, key_id: &str) -> Result<[u8; 32], Box<dyn StdError + Send + Sync>> {
        let mut hasher = Sha256::new();
        hasher.update(&self.master_key);
        hasher.update(key_id.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        Ok(key)
    }

    pub fn list_keys(&self) -> Vec<VaultKey> {
        self.keys.values().cloned().collect()
    }

    pub fn export_master_key_hash(&self) -> String {
        self.hash_sha256(&self.master_key)
    }
}
