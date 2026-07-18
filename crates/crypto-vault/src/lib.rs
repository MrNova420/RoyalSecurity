pub mod prelude;
pub mod tpm_seal;

use std::collections::HashMap;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum CryptoError {
    KeyNotFound(String),
    DecryptionFailed(String),
    SigningFailed(String),
    VerificationFailed(String),
    InvalidShares(String),
    InvalidThreshold(String),
    AlgorithmMismatch(String),
    KeyExpired(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyNotFound(k) => write!(f, "key not found: {k}"),
            Self::DecryptionFailed(m) => write!(f, "decryption failed: {m}"),
            Self::SigningFailed(m) => write!(f, "signing failed: {m}"),
            Self::VerificationFailed(m) => write!(f, "verification failed: {m}"),
            Self::InvalidShares(m) => write!(f, "invalid shares: {m}"),
            Self::InvalidThreshold(m) => write!(f, "invalid threshold: {m}"),
            Self::AlgorithmMismatch(m) => write!(f, "algorithm mismatch: {m}"),
            Self::KeyExpired(k) => write!(f, "key expired: {k}"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub type Result<T> = std::result::Result<T, CryptoError>;

// ---------------------------------------------------------------------------
// Algorithm / KeyUsage enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Algorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum KeyUsage {
    DataEncryption,
    AuditSigning,
    TpmSealing,
    KeyExchange,
    TokenGeneration,
}

// ---------------------------------------------------------------------------
// DerivedKey
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DerivedKey {
    pub key_id: String,
    pub algorithm: Algorithm,
    pub key_material: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub usage: KeyUsage,
}

// ---------------------------------------------------------------------------
// KeyRotationPolicy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyRotationPolicy {
    pub rotation_interval_hours: u64,
    pub auto_rotate: bool,
    pub max_key_age_hours: u64,
}

impl Default for KeyRotationPolicy {
    fn default() -> Self {
        Self {
            rotation_interval_hours: 720,
            auto_rotate: true,
            max_key_age_hours: 2160,
        }
    }
}

// ---------------------------------------------------------------------------
// EncryptedData
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_id: String,
    pub algorithm: Algorithm,
    pub aad: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// ShamirShare
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShamirShare {
    pub index: u8,
    pub share: Vec<u8>,
    pub prime: Vec<u8>,
}

// ---------------------------------------------------------------------------
// GF(256) arithmetic for Shamir Secret Sharing
// ---------------------------------------------------------------------------

fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut p: u8 = 0;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a = (a << 1) & 0xFF;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

fn gf256_pow(mut base: u8, mut exp: u8) -> u8 {
    let mut result: u8 = 1;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf256_mul(result, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    result
}

fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        0
    } else {
        gf256_pow(a, 254)
    }
}

// ---------------------------------------------------------------------------
// CryptoVault
// ---------------------------------------------------------------------------

pub struct CryptoVault {
    pub master_key: Vec<u8>,
    pub derived_keys: HashMap<String, DerivedKey>,
    pub rotation_policy: KeyRotationPolicy,
}

impl CryptoVault {
    /// Create a new vault with a random 32-byte master key and initial derived keys.
    pub fn new() -> Self {
        let mut master_key = vec![0u8; 32];
        OsRng.fill_bytes(&mut master_key);

        let mut vault = Self {
            master_key,
            derived_keys: HashMap::new(),
            rotation_policy: KeyRotationPolicy::default(),
        };

        vault.derive_key("default-encryption", KeyUsage::DataEncryption);
        vault.derive_key("audit-signing", KeyUsage::AuditSigning);
        vault.derive_key("token-generation", KeyUsage::TokenGeneration);

        info!(
            "CryptoVault initialised with {} derived keys",
            vault.derived_keys.len()
        );
        vault
    }

    // ----- key derivation ---------------------------------------------------

    fn random_nonce(len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        OsRng.fill_bytes(&mut buf);
        buf
    }

    /// Derive a new key for `purpose` and return its id.
    pub fn derive_key(&mut self, purpose: &str, usage: KeyUsage) -> String {
        let key_id = purpose.to_string();
        let algorithm = match usage {
            KeyUsage::DataEncryption | KeyUsage::TpmSealing | KeyUsage::KeyExchange => {
                Algorithm::Aes256Gcm
            }
            KeyUsage::AuditSigning => Algorithm::Ed25519,
            KeyUsage::TokenGeneration => Algorithm::ChaCha20Poly1305,
        };

        let key_material = match algorithm {
            Algorithm::Ed25519 => {
                let mut seed = [0u8; 32];
                OsRng.fill_bytes(&mut seed);
                seed.to_vec()
            }
            _ => {
                let mut hasher = Sha256::new();
                hasher.update(&self.master_key);
                hasher.update(purpose.as_bytes());
                hasher.finalize().to_vec()
            }
        };

        let now = Utc::now();
        let derived = DerivedKey {
            key_id: key_id.clone(),
            algorithm,
            key_material,
            created_at: now,
            expires_at: now + Duration::hours(self.rotation_policy.max_key_age_hours as i64),
            usage,
        };

        debug!(purpose, key_id = %key_id, "derived new key");
        self.derived_keys.insert(key_id.clone(), derived);
        key_id
    }

    // ----- lookup helpers ---------------------------------------------------

    fn get_key(&self, key_id: &str) -> Result<&DerivedKey> {
        self.derived_keys
            .get(key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))
    }

    // ----- encrypt / decrypt ------------------------------------------------

    pub fn encrypt(&self, data: &[u8], key_id: &str) -> Result<EncryptedData> {
        let dk = self.get_key(key_id)?;

        match dk.algorithm {
            Algorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&dk.key_material)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
                let nonce_bytes = Self::random_nonce(12);
                let nonce = Nonce::from_slice(&nonce_bytes);
                let ciphertext = cipher
                    .encrypt(nonce, data)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
                Ok(EncryptedData {
                    ciphertext,
                    nonce: nonce_bytes,
                    key_id: key_id.to_string(),
                    algorithm: Algorithm::Aes256Gcm,
                    aad: None,
                })
            }
            Algorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&dk.key_material)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
                let nonce_bytes = Self::random_nonce(12);
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                let ciphertext = cipher
                    .encrypt(nonce, data)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
                Ok(EncryptedData {
                    ciphertext,
                    nonce: nonce_bytes,
                    key_id: key_id.to_string(),
                    algorithm: Algorithm::ChaCha20Poly1305,
                    aad: None,
                })
            }
            Algorithm::Ed25519 => Err(CryptoError::AlgorithmMismatch(
                "Ed25519 keys cannot be used for encryption".into(),
            )),
        }
    }

    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        let dk = self.get_key(&encrypted.key_id)?;

        if dk.algorithm != encrypted.algorithm {
            return Err(CryptoError::AlgorithmMismatch(format!(
                "key algorithm {:?} != encrypted algorithm {:?}",
                dk.algorithm, encrypted.algorithm
            )));
        }

        match encrypted.algorithm {
            Algorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&dk.key_material)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
                let nonce = Nonce::from_slice(&encrypted.nonce);
                cipher
                    .decrypt(nonce, encrypted.ciphertext.as_ref())
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
            }
            Algorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&dk.key_material)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
                let nonce = chacha20poly1305::Nonce::from_slice(&encrypted.nonce);
                cipher
                    .decrypt(nonce, encrypted.ciphertext.as_ref())
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
            }
            Algorithm::Ed25519 => Err(CryptoError::AlgorithmMismatch(
                "Ed25519 keys cannot be used for decryption".into(),
            )),
        }
    }

    // ----- sign / verify ----------------------------------------------------

    pub fn sign(&self, data: &[u8], key_id: &str) -> Result<Vec<u8>> {
        let dk = self.get_key(key_id)?;

        if dk.algorithm != Algorithm::Ed25519 {
            return Err(CryptoError::AlgorithmMismatch(
                "signing requires an Ed25519 key".into(),
            ));
        }

        let seed: [u8; 32] = dk
            .key_material
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::SigningFailed("invalid key length".into()))?;
        let signing_key = SigningKey::from_bytes(&seed);
        let sig = signing_key.sign(data);
        Ok(sig.to_bytes().to_vec())
    }

    pub fn verify(&self, data: &[u8], signature: &[u8], key_id: &str) -> Result<bool> {
        let dk = self.get_key(key_id)?;

        if dk.algorithm != Algorithm::Ed25519 {
            return Err(CryptoError::AlgorithmMismatch(
                "verification requires an Ed25519 key".into(),
            ));
        }

        let seed: [u8; 32] = dk
            .key_material
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::VerificationFailed("invalid key length".into()))?;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| CryptoError::VerificationFailed("invalid signature length".into()))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        Ok(verifying_key.verify(data, &sig).is_ok())
    }

    // ----- rotation ---------------------------------------------------------

    pub fn needs_rotation(&self, key_id: &str) -> bool {
        match self.get_key(key_id) {
            Ok(dk) => {
                let age = Utc::now() - dk.created_at;
                age > Duration::hours(self.rotation_policy.rotation_interval_hours as i64)
            }
            Err(_) => true,
        }
    }

    pub fn rotate_key(&mut self, key_id: &str) -> Result<String> {
        let old = self.get_key(key_id)?.clone();
        let purpose = match old.usage {
            KeyUsage::DataEncryption => "data-encryption",
            KeyUsage::AuditSigning => "audit-signing",
            KeyUsage::TpmSealing => "tpm-sealing",
            KeyUsage::KeyExchange => "key-exchange",
            KeyUsage::TokenGeneration => "token-generation",
        };
        let new_id = self.derive_key(purpose, old.usage);
        info!(old_key = key_id, new_key = %new_id, "key rotated");
        Ok(new_id)
    }

    // ----- Shamir secret sharing (GF(256)) ---------------------------------

    fn shamir_coeff(&self, byte_pos: u32, coeff_idx: u32) -> u8 {
        let mut hasher = Sha256::new();
        hasher.update(&self.master_key);
        hasher.update(byte_pos.to_le_bytes());
        hasher.update(coeff_idx.to_le_bytes());
        let hash = hasher.finalize();
        hash[0]
    }

    /// Split `secret` into `shares` shares with a `threshold` needed to reconstruct.
    pub fn split_secret(
        &self,
        secret: &[u8],
        threshold: u32,
        shares: u32,
    ) -> Result<Vec<ShamirShare>> {
        if threshold == 0 || threshold > shares {
            return Err(CryptoError::InvalidThreshold(format!(
                "threshold {threshold} invalid for {shares} shares"
            )));
        }
        if shares > 255 {
            return Err(CryptoError::InvalidShares(
                "cannot create more than 255 shares".into(),
            ));
        }

        let mut result = Vec::with_capacity(shares as usize);

        for i in 1..=shares {
            let mut share_bytes = Vec::with_capacity(secret.len());
            for (b, &s) in secret.iter().enumerate() {
                let mut val = s;
                let mut x_pow = i as u8;
                for coeff_idx in 1..threshold {
                    let coeff = self.shamir_coeff(b as u32, coeff_idx);
                    val ^= gf256_mul(coeff, x_pow);
                    x_pow = gf256_mul(x_pow, i as u8);
                }
                share_bytes.push(val);
            }
            result.push(ShamirShare {
                index: i as u8,
                share: share_bytes,
                prime: vec![],
            });
        }

        Ok(result)
    }

    /// Reconstruct a secret from `threshold` or more shares via Lagrange interpolation.
    pub fn combine_shares(shares: &[ShamirShare], threshold: u32) -> Result<Vec<u8>> {
        if shares.len() < threshold as usize {
            return Err(CryptoError::InvalidShares(format!(
                "need {} shares but got {}",
                threshold,
                shares.len()
            )));
        }

        let secret_len = shares[0].share.len();
        let mut secret = vec![0u8; secret_len];

        for byte_idx in 0..secret_len {
            let mut val: u8 = 0;
            for (i, share_i) in shares.iter().take(threshold as usize).enumerate() {
                let xi = share_i.index;
                let mut basis: u8 = 1;
                for (j, share_j) in shares.iter().take(threshold as usize).enumerate() {
                    if i == j {
                        continue;
                    }
                    let xj = share_j.index;
                    // Lagrange basis at x=0: l_i(0) = prod_{j!=i} (0-xj)/(xi-xj)
                    // In GF(256), subtraction = XOR, so -xj = xj
                    // (0-xj) = xj, (xi-xj) = xi XOR xj
                    let numer = xj;
                    let denom = xi ^ xj;
                    if denom == 0 {
                        return Err(CryptoError::InvalidShares(
                            "duplicate share indices".into(),
                        ));
                    }
                    let denom_inv = gf256_inv(denom);
                    basis = gf256_mul(basis, gf256_mul(numer, denom_inv));
                }
                val ^= gf256_mul(share_i.share[byte_idx], basis);
            }
            secret[byte_idx] = val;
        }

        Ok(secret)
    }

    // ----- hashing ----------------------------------------------------------

    pub fn hash_data(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    pub fn hash_data_sha3(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_vault() {
        let vault = CryptoVault::new();
        assert_eq!(vault.master_key.len(), 32);
        assert_eq!(vault.derived_keys.len(), 3);
        assert!(vault.derived_keys.contains_key("default-encryption"));
        assert!(vault.derived_keys.contains_key("audit-signing"));
        assert!(vault.derived_keys.contains_key("token-generation"));
    }

    #[test]
    fn test_encrypt_decrypt_aes_roundtrip() {
        let vault = CryptoVault::new();
        let key_id = "default-encryption";
        let plaintext = b"super secret data";

        let encrypted = vault.encrypt(plaintext, key_id).unwrap();
        assert_eq!(encrypted.algorithm, Algorithm::Aes256Gcm);
        assert_eq!(encrypted.key_id, key_id);

        let decrypted = vault.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_chacha_roundtrip() {
        let mut vault = CryptoVault::new();
        let key_id = vault.derive_key("chacha-test", KeyUsage::TokenGeneration);
        let plaintext = b"chacha20poly1305 test data";

        let encrypted = vault.encrypt(plaintext, &key_id).unwrap();
        assert_eq!(encrypted.algorithm, Algorithm::ChaCha20Poly1305);

        let decrypted = vault.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sign_verify() {
        let vault = CryptoVault::new();
        let key_id = "audit-signing";
        let message = b"important audit record";

        let sig = vault.sign(message, key_id).unwrap();
        assert_eq!(sig.len(), 64);

        assert!(vault.verify(message, &sig, key_id).unwrap());
    }

    #[test]
    fn test_verify_wrong_data_fails() {
        let vault = CryptoVault::new();
        let key_id = "audit-signing";
        let message = b"original data";
        let tampered = b"tampered data";

        let sig = vault.sign(message, key_id).unwrap();
        assert!(!vault.verify(tampered, &sig, key_id).unwrap());
    }

    #[test]
    fn test_derive_key_returns_unique_ids() {
        let mut vault = CryptoVault::new();
        let id1 = vault.derive_key("purpose-a", KeyUsage::DataEncryption);
        let id2 = vault.derive_key("purpose-b", KeyUsage::DataEncryption);
        assert_ne!(id1, id2);
        assert!(vault.derived_keys.contains_key(&id1));
        assert!(vault.derived_keys.contains_key(&id2));
    }

    #[test]
    fn test_rotate_key() {
        let mut vault = CryptoVault::new();
        let old_id = "default-encryption";
        let old_key = vault.get_key(old_id).unwrap().clone();

        let new_id = vault.rotate_key(old_id).unwrap();
        assert_ne!(new_id, old_id);

        let new_key = vault.get_key(&new_id).unwrap();
        assert_ne!(new_key.key_material, old_key.key_material);
        assert_eq!(new_key.usage, old_key.usage);
    }

    #[test]
    fn test_needs_rotation() {
        let vault = CryptoVault::new();
        assert!(!vault.needs_rotation("default-encryption"));
    }

    #[test]
    fn test_needs_rotation_missing_key() {
        let vault = CryptoVault::new();
        assert!(vault.needs_rotation("nonexistent-key"));
    }

    #[test]
    fn test_split_combine_secret() {
        let vault = CryptoVault::new();
        let secret = b"my secret bytes!";

        let shares = vault.split_secret(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        let reconstructed = CryptoVault::combine_shares(&shares[..3], 3).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_combine_shares_different_subsets() {
        let vault = CryptoVault::new();
        let secret = b"test secret data";

        let shares = vault.split_secret(secret, 2, 4).unwrap();

        let r1 = CryptoVault::combine_shares(&shares[..2], 2).unwrap();
        assert_eq!(r1, secret);

        let r2 =
            CryptoVault::combine_shares(&[shares[1].clone(), shares[3].clone()], 2).unwrap();
        assert_eq!(r2, secret);
    }

    #[test]
    fn test_hash_consistency() {
        let data = b"hello world";
        let h1 = CryptoVault::hash_data(data);
        let h2 = CryptoVault::hash_data(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn test_hash_sha3_consistency() {
        let data = b"hello world";
        let h1 = CryptoVault::hash_data_sha3(data);
        let h2 = CryptoVault::hash_data_sha3(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn test_sha256_vs_sha3_differ() {
        let data = b"same input";
        assert_ne!(
            CryptoVault::hash_data(data),
            CryptoVault::hash_data_sha3(data)
        );
    }

    #[test]
    fn test_encrypt_ed25519_key_fails() {
        let vault = CryptoVault::new();
        let err = vault.encrypt(b"data", "audit-signing").unwrap_err();
        assert!(matches!(err, CryptoError::AlgorithmMismatch(_)));
    }

    #[test]
    fn test_sign_with_non_ed25519_key_fails() {
        let vault = CryptoVault::new();
        let err = vault.sign(b"data", "default-encryption").unwrap_err();
        assert!(matches!(err, CryptoError::AlgorithmMismatch(_)));
    }

    #[test]
    fn test_invalid_threshold() {
        let vault = CryptoVault::new();
        let err = vault.split_secret(b"secret", 5, 3).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidThreshold(_)));
    }
}
