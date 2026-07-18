pub mod arena;
pub mod bus;
pub mod config;
pub mod crypto;
pub mod audit;
pub mod hotreload;
pub mod module;
pub mod ppl;
pub mod registry;
pub mod tpm;

pub use royalsecurity_common as common;
pub use bus::*;
pub use config::*;
pub use crypto::*;
pub use audit::*;
pub use module::*;
pub use registry::*;
pub use tpm::*;

#[cfg(test)]
mod tests {
    use crate::bus::EventBus;
    use crate::crypto::CryptoVault;
    use crate::audit::AuditLog;
    use crate::config::AppConfig;
    use std::collections::HashMap;

    #[test]
    fn test_event_bus_publish_subscribe() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        
        let event = royalsecurity_common::types::SecurityEvent::Process(
            royalsecurity_common::types::ProcessInfo::default(),
        );
        bus.publish(event).unwrap();
        
        let received = rx.try_recv();
        assert!(received.is_ok(), "Should receive published event");
    }

    #[test]
    fn test_event_bus_multiple_subscribers() {
        let bus = EventBus::new();
        let _rx1 = bus.subscribe();
        let _rx2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
    }

    #[test]
    fn test_crypto_vault_encrypt_decrypt_aes() {
        let mut vault = CryptoVault::new();
        vault.generate_key("test", crate::crypto::KeyAlgorithm::Aes256Gcm);
        
        let plaintext = b"Hello, RoyalSecurity!";
        let encrypted = vault.encrypt_aes256(plaintext, "test").unwrap();
        assert_ne!(encrypted, plaintext);
        
        let decrypted = vault.decrypt_aes256(&encrypted, "test").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_crypto_vault_encrypt_decrypt_chacha() {
        let mut vault = CryptoVault::new();
        vault.generate_key("chacha-test", crate::crypto::KeyAlgorithm::ChaCha20Poly1305);
        
        let plaintext = b"ChaCha20-Poly1305 encryption test";
        let encrypted = vault.encrypt_chacha20(plaintext, "chacha-test").unwrap();
        assert_ne!(encrypted, plaintext);
        
        let decrypted = vault.decrypt_chacha20(&encrypted, "chacha-test").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_crypto_vault_key_rotation() {
        let mut vault = CryptoVault::new();
        vault.generate_key("rotating", crate::crypto::KeyAlgorithm::Aes256Gcm);
        
        let key = vault.rotate_key("rotating").unwrap();
        assert_eq!(key.rotated_count, 1);
        
        let key = vault.rotate_key("rotating").unwrap();
        assert_eq!(key.rotated_count, 2);
    }

    #[test]
    fn test_crypto_vault_hash() {
        let vault = CryptoVault::new();
        let hash1 = vault.hash_sha256(b"test");
        let hash2 = vault.hash_sha256(b"test");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_audit_log_record_and_verify() {
        let mut audit = AuditLog::new();
        
        let mut details = HashMap::new();
        details.insert("test".into(), serde_json::json!("value"));
        
        audit.record("test.action", "system", "target", details);
        assert_eq!(audit.count(), 1);
        assert!(audit.verify_chain(), "Chain should be valid after recording");
    }

    #[test]
    fn test_audit_log_chain_integrity() {
        let mut audit = AuditLog::new();
        
        for i in 0..10 {
            let mut details = HashMap::new();
            details.insert("index".into(), serde_json::json!(i));
            audit.record(&format!("action.{}", i), "system", "target", details);
        }
        
        assert_eq!(audit.count(), 10);
        assert!(audit.verify_chain(), "Chain should be valid with 10 entries");
    }

    #[test]
    fn test_config_default() {
        let config = AppConfig::default();
        assert_eq!(config.general.app_name, "RoyalSecurity");
        assert!(config.defense.av_enabled);
        assert!(config.defense.edr_enabled);
        assert!(config.network.firewall_enabled);
        assert_eq!(config.agent.heartbeat_interval_secs, 5);
    }

    #[test]
    fn test_config_serialization() {
        let config = AppConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.general.app_name, deserialized.general.app_name);
    }
}
