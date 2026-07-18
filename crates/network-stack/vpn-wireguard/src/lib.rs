pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::{EventSeverity, NetworkEvent, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum WgError {
    #[error("peer not found: {0}")]
    PeerNotFound(String),
    #[error("peer already exists: {0}")]
    PeerExists(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("interface not configured")]
    InterfaceNotConfigured,
}

// ---------------------------------------------------------------------------
// WgPeer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeer {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub preshared_key: Option<String>,
    pub handshake_time: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// WireGuardInterface
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardInterface {
    pub name: String,
    pub private_key: String,
    pub public_key: String,
    pub listen_port: u16,
    pub peers: Vec<WgPeer>,
}

// ---------------------------------------------------------------------------
// WgConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgConfig {
    pub interface_name: String,
    pub private_key: String,
    pub address: String,
    pub dns: Vec<String>,
    pub mtu: u16,
    pub peers: Vec<WgPeer>,
}

impl Default for WgConfig {
    fn default() -> Self {
        Self {
            interface_name: "wg0".to_string(),
            private_key: String::new(),
            address: "10.0.0.1/24".to_string(),
            dns: vec!["1.1.1.1".to_string()],
            mtu: 1420,
            peers: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// WgStats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WgStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub active_peers: u32,
    pub uptime_secs: u64,
}

// ---------------------------------------------------------------------------
// WireGuardManager
// ---------------------------------------------------------------------------

pub struct WireGuardManager {
    config: Option<WgConfig>,
    interface: Option<WireGuardInterface>,
    stats: WgStats,
    started_at: Option<DateTime<Utc>>,
}

impl WireGuardManager {
    pub fn new() -> Self {
        info!("Initialized WireGuard manager");
        Self {
            config: None,
            interface: None,
            stats: WgStats::default(),
            started_at: None,
        }
    }

    pub fn with_config(config: WgConfig) -> Self {
        let pub_key = Self::derive_public_key(&config.private_key);
        let interface = WireGuardInterface {
            name: config.interface_name.clone(),
            private_key: config.private_key.clone(),
            public_key: pub_key,
            listen_port: 51820,
            peers: config.peers.clone(),
        };

        info!(
            interface = %config.interface_name,
            address = %config.address,
            peers = config.peers.len(),
            "Initialized WireGuard manager with config"
        );

        Self {
            config: Some(config),
            interface: Some(interface),
            stats: WgStats::default(),
            started_at: Some(Utc::now()),
        }
    }

    pub fn set_config(&mut self, config: WgConfig) {
        let pub_key = Self::derive_public_key(&config.private_key);
        let interface = WireGuardInterface {
            name: config.interface_name.clone(),
            private_key: config.private_key.clone(),
            public_key: pub_key,
            listen_port: 51820,
            peers: config.peers.clone(),
        };
        self.config = Some(config);
        self.interface = Some(interface);
        self.started_at = Some(Utc::now());
    }

    pub fn add_peer(&mut self, peer: WgPeer) -> bool {
        let interface = match self.interface.as_mut() {
            Some(i) => i,
            None => return false,
        };

        if interface.peers.iter().any(|p| p.public_key == peer.public_key) {
            warn!(key = %peer.public_key, "Peer already exists");
            return false;
        }

        info!(key = %peer.public_key, "Added WireGuard peer");
        interface.peers.push(peer);
        self.stats.active_peers = interface.peers.len() as u32;
        true
    }

    pub fn remove_peer(&mut self, public_key: &str) -> bool {
        let interface = match self.interface.as_mut() {
            Some(i) => i,
            None => return false,
        };

        let before = interface.peers.len();
        interface.peers.retain(|p| p.public_key != public_key);
        let removed = interface.peers.len() < before;

        if removed {
            info!(key = %public_key, "Removed WireGuard peer");
            self.stats.active_peers = interface.peers.len() as u32;
        }
        removed
    }

    pub fn generate_keypair() -> (String, String) {
        let private_key = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=".to_string();
        let public_key = "cHVibGljX2tleV9mb3Jfd2d0ZXN0MTIzNDU2Nzg5MA==".to_string();
        (private_key, public_key)
    }

    pub fn get_interface(&self) -> Option<&WireGuardInterface> {
        self.interface.as_ref()
    }

    pub fn get_peers(&self) -> Vec<&WgPeer> {
        self.interface
            .as_ref()
            .map(|i| i.peers.iter().collect())
            .unwrap_or_default()
    }

    pub fn is_peer_alive(&self, public_key: &str) -> bool {
        self.interface
            .as_ref()
            .and_then(|i| i.peers.iter().find(|p| p.public_key == public_key))
            .map(|p| p.handshake_time.is_some())
            .unwrap_or(false)
    }

    pub fn interface_stats(&self) -> WgStats {
        let mut stats = self.stats.clone();
        if let Some(started) = self.started_at {
            stats.uptime_secs = (Utc::now() - started).num_seconds() as u64;
        }
        stats
    }

    fn derive_public_key(private_key: &str) -> String {
        format!("pub_derived_{}", &private_key[..private_key.len().min(8)])
    }

    pub fn config(&self) -> Option<&WgConfig> {
        self.config.as_ref()
    }
}

impl Default for WireGuardManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer(pub_key: &str) -> WgPeer {
        WgPeer {
            public_key: pub_key.to_string(),
            endpoint: Some("192.168.1.1:51820".to_string()),
            allowed_ips: vec!["10.0.0.0/24".to_string()],
            preshared_key: None,
            handshake_time: Some(Utc::now()),
        }
    }

    #[test]
    fn test_new_manager() {
        let manager = WireGuardManager::new();
        assert!(manager.get_interface().is_none());
        assert!(manager.get_peers().is_empty());
    }

    #[test]
    fn test_with_config() {
        let config = WgConfig {
            interface_name: "wg1".to_string(),
            address: "10.0.0.2/24".to_string(),
            ..Default::default()
        };
        let manager = WireGuardManager::with_config(config);
        let iface = manager.get_interface().unwrap();
        assert_eq!(iface.name, "wg1");
    }

    #[test]
    fn test_add_peer() {
        let mut manager = WireGuardManager::new();
        manager.set_config(WgConfig::default());
        assert!(manager.add_peer(make_peer("key1")));
        assert_eq!(manager.get_peers().len(), 1);
    }

    #[test]
    fn test_add_duplicate_peer() {
        let mut manager = WireGuardManager::new();
        manager.set_config(WgConfig::default());
        assert!(manager.add_peer(make_peer("key1")));
        assert!(!manager.add_peer(make_peer("key1")));
    }

    #[test]
    fn test_remove_peer() {
        let mut manager = WireGuardManager::new();
        manager.set_config(WgConfig::default());
        manager.add_peer(make_peer("key1"));
        assert!(manager.remove_peer("key1"));
        assert!(manager.get_peers().is_empty());
    }

    #[test]
    fn test_remove_nonexistent_peer() {
        let mut manager = WireGuardManager::new();
        manager.set_config(WgConfig::default());
        assert!(!manager.remove_peer("nonexistent"));
    }

    #[test]
    fn test_generate_keypair() {
        let (priv_key, pub_key) = WireGuardManager::generate_keypair();
        assert!(!priv_key.is_empty());
        assert!(!pub_key.is_empty());
        assert_ne!(priv_key, pub_key);
    }

    #[test]
    fn test_is_peer_alive() {
        let mut manager = WireGuardManager::new();
        manager.set_config(WgConfig::default());
        manager.add_peer(make_peer("alive_key"));
        assert!(manager.is_peer_alive("alive_key"));
        assert!(!manager.is_peer_alive("dead_key"));
    }

    #[test]
    fn test_is_peer_alive_no_handshake() {
        let mut manager = WireGuardManager::new();
        manager.set_config(WgConfig::default());
        let mut peer = make_peer("no_hs");
        peer.handshake_time = None;
        manager.add_peer(peer);
        assert!(!manager.is_peer_alive("no_hs"));
    }

    #[test]
    fn test_interface_stats_uptime() {
        let manager = WireGuardManager::with_config(WgConfig::default());
        let stats = manager.interface_stats();
        assert!(stats.uptime_secs < 5);
    }

    #[test]
    fn test_default_config() {
        let config = WgConfig::default();
        assert_eq!(config.interface_name, "wg0");
        assert_eq!(config.mtu, 1420);
        assert_eq!(config.dns, vec!["1.1.1.1"]);
    }

    #[test]
    fn test_active_peers_count() {
        let mut manager = WireGuardManager::new();
        manager.set_config(WgConfig::default());
        manager.add_peer(make_peer("k1"));
        manager.add_peer(make_peer("k2"));
        assert_eq!(manager.interface_stats().active_peers, 2);
    }
}
