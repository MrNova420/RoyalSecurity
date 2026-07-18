pub mod prelude;

use chrono::{DateTime, Utc};
use royalsecurity_common::types::{EventSeverity, NetworkEvent, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum TorError {
    #[error("not connected to Tor network")]
    NotConnected,
    #[error("circuit build failed: {0}")]
    CircuitBuildFailed(String),
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("hidden service error: {0}")]
    HiddenServiceError(String),
}

// ---------------------------------------------------------------------------
// TorCircuit
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorCircuit {
    pub id: u32,
    pub guard_node: String,
    pub middle_node: String,
    pub exit_node: String,
    pub created_at: DateTime<Utc>,
    pub is_established: bool,
}

// ---------------------------------------------------------------------------
// TorConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    pub socks_port: u16,
    pub control_port: u16,
    pub data_dir: String,
    pub bridge_lines: Vec<String>,
    pub use_bridges: bool,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            socks_port: 9050,
            control_port: 9051,
            data_dir: "/var/lib/tor".to_string(),
            bridge_lines: Vec::new(),
            use_bridges: false,
        }
    }
}

// ---------------------------------------------------------------------------
// HiddenService
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiddenService {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub local_port: u16,
}

// ---------------------------------------------------------------------------
// TorConnection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConnection {
    pub circuit_id: u32,
    pub remote_addr: String,
    pub connected_at: DateTime<Utc>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

// ---------------------------------------------------------------------------
// TorClient
// ---------------------------------------------------------------------------

pub struct TorClient {
    config: TorConfig,
    circuits: Vec<TorCircuit>,
    hidden_services: Vec<HiddenService>,
    connections: Vec<TorConnection>,
    connected: bool,
    next_circuit_id: u32,
}

impl TorClient {
    pub fn new() -> Self {
        Self::with_config(TorConfig::default())
    }

    pub fn with_config(config: TorConfig) -> Self {
        info!(
            socks_port = config.socks_port,
            control_port = config.control_port,
            use_bridges = config.use_bridges,
            "Initialized Tor client"
        );
        Self {
            config,
            circuits: Vec::new(),
            hidden_services: Vec::new(),
            connections: Vec::new(),
            connected: false,
            next_circuit_id: 1,
        }
    }

    pub fn build_circuit(&mut self) -> TorCircuit {
        let circuit = TorCircuit {
            id: self.next_circuit_id,
            guard_node: format!("guard-{}", self.next_circuit_id),
            middle_node: format!("middle-{}", self.next_circuit_id),
            exit_node: format!("exit-{}", self.next_circuit_id),
            created_at: Utc::now(),
            is_established: true,
        };

        self.next_circuit_id += 1;
        info!(circuit_id = circuit.id, "Built new Tor circuit");
        self.circuits.push(circuit.clone());
        self.connected = true;
        circuit
    }

    pub fn connect_through_tor(
        &mut self,
        address: &str,
        port: u16,
    ) -> Option<TorConnection> {
        let circuit = self.circuits.iter().find(|c| c.is_established).cloned()?;
        let conn = TorConnection {
            circuit_id: circuit.id,
            remote_addr: format!("{address}:{port}"),
            connected_at: Utc::now(),
            bytes_in: 0,
            bytes_out: 0,
        };

        info!(
            circuit_id = circuit.id,
            address = %address,
            port = port,
            "Connected through Tor"
        );
        self.connections.push(conn.clone());
        Some(conn)
    }

    pub fn add_hidden_service(&mut self, service: HiddenService) {
        info!(
            name = %service.name,
            address = %service.address,
            port = service.port,
            "Registered hidden service"
        );
        self.hidden_services.push(service);
    }

    pub fn is_connected(&self) -> bool {
        self.connected && self.circuits.iter().any(|c| c.is_established)
    }

    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    pub fn config(&self) -> &TorConfig {
        &self.config
    }

    pub fn circuits(&self) -> &[TorCircuit] {
        &self.circuits
    }

    pub fn connections(&self) -> &[TorConnection] {
        &self.connections
    }

    pub fn hidden_services(&self) -> &[HiddenService] {
        &self.hidden_services
    }

    pub fn close_circuit(&mut self, circuit_id: u32) -> bool {
        if let Some(circuit) = self.circuits.iter_mut().find(|c| c.id == circuit_id) {
            circuit.is_established = false;
            info!(circuit_id = circuit_id, "Closed Tor circuit");
            return true;
        }
        false
    }
}

impl Default for TorClient {
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

    #[test]
    fn test_new_tor_client() {
        let client = TorClient::new();
        assert!(!client.is_connected());
        assert_eq!(client.circuit_count(), 0);
    }

    #[test]
    fn test_with_config() {
        let config = TorConfig {
            socks_port: 19050,
            control_port: 19051,
            use_bridges: true,
            ..Default::default()
        };
        let client = TorClient::with_config(config);
        assert_eq!(client.config().socks_port, 19050);
        assert!(client.config().use_bridges);
    }

    #[test]
    fn test_build_circuit() {
        let mut client = TorClient::new();
        let circuit = client.build_circuit();
        assert_eq!(circuit.id, 1);
        assert!(circuit.is_established);
        assert_eq!(client.circuit_count(), 1);
    }

    #[test]
    fn test_build_multiple_circuits() {
        let mut client = TorClient::new();
        let c1 = client.build_circuit();
        let c2 = client.build_circuit();
        assert_ne!(c1.id, c2.id);
        assert_eq!(client.circuit_count(), 2);
    }

    #[test]
    fn test_connect_through_tor() {
        let mut client = TorClient::new();
        client.build_circuit();
        let conn = client.connect_through_tor("example.onion", 80);
        assert!(conn.is_some());
        let conn = conn.unwrap();
        assert_eq!(conn.remote_addr, "example.onion:80");
        assert_eq!(conn.bytes_in, 0);
    }

    #[test]
    fn test_connect_without_circuit() {
        let mut client = TorClient::new();
        let conn = client.connect_through_tor("example.onion", 80);
        assert!(conn.is_none());
    }

    #[test]
    fn test_add_hidden_service() {
        let mut client = TorClient::new();
        let service = HiddenService {
            name: "my-service".to_string(),
            address: "abc123.onion".to_string(),
            port: 80,
            local_port: 8080,
        };
        client.add_hidden_service(service);
        assert_eq!(client.hidden_services().len(), 1);
        assert_eq!(client.hidden_services()[0].name, "my-service");
    }

    #[test]
    fn test_is_connected_after_circuit() {
        let mut client = TorClient::new();
        assert!(!client.is_connected());
        client.build_circuit();
        assert!(client.is_connected());
    }

    #[test]
    fn test_close_circuit() {
        let mut client = TorClient::new();
        let circuit = client.build_circuit();
        assert!(client.close_circuit(circuit.id));
        assert!(!client.is_connected());
    }

    #[test]
    fn test_close_nonexistent_circuit() {
        let mut client = TorClient::new();
        assert!(!client.close_circuit(999));
    }

    #[test]
    fn test_default_config() {
        let config = TorConfig::default();
        assert_eq!(config.socks_port, 9050);
        assert_eq!(config.control_port, 9051);
        assert!(!config.use_bridges);
    }
}
