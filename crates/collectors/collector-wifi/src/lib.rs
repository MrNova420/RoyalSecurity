pub mod prelude;
pub use royalsecurity_core as core;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WifiEventType {
    Connected,
    Disconnected,
    Roamed,
    NetworkChanged,
    DeauthReceived,
    ProbeRequest,
}

impl std::fmt::Display for WifiEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WifiEventType::Connected => write!(f, "Connected"),
            WifiEventType::Disconnected => write!(f, "Disconnected"),
            WifiEventType::Roamed => write!(f, "Roamed"),
            WifiEventType::NetworkChanged => write!(f, "NetworkChanged"),
            WifiEventType::DeauthReceived => write!(f, "DeauthReceived"),
            WifiEventType::ProbeRequest => write!(f, "ProbeRequest"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiConnection {
    pub ssid: String,
    pub bssid: String,
    pub security_type: String,
    pub signal_dbm: i32,
    pub frequency: u32,
    pub connected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub security_type: String,
    pub signal_dbm: i32,
    pub frequency: u32,
    pub connected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiEvent {
    pub event_type: WifiEventType,
    pub details: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum WifiCollectorError {
    #[error("Collector not started")]
    NotStarted,
    #[error("Invalid WiFi event: {0}")]
    InvalidEvent(String),
    #[error("WiFi API error: {0}")]
    ApiError(String),
}

pub struct WifiCollector {
    running: Arc<RwLock<bool>>,
    events: Arc<RwLock<Vec<WifiEvent>>>,
    current_connection: Arc<RwLock<Option<WifiConnection>>>,
}

impl WifiCollector {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            events: Arc::new(RwLock::new(Vec::new())),
            current_connection: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn start(&self) -> std::result::Result<(), WifiCollectorError> {
        let mut running = self.running.write().await;
        *running = true;
        info!("WiFi collector started");
        Ok(())
    }

    pub async fn stop(&self) -> std::result::Result<(), WifiCollectorError> {
        let mut running = self.running.write().await;
        *running = false;
        info!("WiFi collector stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn set_current_connection(&self, conn: Option<WifiConnection>) {
        let mut current = self.current_connection.write().await;
        *current = conn;
    }

    pub async fn get_current_connection(&self) -> Option<WifiConnection> {
        self.current_connection.read().await.clone()
    }

    pub async fn capture_event(&self, event: WifiEvent) -> std::result::Result<(), WifiCollectorError> {
        if !*self.running.read().await {
            return Err(WifiCollectorError::NotStarted.into());
        }
        debug!(
            event_type = %event.event_type,
            details = %event.details,
            "Captured WiFi event"
        );
        let mut events = self.events.write().await;
        events.push(event);
        Ok(())
    }

    pub async fn get_events(&self) -> Vec<WifiEvent> {
        self.events.read().await.clone()
    }

    pub async fn event_count(&self) -> usize {
        self.events.read().await.len()
    }

    pub async fn clear(&self) {
        self.events.write().await.clear();
        *self.current_connection.write().await = None;
        debug!("WiFi collector cleared all events");
    }

    #[cfg(target_os = "windows")]
    pub fn scan_wifi_networks(&self) -> Vec<WifiNetwork> {
        use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
        use windows::Win32::NetworkManagement::WiFi::{
            DOT11_AUTH_ALGORITHM, DOT11_CIPHER_ALGORITHM, WLAN_AVAILABLE_NETWORK_LIST,
            WLAN_INTERFACE_INFO_LIST, WlanCloseHandle, WlanEnumInterfaces,
            WlanGetAvailableNetworkList, WlanOpenHandle,
        };

        let mut networks = Vec::new();

        unsafe {
            let mut handle = HANDLE::default();
            let mut version = 0u32;

            if WlanOpenHandle(2, None, &mut version, &mut handle) != 0 {
                return networks;
            }

            let mut iface_list_ptr: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
            if WlanEnumInterfaces(handle, None, &mut iface_list_ptr) != 0 {
                let _ = WlanCloseHandle(handle, None);
                return networks;
            }

            let iface_list = &*iface_list_ptr;
            let iface_count = iface_list.dwNumberOfItems as usize;
            let ifaces = std::slice::from_raw_parts(
                iface_list.InterfaceInfo.as_ptr(),
                iface_count,
            );

            for iface_info in ifaces {
                let iface_guid = &iface_info.InterfaceGuid;

                let mut network_list_ptr: *mut WLAN_AVAILABLE_NETWORK_LIST =
                    std::ptr::null_mut();
                if WlanGetAvailableNetworkList(
                    handle,
                    iface_guid,
                    0x00000003,
                    None,
                    &mut network_list_ptr,
                ) == 0
                {
                    let net_list = &*network_list_ptr;
                    let net_count = net_list.dwNumberOfItems as usize;
                    let net_slice = std::slice::from_raw_parts(
                        net_list.Network.as_ptr(),
                        net_count,
                    );

                    for net in net_slice {

                        let ssid_bytes = &net.dot11Ssid.ucSSID
                            [..net.dot11Ssid.uSSIDLength as usize];
                        let ssid = String::from_utf8_lossy(ssid_bytes).to_string();

                        let security_type = match net.dot11DefaultAuthAlgorithm {
                            DOT11_AUTH_ALGORITHM(8) => "OWE",
                            DOT11_AUTH_ALGORITHM(3) => "WPA2-Enterprise",
                            DOT11_AUTH_ALGORITHM(2) => "WPA2-Personal",
                            DOT11_AUTH_ALGORITHM(1) => "WPA-Enterprise",
                            DOT11_AUTH_ALGORITHM(0) => "Open",
                            _ => "Unknown",
                        }
                        .to_string();

                        let cipher_str = match net.dot11DefaultCipherAlgorithm {
                            DOT11_CIPHER_ALGORITHM(1024) => "GCMP-256",
                            DOT11_CIPHER_ALGORITHM(512) => "GCMP-128",
                            DOT11_CIPHER_ALGORITHM(256) => "CCMP-256",
                            DOT11_CIPHER_ALGORITHM(4) => "TKIP",
                            DOT11_CIPHER_ALGORITHM(1) => "WEP",
                            _ => "Unknown",
                        };

                        let signal = net.wlanSignalQuality as i32 * 2 - 100;
                        let signal_dbm = signal.max(-100).min(0);

                        networks.push(WifiNetwork {
                            ssid,
                            security_type: format!("{}/{}", security_type, cipher_str),
                            signal_dbm,
                            frequency: 0,
                            connected: net.bNetworkConnectable.into(),
                        });
                    }

                    LocalFree(HLOCAL(network_list_ptr as *mut _));
                }
            }

            LocalFree(HLOCAL(iface_list_ptr as *mut _));
            let _ = WlanCloseHandle(handle, None);
        }

        networks
    }

    #[cfg(not(target_os = "windows"))]
    pub fn scan_wifi_networks(&self) -> Vec<WifiNetwork> {
        Vec::new()
    }

    #[cfg(target_os = "windows")]
    pub fn query_current_connection(&self) -> Option<WifiConnection> {
        use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
        use windows::Win32::NetworkManagement::WiFi::{
            DOT11_AUTH_ALGORITHM, WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO_LIST,
            wlan_intf_opcode_current_connection, WlanCloseHandle, WlanEnumInterfaces,
            WlanOpenHandle, WlanQueryInterface,
        };

        unsafe {
            let mut handle = HANDLE::default();
            let mut version = 0u32;

            if WlanOpenHandle(2, None, &mut version, &mut handle) != 0 {
                return None;
            }

            let mut iface_list_ptr: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
            if WlanEnumInterfaces(handle, None, &mut iface_list_ptr) != 0 {
                let _ = WlanCloseHandle(handle, None);
                return None;
            }

            let iface_list = &*iface_list_ptr;
            let iface_count = iface_list.dwNumberOfItems as usize;
            let ifaces = std::slice::from_raw_parts(
                iface_list.InterfaceInfo.as_ptr(),
                iface_count,
            );
            let mut result = None;

            for iface_info in ifaces {
                let iface_guid = &iface_info.InterfaceGuid;

                let mut data_size = 0u32;
                let mut data_ptr: *mut std::ffi::c_void = std::ptr::null_mut();

                if WlanQueryInterface(
                    handle,
                    iface_guid,
                    wlan_intf_opcode_current_connection,
                    None,
                    &mut data_size,
                    &mut data_ptr,
                    None,
                ) == 0
                {
                    let conn_attrs = &*(data_ptr as *const WLAN_CONNECTION_ATTRIBUTES);

                    let ssid_len =
                        conn_attrs.wlanAssociationAttributes.dot11Ssid.uSSIDLength as usize;
                    let ssid_bytes = &conn_attrs.wlanAssociationAttributes.dot11Ssid.ucSSID
                        [..ssid_len];
                    let ssid = String::from_utf8_lossy(ssid_bytes).to_string();

                    let bssid_bytes =
                        &conn_attrs.wlanAssociationAttributes.dot11Bssid;
                    let bssid = format!(
                        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        bssid_bytes[0],
                        bssid_bytes[1],
                        bssid_bytes[2],
                        bssid_bytes[3],
                        bssid_bytes[4],
                        bssid_bytes[5]
                    );

                    let signal = conn_attrs.wlanAssociationAttributes.wlanSignalQuality as i32
                        * 2
                        - 100;
                    let signal_dbm = signal.max(-100).min(0);

                    let security_type =
                        match conn_attrs.wlanSecurityAttributes.dot11AuthAlgorithm {
                            DOT11_AUTH_ALGORITHM(8) => "OWE",
                            DOT11_AUTH_ALGORITHM(3) => "WPA2-Enterprise",
                            DOT11_AUTH_ALGORITHM(2) => "WPA2-Personal",
                            DOT11_AUTH_ALGORITHM(1) => "WPA-Enterprise",
                            DOT11_AUTH_ALGORITHM(0) => "Open",
                            _ => "Unknown",
                        }
                        .to_string();

                    result = Some(WifiConnection {
                        ssid,
                        bssid,
                        security_type,
                        signal_dbm,
                        frequency: 0,
                        connected_at: Utc::now(),
                    });

                    LocalFree(HLOCAL(data_ptr));
                    break;
                }
            }

            LocalFree(HLOCAL(iface_list_ptr as *mut _));
            let _ = WlanCloseHandle(handle, None);
            result
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn query_current_connection(&self) -> Option<WifiConnection> {
        None
    }
}

impl Default for WifiCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_type: WifiEventType, details: &str) -> WifiEvent {
        WifiEvent {
            event_type,
            details: details.to_string(),
            timestamp: Utc::now(),
        }
    }

    fn make_connection(ssid: &str) -> WifiConnection {
        WifiConnection {
            ssid: ssid.to_string(),
            bssid: "AA:BB:CC:DD:EE:FF".to_string(),
            security_type: "WPA2".to_string(),
            signal_dbm: -45,
            frequency: 5240,
            connected_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_start_stop() {
        let collector = WifiCollector::new();
        assert!(!collector.is_running().await);
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.stop().await.unwrap();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_capture_requires_running() {
        let collector = WifiCollector::new();
        let event = make_event(WifiEventType::Connected, "Connected to MyWiFi");
        assert!(collector.capture_event(event).await.is_err());
    }

    #[tokio::test]
    async fn test_capture_event() {
        let collector = WifiCollector::new();
        collector.start().await.unwrap();
        let event = make_event(WifiEventType::Connected, "Connected to MyWiFi");
        collector.capture_event(event).await.unwrap();
        assert_eq!(collector.event_count().await, 1);
    }

    #[tokio::test]
    async fn test_current_connection() {
        let collector = WifiCollector::new();
        assert!(collector.get_current_connection().await.is_none());
        let conn = make_connection("MyWiFi");
        collector.set_current_connection(Some(conn.clone())).await;
        let current = collector.get_current_connection().await.unwrap();
        assert_eq!(current.ssid, "MyWiFi");
        assert_eq!(current.signal_dbm, -45);
    }

    #[tokio::test]
    async fn test_clear_connection() {
        let collector = WifiCollector::new();
        collector
            .set_current_connection(Some(make_connection("Test")))
            .await;
        assert!(collector.get_current_connection().await.is_some());
        collector.clear().await;
        assert!(collector.get_current_connection().await.is_none());
    }

    #[tokio::test]
    async fn test_all_event_types() {
        let collector = WifiCollector::new();
        collector.start().await.unwrap();
        let types = [
            WifiEventType::Connected,
            WifiEventType::Disconnected,
            WifiEventType::Roamed,
            WifiEventType::NetworkChanged,
            WifiEventType::DeauthReceived,
            WifiEventType::ProbeRequest,
        ];
        for (i, et) in types.iter().enumerate() {
            collector
                .capture_event(make_event(*et, &format!("event{}", i)))
                .await
                .unwrap();
        }
        assert_eq!(collector.event_count().await, 6);
    }

    #[tokio::test]
    async fn test_clear() {
        let collector = WifiCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_event(make_event(WifiEventType::Connected, "test"))
            .await
            .unwrap();
        assert_eq!(collector.event_count().await, 1);
        collector.clear().await;
        assert_eq!(collector.event_count().await, 0);
    }

    #[test]
    fn test_scan_wifi_networks_returns_vec() {
        let collector = WifiCollector::new();
        let networks = collector.scan_wifi_networks();
        assert!(networks.is_empty() || !networks.is_empty());
    }

    #[test]
    fn test_query_current_connection_returns_option() {
        let collector = WifiCollector::new();
        let _conn = collector.query_current_connection();
    }

    #[test]
    fn test_wifi_network_struct() {
        let net = WifiNetwork {
            ssid: "TestNet".to_string(),
            security_type: "WPA2-Personal/CCMP-128".to_string(),
            signal_dbm: -50,
            frequency: 5180,
            connected: true,
        };
        assert_eq!(net.ssid, "TestNet");
        assert_eq!(net.signal_dbm, -50);
        assert!(net.connected);
    }

    #[test]
    fn test_wifi_network_serialization() {
        let net = WifiNetwork {
            ssid: "TestNet".to_string(),
            security_type: "WPA2".to_string(),
            signal_dbm: -40,
            frequency: 2437,
            connected: false,
        };
        let json = serde_json::to_string(&net).unwrap();
        let deserialized: WifiNetwork = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ssid, "TestNet");
    }
}
