pub mod prelude;
pub use royalsecurity_core as core;

use chrono::{DateTime, TimeDelta, Utc};
use royalsecurity_common::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryChange {
    pub key_path: String,
    pub value_name: String,
    pub value_data: Option<String>,
    pub action: RegistryAction,
    pub process_name: String,
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryCollectorError {
    #[error("Collector not started")]
    NotStarted,
    #[error("Invalid registry change: {0}")]
    InvalidChange(String),
    #[error("Registry key not found: {0}")]
    KeyNotFound(String),
    #[error("Failed to create event: {0}")]
    EventCreationFailed(String),
    #[error("Failed to register notification: {0}")]
    NotificationFailed(String),
}

pub struct RegistryCollector {
    running: Arc<RwLock<bool>>,
    changes: Arc<RwLock<Vec<RegistryChange>>>,
}

pub struct WatchedKey {
    pub name: &'static str,
    pub root: &'static str,
    pub subkey: &'static str,
}

pub fn get_watched_keys() -> Vec<WatchedKey> {
    vec![
        WatchedKey {
            name: "Startup Persistence (Run)",
            root: "HKLM",
            subkey: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        },
        WatchedKey {
            name: "Startup Persistence (RunOnce)",
            root: "HKLM",
            subkey: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        },
        WatchedKey {
            name: "User Startup Persistence (Run)",
            root: "HKCU",
            subkey: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        },
        WatchedKey {
            name: "Services",
            root: "HKLM",
            subkey: "SYSTEM\\CurrentControlSet\\Services",
        },
        WatchedKey {
            name: "Winlogon",
            root: "HKLM",
            subkey: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        },
    ]
}

impl RegistryCollector {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            changes: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn start(&self) -> std::result::Result<(), RegistryCollectorError> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }
        *running = true;

        #[cfg(target_os = "windows")]
        {
            let changes = self.changes.clone();
            let running = self.running.clone();
            std::thread::spawn(move || {
                monitor_registry_keys(changes, running);
            });
        }

        info!("Registry collector started");
        Ok(())
    }

    pub async fn stop(&self) -> std::result::Result<(), RegistryCollectorError> {
        let mut running = self.running.write().await;
        *running = false;
        info!("Registry collector stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn capture_change(
        &self,
        event: RegistryChange,
    ) -> std::result::Result<(), RegistryCollectorError> {
        if !*self.running.read().await {
            return Err(RegistryCollectorError::NotStarted.into());
        }
        if event.key_path.is_empty() {
            return Err(RegistryCollectorError::InvalidChange(
                "Empty key path".into(),
            )
            .into());
        }
        debug!(
            key = %event.key_path,
            action = %event.action,
            pid = event.pid,
            "Captured registry change"
        );
        let mut changes = self.changes.write().await;
        changes.push(event);
        Ok(())
    }

    pub async fn get_changes(&self) -> Vec<RegistryChange> {
        self.changes.read().await.clone()
    }

    pub async fn get_changes_by_key(&self, key: &str) -> Vec<RegistryChange> {
        self.changes
            .read()
            .await
            .iter()
            .filter(|c| c.key_path.contains(key))
            .cloned()
            .collect()
    }

    pub async fn change_count(&self) -> usize {
        self.changes.read().await.len()
    }

    pub async fn purge_old(&self, max_age_secs: u64) {
        let cutoff = Utc::now() - TimeDelta::seconds(max_age_secs as i64);
        let mut changes = self.changes.write().await;
        let before = changes.len();
        changes.retain(|c| c.timestamp > cutoff);
        let purged = before - changes.len();
        if purged > 0 {
            debug!("Purged {} old registry changes", purged);
        }
    }

    pub async fn clear(&self) {
        self.changes.write().await.clear();
        debug!("Registry collector cleared all changes");
    }

    pub async fn watched_key_paths(&self) -> Vec<String> {
        get_watched_keys()
            .iter()
            .map(|k| format!("{}\\{}", k.root, k.subkey))
            .collect()
    }
}

impl Default for RegistryCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Win32 Registry Change-Notification Helpers
// ═══════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
pub fn open_registry_key(
    root: &str,
    subkey: &str,
) -> std::result::Result<
    windows::Win32::System::Registry::HKEY,
    RegistryCollectorError,
> {
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    use windows::core::PCWSTR;

    let root_hkey = match root {
        "HKLM" => HKEY_LOCAL_MACHINE,
        "HKCU" => HKEY_CURRENT_USER,
        _ => {
            return Err(RegistryCollectorError::KeyNotFound(format!(
                "Unknown hive: {root}"
            )))
        }
    };

    let wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut hkey: windows::Win32::System::Registry::HKEY = Default::default();

    unsafe {
        let err = RegOpenKeyExW(
            root_hkey,
            PCWSTR::from_raw(wide.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        );
        if err.is_err() {
            return Err(RegistryCollectorError::KeyNotFound(format!(
                "{root}\\{subkey}: error {:#x}",
                err.0
            )));
        }
    }

    Ok(hkey)
}

#[cfg(not(target_os = "windows"))]
pub fn open_registry_key(
    _root: &str,
    _subkey: &str,
) -> std::result::Result<(), RegistryCollectorError> {
    Err(RegistryCollectorError::KeyNotFound(
        "Registry not available on this platform".into(),
    ))
}

#[cfg(target_os = "windows")]
pub fn create_notification_event() -> std::result::Result<
    windows::Win32::Foundation::HANDLE,
    RegistryCollectorError,
> {
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::System::Threading::CreateEventW;

    unsafe {
        CreateEventW(None, BOOL(1), BOOL(0), None).map_err(|e| {
            RegistryCollectorError::EventCreationFailed(e.to_string())
        })
    }
}

#[cfg(target_os = "windows")]
pub fn register_notification(
    hkey: windows::Win32::System::Registry::HKEY,
    event: windows::Win32::Foundation::HANDLE,
) -> std::result::Result<(), RegistryCollectorError> {
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::System::Registry::{RegNotifyChangeKeyValue, REG_NOTIFY_CHANGE_LAST_SET};

    unsafe {
        let err = RegNotifyChangeKeyValue(
            hkey,
            BOOL(1),
            REG_NOTIFY_CHANGE_LAST_SET,
            event,
            BOOL(1),
        );
        if err.is_err() {
            return Err(RegistryCollectorError::NotificationFailed(format!(
                "error {:#x}",
                err.0
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn read_key_values(
    hkey: windows::Win32::System::Registry::HKEY,
) -> Vec<(String, String)> {
    use windows::Win32::System::Registry::RegEnumValueW;
    use windows::core::PWSTR;

    let mut values = Vec::new();
    let mut index = 0;

    unsafe {
        loop {
            let mut name_buf = [0u16; 256];
            let mut name_len = 256u32;
            let mut data_buf = [0u8; 4096];
            let mut data_len = 4096u32;
            let mut reg_type: u32 = 0;

            let result = RegEnumValueW(
                hkey,
                index,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                Some(&mut reg_type),
                Some(data_buf.as_mut_ptr() as *mut u8),
                Some(&mut data_len),
            );

            if result.is_err() {
                break;
            }

            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]).to_string();
            let data_str = match reg_type {
                1 => String::from_utf16_lossy(
                    &data_buf[..data_len as usize]
                        .chunks_exact(2)
                        .map(|c| u16::from_ne_bytes([c[0], c[1]]))
                        .collect::<Vec<_>>(),
                )
                .trim_end_matches('\0')
                .to_string(),
                4 => {
                    let val = u32::from_ne_bytes([
                        data_buf[0],
                        data_buf[1],
                        data_buf[2],
                        data_buf[3],
                    ]);
                    format!("{val}")
                }
                _ => format!("{:?}", &data_buf[..data_len as usize]),
            };

            values.push((name, data_str));
            index += 1;
        }
    }

    values
}

// ═══════════════════════════════════════════════════════════════
//  Real-time Registry Monitoring Loop
// ═══════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
fn monitor_registry_keys(
    changes: Arc<RwLock<Vec<RegistryChange>>>,
    running: Arc<RwLock<bool>>,
) {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Registry::{RegCloseKey, HKEY};
    use windows::Win32::System::Threading::WaitForSingleObject;

    const POLL_TIMEOUT_MS: u32 = 500;

    struct KeyWatcher {
        hkey: HKEY,
        event: HANDLE,
        display_name: String,
        key_path: String,
    }

    let watched = get_watched_keys();
    let mut watchers: Vec<KeyWatcher> = Vec::new();

    for wk in &watched {
        let hkey = match open_registry_key(wk.root, wk.subkey) {
            Ok(h) => h,
            Err(e) => {
                warn!("Failed to open {}\\{}: {}", wk.root, wk.subkey, e);
                continue;
            }
        };

        let event = match create_notification_event() {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to create event for {}: {}", wk.subkey, e);
                unsafe {
                    let _ = RegCloseKey(hkey);
                }
                continue;
            }
        };

        if register_notification(hkey, event).is_err() {
            unsafe {
                CloseHandle(event).ok();
                let _ = RegCloseKey(hkey);
            }
            continue;
        }

        watchers.push(KeyWatcher {
            hkey,
            event,
            display_name: wk.name.to_string(),
            key_path: format!("{}\\{}", wk.root, wk.subkey),
        });
    }

    if watchers.is_empty() {
        error!("No registry keys could be opened for monitoring");
        return;
    }

    info!("Monitoring {} registry keys for changes", watchers.len());

    loop {
        if !*running.blocking_read() {
            break;
        }

        for watcher in &mut watchers {
            unsafe {
                let wait_result = WaitForSingleObject(watcher.event, POLL_TIMEOUT_MS);
                if wait_result.0 == 0 {
                    let values = read_key_values(watcher.hkey);

                    let change = RegistryChange {
                        key_path: watcher.key_path.clone(),
                        value_name: if values.is_empty() {
                            "(no values)".to_string()
                        } else {
                            values
                                .iter()
                                .take(5)
                                .map(|(n, _)| n.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        },
                        value_data: values.first().map(|(_, v)| v.clone()),
                        action: RegistryAction::Modified,
                        process_name: "unknown".to_string(),
                        pid: 0,
                        timestamp: Utc::now(),
                    };

                    if *running.blocking_read() {
                        changes.blocking_write().push(change);
                        debug!("Change detected in: {}", watcher.display_name);
                    }

                    use windows::Win32::System::Threading::ResetEvent;
                    ResetEvent(watcher.event).ok();
                    register_notification(watcher.hkey, watcher.event).ok();
                }
            }
        }
    }

    unsafe {
        for watcher in watchers {
            CloseHandle(watcher.event).ok();
            let _ = RegCloseKey(watcher.hkey);
        }
    }

    info!("Registry monitoring stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_change(key: &str, action: RegistryAction) -> RegistryChange {
        RegistryChange {
            key_path: key.to_string(),
            value_name: "TestValue".to_string(),
            value_data: Some("TestData".to_string()),
            action,
            process_name: "test.exe".to_string(),
            pid: 1234,
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_new_collector_is_not_running() {
        let collector = RegistryCollector::new();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let collector = RegistryCollector::new();
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.stop().await.unwrap();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_capture_requires_running() {
        let collector = RegistryCollector::new();
        let event = make_change("HKLM\\Software\\Test", RegistryAction::Created);
        assert!(collector.capture_change(event).await.is_err());
    }

    #[tokio::test]
    async fn test_capture_change() {
        let collector = RegistryCollector::new();
        collector.start().await.unwrap();
        let event = make_change("HKLM\\Software\\Test", RegistryAction::Created);
        collector.capture_change(event).await.unwrap();
        assert_eq!(collector.change_count().await, 1);
    }

    #[tokio::test]
    async fn test_reject_empty_key() {
        let collector = RegistryCollector::new();
        collector.start().await.unwrap();
        let event = make_change("", RegistryAction::Created);
        assert!(collector.capture_change(event).await.is_err());
    }

    #[tokio::test]
    async fn test_get_changes_by_key() {
        let collector = RegistryCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_change(make_change(
                "HKLM\\Software\\Microsoft",
                RegistryAction::Created,
            ))
            .await
            .unwrap();
        collector
            .capture_change(make_change(
                "HKLM\\Software\\Test",
                RegistryAction::Modified,
            ))
            .await
            .unwrap();
        collector
            .capture_change(make_change(
                "HKCU\\Environment",
                RegistryAction::Deleted,
            ))
            .await
            .unwrap();

        let ms_changes = collector.get_changes_by_key("Microsoft").await;
        assert_eq!(ms_changes.len(), 1);

        let all_hklm = collector.get_changes_by_key("HKLM").await;
        assert_eq!(all_hklm.len(), 2);
    }

    #[tokio::test]
    async fn test_purge_old() {
        let collector = RegistryCollector::new();
        collector.start().await.unwrap();
        let mut old_event = make_change("HKLM\\Old", RegistryAction::Created);
        old_event.timestamp = Utc::now() - TimeDelta::seconds(3600);
        collector.capture_change(old_event).await.unwrap();
        collector
            .capture_change(make_change("HKLM\\New", RegistryAction::Created))
            .await
            .unwrap();
        assert_eq!(collector.change_count().await, 2);

        collector.purge_old(60).await;
        assert_eq!(collector.change_count().await, 1);
    }

    #[tokio::test]
    async fn test_clear() {
        let collector = RegistryCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_change(make_change("HKLM\\Test", RegistryAction::Created))
            .await
            .unwrap();
        assert_eq!(collector.change_count().await, 1);
        collector.clear().await;
        assert_eq!(collector.change_count().await, 0);
    }

    #[test]
    fn test_watched_keys_count() {
        let keys = get_watched_keys();
        assert_eq!(keys.len(), 5);
    }

    #[test]
    fn test_watched_keys_include_persistence() {
        let keys = get_watched_keys();
        assert!(keys.iter().any(|k| k.subkey.contains("Run")));
        assert!(keys.iter().any(|k| k.subkey.contains("RunOnce")));
        assert!(keys.iter().any(|k| k.subkey.contains("Services")));
        assert!(keys.iter().any(|k| k.subkey.contains("Winlogon")));
    }

    #[test]
    fn test_watched_keys_have_valid_roots() {
        let keys = get_watched_keys();
        for key in &keys {
            assert!(
                key.root == "HKLM" || key.root == "HKCU",
                "Invalid root: {}",
                key.root
            );
        }
    }

    #[test]
    fn test_watched_keys_all_nonempty() {
        let keys = get_watched_keys();
        for key in &keys {
            assert!(!key.name.is_empty());
            assert!(!key.subkey.is_empty());
        }
    }

    #[tokio::test]
    async fn test_watched_key_paths() {
        let collector = RegistryCollector::new();
        let paths = collector.watched_key_paths().await;
        assert_eq!(paths.len(), 5);
        assert!(paths.iter().any(|p| p.contains("CurrentVersion\\Run")));
        assert!(paths.iter().any(|p| p.contains("Services")));
        assert!(paths.iter().any(|p| p.contains("Winlogon")));
    }

    #[tokio::test]
    async fn test_start_idempotent() {
        let collector = RegistryCollector::new();
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_capture_after_stop() {
        let collector = RegistryCollector::new();
        collector.start().await.unwrap();
        collector.stop().await.unwrap();
        let event = make_change("HKLM\\Software\\Test", RegistryAction::Created);
        assert!(collector.capture_change(event).await.is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_open_registry_key_known_key() {
        let result =
            open_registry_key("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
        assert!(
            result.is_ok(),
            "Failed to open known key: {:?}",
            result.err()
        );
        unsafe {
            let _ = windows::Win32::System::Registry::RegCloseKey(result.unwrap());
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_open_registry_key_invalid_path() {
        let result = open_registry_key("HKLM", "NONEXISTENT\\FAKE\\PATH\\TO\\KEY");
        assert!(result.is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_open_registry_key_unknown_hive() {
        let result = open_registry_key("HKUZ", "SOFTWARE\\Test");
        assert!(result.is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_create_notification_event() {
        let result = create_notification_event();
        assert!(
            result.is_ok(),
            "Failed to create event: {:?}",
            result.err()
        );
        unsafe {
            windows::Win32::Foundation::CloseHandle(result.unwrap()).ok();
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_register_notification_on_known_key() {
        let hkey = open_registry_key(
            "HKLM",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        )
        .expect("open key");
        let event = create_notification_event().expect("create event");
        let result = register_notification(hkey, event);
        assert!(
            result.is_ok(),
            "Failed to register notification: {:?}",
            result.err()
        );
        unsafe {
            windows::Win32::Foundation::CloseHandle(event).ok();
            let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_read_key_values_on_known_key() {
        let hkey = open_registry_key(
            "HKLM",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        )
        .expect("open key");
        let values = read_key_values(hkey);
        assert!(!values.is_empty(), "Expected at least one value");
        assert!(
            !values[0].0.is_empty(),
            "First value name should not be empty"
        );
        unsafe {
            let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_open_registry_key_unsupported_platform() {
        let result = open_registry_key("HKLM", "SOFTWARE\\Test");
        assert!(result.is_err());
    }
}
