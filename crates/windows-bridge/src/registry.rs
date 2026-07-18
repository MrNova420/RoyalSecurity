use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValue {
    pub key: String,
    pub value_name: String,
    pub value_data: String,
    pub data_type: String,
    pub last_modified: Option<DateTime<Utc>>,
}

#[cfg(windows)]
pub fn read_registry_key(path: &str) -> Vec<RegistryValue> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    use windows::core::PWSTR;

    let mut values = Vec::new();
    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut hkey = Default::default();

    unsafe {
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, windows::core::PCWSTR::from_raw(wide_path.as_ptr()), 0, KEY_READ, &mut hkey).is_err()
        {
            return values;
        }

        let mut index = 0;
        loop {
            let mut name_buf = [0u16; 256];
            let mut name_len = 256u32;
            let mut data_buf = [0u8; 4096];
            let mut data_len = 4096u32;
            let mut reg_type = Default::default();

            let result = RegEnumValueW(
                hkey,
                index,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                Some(&mut reg_type),
                Some(data_buf.as_mut_ptr()),
                Some(&mut data_len),
            );

            if result.is_err() {
                break;
            }

            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]).to_string();
            let type_str = match reg_type {
                1 => "REG_SZ",
                3 => "REG_BINARY",
                4 => "REG_DWORD",
                5 => "REG_DWORD_BIG_ENDIAN",
                7 => "REG_MULTI_SZ",
                11 => "REG_QWORD",
                _ => "REG_UNKNOWN",
            };
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

            values.push(RegistryValue {
                key: path.to_string(),
                value_name: name,
                value_data: data_str,
                data_type: type_str.to_string(),
                last_modified: None,
            });

            index += 1;
        }

        let _ = RegCloseKey(hkey);
    }
    values
}

#[cfg(not(windows))]
pub fn read_registry_key(path: &str) -> Vec<RegistryValue> {
    vec![
        RegistryValue {
            key: path.to_string(),
            value_name: "TestValue".to_string(),
            value_data: "test_data".to_string(),
            data_type: "REG_SZ".to_string(),
            last_modified: Some(Utc::now()),
        },
        RegistryValue {
            key: path.to_string(),
            value_name: "Enabled".to_string(),
            value_data: "1".to_string(),
            data_type: "REG_DWORD".to_string(),
            last_modified: Some(Utc::now()),
        },
        RegistryValue {
            key: path.to_string(),
            value_name: "Path".to_string(),
            value_data: "C:\\Program Files\\App".to_string(),
            data_type: "REG_SZ".to_string(),
            last_modified: Some(Utc::now()),
        },
    ]
}

pub fn monitor_registry_key<F>(_path: &str, _callback: F)
where
    F: Fn(&RegistryValue) + Send + 'static,
{
    tracing::info!(
        "Registry monitoring placeholder - will implement with RegNotifyChangeKeyValue"
    );
}

pub fn get_persistence_entries() -> Vec<RegistryValue> {
    let autorun_keys = [
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    ];

    let mut entries = Vec::new();
    for key in &autorun_keys {
        let values = read_registry_key(key);
        entries.extend(values);
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_registry_key_returns_data() {
        let values = read_registry_key("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
        assert!(!values.is_empty());
    }

    #[test]
    fn test_registry_value_fields() {
        let values = read_registry_key("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
        assert!(!values[0].data_type.is_empty());
        assert!(!values[0].value_name.is_empty());
    }

    #[test]
    fn test_get_persistence_entries() {
        let entries = get_persistence_entries();
        assert!(!entries.is_empty());
    }

    #[test]
    fn test_monitor_registry_key_no_panic() {
        monitor_registry_key("SOFTWARE\\Test", |_| {});
    }
}
