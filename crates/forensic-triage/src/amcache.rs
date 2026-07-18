use serde::{Deserialize, Serialize};
use chrono::{DateTime, NaiveDate, Utc};
use crate::{ForensicError, Result};

const AMCACHE_REGF_MAGIC: &[u8; 4] = b"regf";
const ROOT_ENTRY_OFFSET: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmcacheEntry {
    pub program_name: String,
    pub publisher: String,
    pub version: String,
    pub install_date: Option<DateTime<Utc>>,
    pub source: String,
    pub root_dir_path: String,
    pub uninstall_string: String,
    pub sha1: String,
    pub file_size: u64,
    pub language_id: u32,
    pub store_app_id: String,
    pub bin_file_version: String,
    pub bin_product_version: String,
    pub product_name: String,
    pub company_name: String,
    pub link_date: Option<DateTime<Utc>>,
}

const REG_KEY_VALUE: u32 = 0x66;

pub fn parse_amcache(data: &[u8]) -> Result<Vec<AmcacheEntry>> {
    let mut entries = Vec::new();

    if data.len() < 4096 {
        return Err(ForensicError::BufferTooSmall { needed: 4096, have: data.len() });
    }

    if &data[0..4] != AMCACHE_REGF_MAGIC {
        return Err(ForensicError::InvalidMagic);
    }

    let uninstall_key = find_key_in_hive(data, "Root\\InventoryApplication");
    if let Some(offset) = uninstall_key {
        parse_inventory_application(data, offset, &mut entries);
    }

    let uninstall_key_vista = find_key_in_hive(data, "Root\\Uninstall\\");
    if let Some(offset) = uninstall_key_vista {
        parse_uninstall_key(data, offset, &mut entries);
    }

    Ok(entries)
}

fn find_key_in_hive(data: &[u8], target_path: &str) -> Option<usize> {
    let mut offset = ROOT_ENTRY_OFFSET;

    while offset + 76 <= data.len() {
        let cell_size = i32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let abs_size = cell_size.unsigned_abs() as usize;

        if abs_size < 76 || abs_size > 65536 {
            break;
        }

        if cell_size > 0 && offset + abs_size <= data.len() {
            let cell_type = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());

            if cell_type == 0x20 {
                let key_name_len = u16::from_le_bytes(data[offset + 54..offset + 56].try_into().unwrap()) as usize;
                if key_name_len > 0 && key_name_len < 256 && offset + 76 + key_name_len <= data.len() {
                    let key_name = String::from_utf8_lossy(&data[offset + 76..offset + 76 + key_name_len]).to_string();
                    if key_name.contains(target_path) || target_path.starts_with(&key_name) {
                        return Some(offset);
                    }
                }
            }
        }

        offset += abs_size;
    }

    None
}

fn parse_inventory_application(data: &[u8], key_offset: usize, entries: &mut Vec<AmcacheEntry>) {
    if key_offset + 76 > data.len() {
        return;
    }

    let values_list_offset = u32::from_le_bytes(data[key_offset + 40..key_offset + 44].try_into().unwrap()) as usize;
    let num_values = u32::from_le_bytes(data[key_offset + 32..key_offset + 36].try_into().unwrap()) as usize;

    if values_list_offset == 0 || num_values == 0 {
        return;
    }

    let mut name = String::new();
    let mut publisher = String::new();
    let mut version = String::new();
    let mut install_date = None;
    let mut sha1 = String::new();
    let mut file_size: u64 = 0;
    let mut source = String::new();
    let mut root_dir_path = String::new();
    let mut uninstall_string = String::new();
    let mut language_id: u32 = 0;
    let mut store_app_id = String::new();
    let mut bin_file_version = String::new();
    let mut bin_product_version = String::new();
    let mut product_name = String::new();
    let mut company_name = String::new();
    let mut link_date = None;

    for i in 0..num_values {
        let val_offset_pos = values_list_offset + i * 4;
        if val_offset_pos + 4 > data.len() {
            break;
        }

        let val_offset_raw = u32::from_le_bytes(data[val_offset_pos..val_offset_pos + 4].try_into().unwrap());
        let val_offset = (val_offset_raw & 0x7FFFFFFF) as usize;

        if val_offset + 20 > data.len() {
            continue;
        }

        let cell_size = i32::from_le_bytes(data[val_offset..val_offset + 4].try_into().unwrap());
        if cell_size <= 0 {
            continue;
        }

        let name_len = u16::from_le_bytes(data[val_offset + 4..val_offset + 6].try_into().unwrap()) as usize;
        let data_size = u32::from_le_bytes(data[val_offset + 8..val_offset + 12].try_into().unwrap());
        let data_off = u32::from_le_bytes(data[val_offset + 12..val_offset + 16].try_into().unwrap()) as usize;
        let data_type = u32::from_le_bytes(data[val_offset + 16..val_offset + 20].try_into().unwrap());

        let val_name = if name_len > 0 && val_offset + 20 + name_len <= data.len() {
            String::from_utf8_lossy(&data[val_offset + 20..val_offset + 20 + name_len]).to_string()
        } else {
            continue;
        };

        let actual_data_size = (data_size & 0x7FFFFFFF) as usize;
        let actual_data_offset = (data_off & 0x7FFFFFFF) as usize;

        let val_data = if actual_data_size > 0 && actual_data_offset + actual_data_size <= data.len() {
            &data[actual_data_offset..actual_data_offset + actual_data_size]
        } else {
            &[]
        };

        let val_string = match data_type {
            1 | 2 => String::from_utf8_lossy(val_data).trim_end_matches('\0').to_string(),
            4 => {
                if val_data.len() >= 4 {
                    u32::from_le_bytes(val_data[0..4].try_into().unwrap()).to_string()
                } else {
                    String::new()
                }
            }
            11 => {
                if val_data.len() >= 8 {
                    u64::from_le_bytes(val_data[0..8].try_into().unwrap()).to_string()
                } else {
                    String::new()
                }
            }
            _ => String::new(),
        };

        match val_name.as_str() {
            "Name" => name = val_string,
            "Publisher" => publisher = val_string,
            "Version" => version = val_string,
            "InstallDate" => {
                if val_string.len() == 8 {
                    install_date = NaiveDate::parse_from_str(&val_string, "%Y%m%d")
                        .ok()
                        .and_then(|d| d.and_hms_opt(0, 0, 0))
                        .map(|dt| dt.and_utc());
                }
            }
            "SHA1" => sha1 = hex::encode(val_data),
            "Size" => file_size = val_string.parse().unwrap_or(0),
            "Source" => source = val_string,
            "RootDirPath" => root_dir_path = val_string,
            "UninstallString" => uninstall_string = val_string,
            "LanguageId" => language_id = val_string.parse().unwrap_or(0),
            "StoreAppId" => store_app_id = val_string,
            "BinFileVersion" => bin_file_version = val_string,
            "BinProductVersion" => bin_product_version = val_string,
            "ProductName" => product_name = val_string,
            "CompanyName" => company_name = val_string,
            "LinkDate" => {
                if val_string.len() == 8 {
                    link_date = NaiveDate::parse_from_str(&val_string, "%Y%m%d")
                        .ok()
                        .and_then(|d| d.and_hms_opt(0, 0, 0))
                        .map(|dt| dt.and_utc());
                }
            }
            _ => {}
        }
    }

    if !name.is_empty() {
        entries.push(AmcacheEntry {
            program_name: name,
            publisher,
            version,
            install_date,
            source,
            root_dir_path,
            uninstall_string,
            sha1,
            file_size,
            language_id,
            store_app_id,
            bin_file_version,
            bin_product_version,
            product_name,
            company_name,
            link_date,
        });
    }
}

fn parse_uninstall_key(data: &[u8], key_offset: usize, entries: &mut Vec<AmcacheEntry>) {
    if key_offset + 76 > data.len() {
        return;
    }

    let values_list_offset = u32::from_le_bytes(data[key_offset + 40..key_offset + 44].try_into().unwrap()) as usize;
    let num_values = u32::from_le_bytes(data[key_offset + 32..key_offset + 36].try_into().unwrap()) as usize;

    if values_list_offset == 0 || num_values == 0 {
        return;
    }

    for i in 0..num_values {
        let val_offset_pos = values_list_offset + i * 4;
        if val_offset_pos + 4 > data.len() {
            break;
        }

        let val_offset_raw = u32::from_le_bytes(data[val_offset_pos..val_offset_pos + 4].try_into().unwrap());
        let val_offset = (val_offset_raw & 0x7FFFFFFF) as usize;

        if val_offset + 20 > data.len() {
            continue;
        }

        let cell_size = i32::from_le_bytes(data[val_offset..val_offset + 4].try_into().unwrap());
        if cell_size <= 0 {
            continue;
        }

        let name_len = u16::from_le_bytes(data[val_offset + 4..val_offset + 6].try_into().unwrap()) as usize;
        let data_size = u32::from_le_bytes(data[val_offset + 8..val_offset + 12].try_into().unwrap());
        let data_off = u32::from_le_bytes(data[val_offset + 12..val_offset + 16].try_into().unwrap()) as usize;
        let data_type = u32::from_le_bytes(data[val_offset + 16..val_offset + 20].try_into().unwrap());

        let val_name = if name_len > 0 && val_offset + 20 + name_len <= data.len() {
            String::from_utf8_lossy(&data[val_offset + 20..val_offset + 20 + name_len]).to_string()
        } else {
            continue;
        };

        let actual_data_size = (data_size & 0x7FFFFFFF) as usize;
        let actual_data_offset = (data_off & 0x7FFFFFFF) as usize;

        let val_data = if actual_data_size > 0 && actual_data_offset + actual_data_size <= data.len() {
            &data[actual_data_offset..actual_data_offset + actual_data_size]
        } else {
            &[]
        };

        let val_string = match data_type {
            1 | 2 => String::from_utf8_lossy(val_data).trim_end_matches('\0').to_string(),
            4 => {
                if val_data.len() >= 4 {
                    u32::from_le_bytes(val_data[0..4].try_into().unwrap()).to_string()
                } else {
                    String::new()
                }
            }
            11 => {
                if val_data.len() >= 8 {
                    u64::from_le_bytes(val_data[0..8].try_into().unwrap()).to_string()
                } else {
                    String::new()
                }
            }
            _ => String::new(),
        };

        if val_name == "DisplayName" && !val_string.is_empty() {
            entries.push(AmcacheEntry {
                program_name: val_string,
                publisher: String::new(),
                version: String::new(),
                install_date: None,
                source: String::new(),
                root_dir_path: String::new(),
                uninstall_string: String::new(),
                sha1: String::new(),
                file_size: 0,
                language_id: 0,
                store_app_id: String::new(),
                bin_file_version: String::new(),
                bin_product_version: String::new(),
                product_name: String::new(),
                company_name: String::new(),
                link_date: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_magic() {
        let data = vec![0u8; 8192];
        let result = parse_amcache(&data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ForensicError::InvalidMagic));
    }

    #[test]
    fn test_buffer_too_small() {
        let data = vec![0u8; 100];
        let result = parse_amcache(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_amcache_empty() {
        let mut data = vec![0u8; 8192];
        data[0..4].copy_from_slice(AMCACHE_REGF_MAGIC);
        let entries = parse_amcache(&data).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_amcache_valid_header() {
        let mut data = vec![0u8; 8192];
        data[0..4].copy_from_slice(AMCACHE_REGF_MAGIC);
        let result = parse_amcache(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_amcache_entry_serialization() {
        let entry = AmcacheEntry {
            program_name: "TestApp".to_string(),
            publisher: "TestPublisher".to_string(),
            version: "1.0.0".to_string(),
            install_date: None,
            source: "Uninstall".to_string(),
            root_dir_path: String::new(),
            uninstall_string: String::new(),
            sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
            file_size: 12345,
            language_id: 1033,
            store_app_id: String::new(),
            bin_file_version: String::new(),
            bin_product_version: String::new(),
            product_name: String::new(),
            company_name: String::new(),
            link_date: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("TestApp"));
        assert!(json.contains("TestPublisher"));
    }

    #[test]
    fn test_find_key_in_hive_missing() {
        let mut data = vec![0u8; 8192];
        data[0..4].copy_from_slice(AMCACHE_REGF_MAGIC);
        let result = find_key_in_hive(&data, "NonExistent");
        assert!(result.is_none());
    }
}
