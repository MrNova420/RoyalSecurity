use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::{ForensicError, Result};

const REGF_MAGIC: &[u8; 4] = b"regf";
const REG_KEY_NODE: u32 = 0x20;
const REG_KEY_VALUE: u32 = 0x66;
const REG_HIVE_BIN: u32 = 0x686E6962;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub hive_name: String,
    pub key_path: String,
    pub values: Vec<RegistryValue>,
    pub last_written: Option<DateTime<Utc>>,
    pub access_bits: u32,
    pub class_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValue {
    pub name: String,
    pub data_type: u32,
    pub data: Vec<u8>,
    pub data_string: String,
}

#[derive(Debug)]
struct RegfHeader {
    hive_bins_data_size: u32,
    base_block_offset: u32,
    hive_bins_offset: u32,
    file_name: String,
    last_modified: u64,
}

#[derive(Debug)]
struct KeyNode {
    flags: u16,
    last_written: u64,
    access_bits: u32,
    parent_offset: u32,
    num_children: u32,
    num_values: u32,
    children_list_offset: u32,
    values_list_offset: u32,
    class_name_offset: u32,
    class_name_length: u16,
    key_name: String,
}

pub fn parse_registry_hive(data: &[u8], hive_name: &str) -> Result<Vec<RegistryEntry>> {
    if data.len() < 4096 {
        return Err(ForensicError::BufferTooSmall { needed: 4096, have: data.len() });
    }

    if &data[0..4] != REGF_MAGIC {
        return Err(ForensicError::InvalidMagic);
    }

    let header = parse_regf_header(data)?;
    let mut entries = Vec::new();

    parse_hive_bins(data, &header, hive_name, &mut entries, 4096, "")?;

    Ok(entries)
}

fn parse_regf_header(data: &[u8]) -> Result<RegfHeader> {
    let hive_bins_data_size = u32::from_le_bytes(data[36..40].try_into().unwrap());
    let last_modified = u64::from_le_bytes(data[12..20].try_into().unwrap());
    let file_name = decode_utf16_le_fixed(&data[48..96]);

    Ok(RegfHeader {
        hive_bins_data_size,
        base_block_offset: 4096,
        hive_bins_offset: 4096,
        file_name,
        last_modified,
    })
}

fn parse_hive_bins(
    data: &[u8],
    header: &RegfHeader,
    hive_name: &str,
    entries: &mut Vec<RegistryEntry>,
    offset: usize,
    path: &str,
) -> Result<()> {
    let mut bin_offset = offset;

    while bin_offset + 32 <= data.len() {
        if &data[bin_offset..bin_offset + 4] != &REG_HIVE_BIN.to_le_bytes() {
            break;
        }

        let bin_size = i32::from_le_bytes(data[bin_offset + 4..bin_offset + 8].try_into().unwrap());
        let abs_size = bin_size.unsigned_abs() as usize;

        if abs_size < 32 {
            break;
        }

        let mut cell_offset = bin_offset + 32;

        while cell_offset + 4 <= bin_offset + abs_size {
            let cell_size = i32::from_le_bytes(data[cell_offset..cell_offset + 4].try_into().unwrap());
            let abs_cell_size = cell_size.unsigned_abs() as usize;

            if abs_cell_size < 4 || abs_cell_size > 65536 {
                break;
            }

            if cell_offset + abs_cell_size > data.len() {
                break;
            }

            if cell_size < 0 {
                cell_offset += abs_cell_size;
                continue;
            }

            if abs_cell_size >= 76 && cell_offset + 76 <= data.len() {
                let cell_type = u32::from_le_bytes(data[cell_offset..cell_offset + 4].try_into().unwrap());

                match cell_type {
                    t if t == REG_KEY_NODE => {
                        if let Some(entry) = parse_key_node(data, cell_offset, hive_name, path) {
                            entries.push(entry);
                        }
                    }
                    _ => {}
                }
            }

            cell_offset += abs_cell_size;
        }

        bin_offset += abs_size;
    }

    Ok(())
}

fn parse_key_node(data: &[u8], offset: usize, hive_name: &str, parent_path: &str) -> Option<RegistryEntry> {
    if offset + 76 > data.len() {
        return None;
    }

    let flags = u16::from_le_bytes(data[offset + 4..offset + 6].try_into().unwrap());
    let last_written = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap());
    let access_bits = u32::from_le_bytes(data[offset + 20..offset + 24].try_into().unwrap());
    let _parent_offset = u32::from_le_bytes(data[offset + 24..offset + 28].try_into().unwrap());
    let _num_children = u32::from_le_bytes(data[offset + 28..offset + 32].try_into().unwrap());
    let num_values = u32::from_le_bytes(data[offset + 32..offset + 36].try_into().unwrap());
    let _children_list_offset = u32::from_le_bytes(data[offset + 36..offset + 40].try_into().unwrap());
    let values_list_offset = u32::from_le_bytes(data[offset + 40..offset + 44].try_into().unwrap());
    let class_name_offset = u32::from_le_bytes(data[offset + 44..offset + 48].try_into().unwrap());
    let class_name_length = u16::from_le_bytes(data[offset + 52..offset + 54].try_into().unwrap());
    let key_name_length = u16::from_le_bytes(data[offset + 54..offset + 56].try_into().unwrap()) as usize;

    if key_name_length == 0 || key_name_length > 256 {
        return None;
    }

    let key_name = if flags & 0x0020 != 0 {
        decode_utf16_le(&data[offset + 76..offset + 76 + key_name_length * 2])
    } else {
        String::from_utf8_lossy(&data[offset + 76..offset + 76 + key_name_length]).to_string()
    };

    let mut values = Vec::new();
    if num_values > 0 && values_list_offset > 0 {
        let vlist_abs = (values_list_offset & 0x7FFFFFFF) as usize;
        let hive_bin_offset = find_hive_bin_offset(offset, vlist_abs);
        let actual_offset = hive_bin_offset + vlist_abs;

        if actual_offset + 4 <= data.len() {
            for i in 0..num_values as usize {
                let val_offset_pos = actual_offset + i * 4;
                if val_offset_pos + 4 > data.len() {
                    break;
                }
                let val_offset_raw = u32::from_le_bytes(data[val_offset_pos..val_offset_pos + 4].try_into().unwrap());
                let val_abs = (val_offset_raw & 0x7FFFFFFF) as usize;
                let val_bin_offset = find_hive_bin_offset(offset, val_abs);
                let val_abs_offset = val_bin_offset + val_abs;

                if let Some(value) = parse_value_entry(data, val_abs_offset) {
                    values.push(value);
                }
            }
        }
    }

    let mut full_path = if parent_path.is_empty() {
        format!("{}\\{}", hive_name, key_name)
    } else {
        format!("{}\\{}", parent_path, key_name)
    };

    let class_name = if class_name_length > 0 && class_name_offset > 0 {
        let cn_abs = (class_name_offset & 0x7FFFFFFF) as usize;
        let cn_bin_offset = find_hive_bin_offset(offset, cn_abs);
        let actual_cn = cn_bin_offset + cn_abs;
        if actual_cn + class_name_length as usize * 2 <= data.len() {
            decode_utf16_le(&data[actual_cn..actual_cn + class_name_length as usize * 2])
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    Some(RegistryEntry {
        hive_name: hive_name.to_string(),
        key_path: full_path,
        values,
        last_written: windows_filetime_to_datetime(last_written),
        access_bits,
        class_name,
    })
}

fn parse_value_entry(data: &[u8], offset: usize) -> Option<RegistryValue> {
    if offset + 20 > data.len() {
        return None;
    }

    let name_length = u16::from_le_bytes(data[offset + 4..offset + 6].try_into().unwrap()) as usize;
    let data_size = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap());
    let data_offset = u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap());
    let data_type = u32::from_le_bytes(data[offset + 16..offset + 20].try_into().unwrap());

    let name = if name_length > 0 {
        if offset + 20 + name_length <= data.len() {
            String::from_utf8_lossy(&data[offset + 20..offset + 20 + name_length]).to_string()
        } else {
            String::new()
        }
    } else {
        "(Default)".to_string()
    };

    let actual_data_size = (data_size & 0x7FFFFFFF) as usize;
    let actual_data_offset = (data_offset & 0x7FFFFFFF) as usize;
    let data_bin_offset = find_hive_bin_offset(offset, actual_data_offset);
    let abs_data_offset = data_bin_offset + actual_data_offset;

    let raw_data = if actual_data_size > 0 && actual_data_size <= 4096 && abs_data_offset + actual_data_size <= data.len() {
        data[abs_data_offset..abs_data_offset + actual_data_size].to_vec()
    } else {
        Vec::new()
    };

    let data_string = match data_type {
        1 | 2 => String::from_utf8_lossy(&raw_data).trim_end_matches('\0').to_string(),
        4 => {
            if raw_data.len() >= 4 {
                let val = u32::from_le_bytes(raw_data[0..4].try_into().unwrap());
                format!("{}", val)
            } else {
                String::new()
            }
        }
        11 => {
            if raw_data.len() >= 8 {
                let val = u64::from_le_bytes(raw_data[0..8].try_into().unwrap());
                format!("{}", val)
            } else {
                String::new()
            }
        }
        _ => hex::encode(&raw_data),
    };

    Some(RegistryValue {
        name,
        data_type,
        data: raw_data,
        data_string,
    })
}

fn find_hive_bin_offset(_current_offset: usize, _target: usize) -> usize {
    0
}

fn windows_filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }

    let windows_epoch_diff: i64 = 116_444_736_000_000_000;
    let unix_time = ((filetime as i64) - windows_epoch_diff) / 10_000_000;

    DateTime::from_timestamp(unix_time, 0)
}

fn decode_utf16_le(data: &[u8]) -> String {
    let chunks: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&chunks).to_string()
}

fn decode_utf16_le_fixed(data: &[u8]) -> String {
    let name = decode_utf16_le(data);
    name.trim_end_matches('\0').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_regf_header() -> Vec<u8> {
        let mut data = vec![0u8; 4096];
        data[0..4].copy_from_slice(REGF_MAGIC);
        data[12..20].copy_from_slice(&130_000_000_000_000_000u64.to_le_bytes());
        data[36..40].copy_from_slice(&0u32.to_le_bytes());
        let file_name = "SOFTWARE";
        for (i, ch) in file_name.encode_utf16().enumerate() {
            let off = 48 + i * 2;
            if off + 2 <= 96 {
                data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
            }
        }
        data
    }

    #[test]
    fn test_invalid_magic() {
        let data = vec![0u8; 4096];
        let result = parse_registry_hive(&data, "TEST");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ForensicError::InvalidMagic));
    }

    #[test]
    fn test_buffer_too_small() {
        let data = vec![0u8; 100];
        let result = parse_registry_hive(&data, "TEST");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_regf_header() {
        let data = make_regf_header();
        let header = parse_regf_header(&data).unwrap();
        assert!(header.file_name.contains("SOFTWARE"));
    }

    #[test]
    fn test_windows_filetime_to_datetime_valid() {
        let dt = windows_filetime_to_datetime(130_000_000_000_000_000);
        assert!(dt.is_some());
    }

    #[test]
    fn test_windows_filetime_to_datetime_zero() {
        assert!(windows_filetime_to_datetime(0).is_none());
    }

    #[test]
    fn test_parse_registry_hive_empty_bins() {
        let mut data = make_regf_header();
        data[36..40].copy_from_slice(&0u32.to_le_bytes());
        let entries = parse_registry_hive(&data, "TEST").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_decode_utf16_le() {
        let data = "Test".encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>();
        let result = decode_utf16_le(&data);
        assert_eq!(result, "Test");
    }
}
