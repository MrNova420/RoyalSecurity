use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::{ForensicError, Result};

const APP_COMPAT_CACHE_KEY: &str = "ControlSet001\\Control\\Session Manager\\AppCompatCache";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimcacheEntry {
    pub index: u32,
    pub last_modified: Option<DateTime<Utc>>,
    pub executable_path: String,
    pub flags: u32,
    pub data_size: u32,
    pub insertion_time: Option<DateTime<Utc>>,
    pub last_update_time: Option<DateTime<Utc>>,
}

#[derive(Debug)]
enum AppCompatCacheFormat {
    Xp,
    Vista,
    Win7,
    Win8,
    Win81,
    Win10,
}

pub fn parse_shimcache(data: &[u8]) -> Result<Vec<ShimcacheEntry>> {
    let mut entries = Vec::new();

    if data.len() < 4096 {
        return Ok(entries);
    }

    let format = detect_format(data);

    match format {
        AppCompatCacheFormat::Win10 => parse_win10_shimcache(data, &mut entries)?,
        AppCompatCacheFormat::Win8 | AppCompatCacheFormat::Win81 => parse_win8_shimcache(data, &mut entries)?,
        AppCompatCacheFormat::Win7 => parse_win7_shimcache(data, &mut entries)?,
        AppCompatCacheFormat::Vista => parse_vista_shimcache(data, &mut entries)?,
        AppCompatCacheFormat::Xp => parse_xp_shimcache(data, &mut entries)?,
    }

    Ok(entries)
}

fn detect_format(data: &[u8]) -> AppCompatCacheFormat {
    if data.len() < 128 {
        return AppCompatCacheFormat::Win10;
    }

    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let version = u16::from_le_bytes(data[4..6].try_into().unwrap());

    match (magic, version) {
        (0x00000004, _) => AppCompatCacheFormat::Win10,
        (0x00000003, _) => AppCompatCacheFormat::Win81,
        (0x00000002, _) => AppCompatCacheFormat::Win8,
        (0x00000001, _) => AppCompatCacheFormat::Win7,
        (0x00000000, _) => AppCompatCacheFormat::Vista,
        _ => AppCompatCacheFormat::Win10,
    }
}

fn parse_win10_shimcache(data: &[u8], entries: &mut Vec<ShimcacheEntry>) -> Result<()> {
    let mut offset = 16;
    let mut index = 0;

    while offset + 128 <= data.len() {
        let entry_size = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());

        if entry_size == 0 || entry_size > 4096 {
            break;
        }

        let flags = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());
        let insertion_time = u64::from_le_bytes(data[offset + 16..offset + 24].try_into().unwrap());
        let last_update_time = u64::from_le_bytes(data[offset + 24..offset + 32].try_into().unwrap());
        let file_size = u32::from_le_bytes(data[offset + 32..offset + 36].try_into().unwrap());

        let path_offset = offset + 64;
        let path_len = entry_size.saturating_sub(64) as usize;

        if path_offset + path_len <= data.len() {
            let path = decode_utf16_le(&data[path_offset..path_offset + path_len]);

            entries.push(ShimcacheEntry {
                index,
                last_modified: windows_filetime_to_datetime(insertion_time),
                executable_path: path,
                flags,
                data_size: file_size,
                insertion_time: windows_filetime_to_datetime(insertion_time),
                last_update_time: windows_filetime_to_datetime(last_update_time),
            });
        }

        offset += entry_size as usize;
        index += 1;

        if entries.len() >= 10000 {
            break;
        }
    }

    Ok(())
}

fn parse_win8_shimcache(data: &[u8], entries: &mut Vec<ShimcacheEntry>) -> Result<()> {
    let mut offset = 128;
    let mut index = 0;

    while offset + 128 <= data.len() {
        let path_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;

        if path_len == 0 || path_len > 1024 {
            break;
        }

        let flags = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());
        let insertion_time = u64::from_le_bytes(data[offset + 16..offset + 24].try_into().unwrap());
        let last_update_time = u64::from_le_bytes(data[offset + 24..offset + 32].try_into().unwrap());
        let file_size = u32::from_le_bytes(data[offset + 32..offset + 36].try_into().unwrap());

        let path = if offset + 64 + path_len * 2 <= data.len() {
            decode_utf16_le(&data[offset + 64..offset + 64 + path_len * 2])
        } else {
            String::new()
        };

        entries.push(ShimcacheEntry {
            index,
            last_modified: windows_filetime_to_datetime(insertion_time),
            executable_path: path,
            flags,
            data_size: file_size,
            insertion_time: windows_filetime_to_datetime(insertion_time),
            last_update_time: windows_filetime_to_datetime(last_update_time),
        });

        offset += 64 + path_len * 2;
        index += 1;

        if entries.len() >= 10000 {
            break;
        }
    }

    Ok(())
}

fn parse_win7_shimcache(data: &[u8], entries: &mut Vec<ShimcacheEntry>) -> Result<()> {
    let mut offset = 64;
    let mut index = 0;

    while offset + 128 <= data.len() {
        let path_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;

        if path_len == 0 || path_len > 1024 {
            break;
        }

        let last_modified = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap());
        let file_size = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());

        let path = if offset + 16 + path_len * 2 <= data.len() {
            decode_utf16_le(&data[offset + 16..offset + 16 + path_len * 2])
        } else {
            String::new()
        };

        entries.push(ShimcacheEntry {
            index,
            last_modified: windows_filetime_to_datetime(last_modified),
            executable_path: path,
            flags: 0,
            data_size: file_size,
            insertion_time: None,
            last_update_time: None,
        });

        offset += 16 + path_len * 2;
        index += 1;

        if entries.len() >= 10000 {
            break;
        }
    }

    Ok(())
}

fn parse_vista_shimcache(data: &[u8], entries: &mut Vec<ShimcacheEntry>) -> Result<()> {
    let mut offset = 64;
    let mut index = 0;

    while offset + 128 <= data.len() {
        let path_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;

        if path_len == 0 || path_len > 1024 {
            break;
        }

        let last_modified = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap());
        let file_size = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());

        let path = if offset + 16 + path_len * 2 <= data.len() {
            decode_utf16_le(&data[offset + 16..offset + 16 + path_len * 2])
        } else {
            String::new()
        };

        entries.push(ShimcacheEntry {
            index,
            last_modified: windows_filetime_to_datetime(last_modified),
            executable_path: path,
            flags: 0,
            data_size: file_size,
            insertion_time: None,
            last_update_time: None,
        });

        offset += 16 + path_len * 2;
        index += 1;

        if entries.len() >= 10000 {
            break;
        }
    }

    Ok(())
}

fn parse_xp_shimcache(data: &[u8], entries: &mut Vec<ShimcacheEntry>) -> Result<()> {
    let mut offset = 64;
    let mut index = 0;

    while offset + 128 <= data.len() {
        let path_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;

        if path_len == 0 || path_len > 1024 {
            break;
        }

        let last_modified = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap());

        let path = if offset + 16 + path_len * 2 <= data.len() {
            decode_utf16_le(&data[offset + 16..offset + 16 + path_len * 2])
        } else {
            String::new()
        };

        entries.push(ShimcacheEntry {
            index,
            last_modified: windows_filetime_to_datetime(last_modified),
            executable_path: path,
            flags: 0,
            data_size: 0,
            insertion_time: None,
            last_update_time: None,
        });

        offset += 16 + path_len * 2;
        index += 1;

        if entries.len() >= 10000 {
            break;
        }
    }

    Ok(())
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
    String::from_utf16_lossy(&chunks).trim_end_matches('\0').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_win10_shimcache() -> Vec<u8> {
        let mut data = vec![0u8; 4096];
        data[0..4].copy_from_slice(&4u32.to_le_bytes());
        data[4..6].copy_from_slice(&0u16.to_le_bytes());

        let entry_offset = 16;
        data[entry_offset..entry_offset + 4].copy_from_slice(&256u32.to_le_bytes());
        data[entry_offset + 4..entry_offset + 8].copy_from_slice(&1u32.to_le_bytes());
        data[entry_offset + 16..entry_offset + 24].copy_from_slice(&130_000_000_000_000_000u64.to_le_bytes());
        data[entry_offset + 24..entry_offset + 32].copy_from_slice(&130_000_000_000_000_000u64.to_le_bytes());
        data[entry_offset + 32..entry_offset + 36].copy_from_slice(&12345u32.to_le_bytes());

        let path = "C:\\Windows\\System32\\cmd.exe";
        for (i, ch) in path.encode_utf16().enumerate() {
            let off = entry_offset + 64 + i * 2;
            data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        data
    }

    #[test]
    fn test_buffer_too_small() {
        let data = vec![0u8; 100];
        let entries = parse_shimcache(&data).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_detect_format_win10() {
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(&4u32.to_le_bytes());
        let format = detect_format(&data);
        assert!(matches!(format, AppCompatCacheFormat::Win10));
    }

    #[test]
    fn test_detect_format_win8() {
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(&2u32.to_le_bytes());
        let format = detect_format(&data);
        assert!(matches!(format, AppCompatCacheFormat::Win8));
    }

    #[test]
    fn test_parse_win10_shimcache() {
        let data = make_win10_shimcache();
        let entries = parse_shimcache(&data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].executable_path, "C:\\Windows\\System32\\cmd.exe");
    }

    #[test]
    fn test_parse_win10_shimcache_timestamp() {
        let data = make_win10_shimcache();
        let entries = parse_shimcache(&data).unwrap();
        assert!(entries[0].insertion_time.is_some());
    }

    #[test]
    fn test_parse_win10_shimcache_flags() {
        let data = make_win10_shimcache();
        let entries = parse_shimcache(&data).unwrap();
        assert_eq!(entries[0].flags, 1);
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
}
