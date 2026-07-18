use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnkFile {
    pub target_path: String,
    pub target_file_size: u32,
    pub creation_time: Option<DateTime<Utc>>,
    pub modification_time: Option<DateTime<Utc>>,
    pub access_time: Option<DateTime<Utc>>,
    pub mac_addresses: Vec<String>,
    pub volume_serial: Option<String>,
    pub volume_type: Option<String>,
    pub local_base_path: Option<String>,
    pub command_line_arguments: Option<String>,
    pub icon_location: Option<String>,
    pub working_directory: Option<String>,
}

impl LnkFile {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 76 {
            return Err("LNK file too small".into());
        }
        let magic = &data[0..4];
        if magic != b"L\x00\x00\x00" {
            return Err("Invalid LNK magic bytes".into());
        }
        let file_size = u32::from_le_bytes(data[52..56].try_into().map_err(|_| "parse error")?);
        let flags = u32::from_le_bytes(data[20..24].try_into().map_err(|_| "parse error")?);
        let mut target_path = String::new();
        let mut mac_addresses = Vec::new();
        let mut volume_serial = None;
        let mut local_base_path = None;
        let mut command_line_arguments = None;
        let mut icon_location = None;
        let mut working_directory = None;
        let mut offset = 76;
        while offset + 4 <= data.len() {
            let clsid = u32::from_le_bytes(data[offset..offset+4].try_into().map_err(|_| "parse error")?);
            let rec_size = u32::from_le_bytes(data[offset+4..offset+8].try_into().map_err(|_| "parse error")?) as usize;
            if rec_size < 8 || offset + rec_size > data.len() {
                break;
            }
            let rec_data = &data[offset+8..offset+rec_size];
            match clsid {
                0x00000001 => {
                    if let Ok(s) = read_string_at(rec_data, 0) {
                        if !s.is_empty() { target_path = s; }
                    }
                }
                0x00000002 => {
                    if let Ok(s) = read_string_at(rec_data, 0) {
                        local_base_path = Some(s);
                    }
                }
                0x00000003 => {
                    if rec_data.len() >= 4 {
                        command_line_arguments = read_string_at(rec_data, 0).ok();
                    }
                }
                0x00000004 => {
                    working_directory = read_string_at(rec_data, 0).ok();
                }
                0x00000006 => {
                    icon_location = read_string_at(rec_data, 0).ok();
                }
                0x00000009 => {
                    if rec_data.len() >= 8 {
                        let serial = u32::from_le_bytes(rec_data[4..8].try_into().map_err(|_| "e")?);
                        volume_serial = Some(format!("{:08X}", serial));
                    }
                }
                0x0000000A => {
                    let mut i = 0;
                    while i + 8 <= rec_data.len() {
                        let b0 = rec_data[i];
                        let b1 = rec_data[i+1];
                        let b2 = rec_data[i+2];
                        let b3 = rec_data[i+3];
                        let b4 = rec_data[i+4];
                        let b5 = rec_data[i+5];
                        mac_addresses.push(format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", b0, b1, b2, b3, b4, b5));
                        i += 8;
                    }
                }
                _ => {}
            }
            offset += rec_size;
        }
        let creation_time = if flags & 0x01 != 0 {
            Some(filetime_to_datetime(u64::from_le_bytes(data[28..36].try_into().map_err(|_| "e")?)))
        } else { None };
        let modification_time = if flags & 0x02 != 0 {
            Some(filetime_to_datetime(u64::from_le_bytes(data[36..44].try_into().map_err(|_| "e")?)))
        } else { None };
        let access_time = if flags & 0x04 != 0 {
            Some(filetime_to_datetime(u64::from_le_bytes(data[44..52].try_into().map_err(|_| "e")?)))
        } else { None };
        Ok(LnkFile {
            target_path,
            target_file_size: file_size,
            creation_time,
            modification_time,
            access_time,
            mac_addresses,
            volume_serial,
            volume_type: None,
            local_base_path,
            command_line_arguments,
            icon_location,
            working_directory,
        })
    }
}

fn read_string_at(data: &[u8], offset: usize) -> Result<String, String> {
    if offset >= data.len() { return Err("out of bounds".into()); }
    let slice = &data[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Ok(String::from_utf8_lossy(&slice[..end]).to_string())
}

fn filetime_to_datetime(ft: u64) -> DateTime<Utc> {
    if ft == 0 { return Utc::now(); }
    let intervals = ft.saturating_sub(116444736000000000);
    let secs = intervals / 10_000_000;
    let nanos = ((intervals % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs as i64, nanos).unwrap_or_else(|| Utc::now())
}

pub type LnkEntry = LnkFile;

pub fn parse_lnk(data: &[u8]) -> Result<LnkFile, String> {
    LnkFile::parse(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_too_small() {
        assert!(LnkFile::parse(&[0u8; 10]).is_err());
    }
    #[test]
    fn test_invalid_magic() {
        let mut data = vec![0u8; 200];
        data[0..4].copy_from_slice(b"BAD!");
        assert!(LnkFile::parse(&data).is_err());
    }
    #[test]
    fn test_valid_minimal() {
        let mut data = vec![0u8; 200];
        data[0..4].copy_from_slice(b"L\x00\x00\x00");
        data[20..24].copy_from_slice(&0u32.to_le_bytes());
        let result = LnkFile::parse(&data);
        assert!(result.is_ok());
    }
    #[test]
    fn test_read_string_at_empty() {
        assert!(read_string_at(&[], 0).is_err());
    }
    #[test]
    fn test_filetime_zero() {
        let dt = filetime_to_datetime(0);
        assert!(dt <= Utc::now());
    }
}
