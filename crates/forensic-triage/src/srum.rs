use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::{ForensicError, Result};

const SRUM_MAGIC: &[u8; 4] = b"SRUM";
const SRUM_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrumEntry {
    pub entry_type: String,
    pub application_id: String,
    pub user_sid: String,
    pub resource_id: u32,
    pub timestamp: Option<DateTime<Utc>>,
    pub data: SrumData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SrumData {
    NetworkUsage {
        bytes_sent: u64,
        bytes_received: u64,
        connect_time_ms: u64,
        connected: bool,
    },
    ApplicationUsage {
        cpu_time_ms: u64,
        disk_bytes_read: u64,
        disk_bytes_written: u64,
        context_switches: u64,
        page_faults: u64,
    },
    EnergyUsage {
        cpu_energy: u64,
        af_energy: u64,
        disk_energy: u64,
        network_energy: u64,
        display_energy: u64,
    },
    Unknown(Vec<u8>),
}

#[derive(Debug)]
struct SrumHeader {
    magic: [u8; 4],
    version: u32,
    entry_count: u32,
    table_offset: u32,
    table_size: u32,
}

pub fn parse_srum(data: &[u8]) -> Result<Vec<SrumEntry>> {
    let mut entries = Vec::new();

    if data.len() < 64 {
        return Err(ForensicError::BufferTooSmall { needed: 64, have: data.len() });
    }

    if &data[0..4] != SRUM_MAGIC {
        return Err(ForensicError::InvalidMagic);
    }

    let header = parse_srum_header(data)?;
    let mut offset = header.table_offset as usize;

    for i in 0..header.entry_count as usize {
        if offset + 32 > data.len() {
            break;
        }

        let entry_type = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let entry_size = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let timestamp = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap());

        if entry_size < 32 || offset + entry_size > data.len() {
            break;
        }

        let entry_data = &data[offset + 32..offset + entry_size];

        let parsed = match entry_type {
            1 => parse_network_usage(entry_data),
            2 => parse_application_usage(entry_data),
            3 => parse_energy_usage(entry_data),
            _ => SrumData::Unknown(entry_data.to_vec()),
        };

        let application_id = extract_string_field(entry_data, 0);
        let user_sid = extract_string_field(entry_data, 64);
        let resource_id = u32::from_le_bytes(entry_data.get(128..132).map(|s| { let mut b = [0u8; 4]; let len = s.len().min(4); b[..len].copy_from_slice(&s[..len]); b }).unwrap_or([0u8; 4]));

        entries.push(SrumEntry {
            entry_type: match entry_type {
                1 => "NetworkUsage".to_string(),
                2 => "ApplicationUsage".to_string(),
                3 => "EnergyUsage".to_string(),
                _ => format!("Unknown({})", entry_type),
            },
            application_id,
            user_sid,
            resource_id,
            timestamp: windows_filetime_to_datetime(timestamp),
            data: parsed,
        });

        offset += entry_size;
    }

    Ok(entries)
}

fn parse_srum_header(data: &[u8]) -> Result<SrumHeader> {
    if data.len() < 64 {
        return Err(ForensicError::BufferTooSmall { needed: 64, have: data.len() });
    }

    let mut magic = [0u8; 4];
    magic.copy_from_slice(&data[0..4]);

    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let entry_count = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let table_offset = u32::from_le_bytes(data[12..16].try_into().unwrap());
    let table_size = u32::from_le_bytes(data[16..20].try_into().unwrap());

    Ok(SrumHeader {
        magic,
        version,
        entry_count,
        table_offset,
        table_size,
    })
}

fn parse_network_usage(data: &[u8]) -> SrumData {
    let bytes_sent = if data.len() >= 8 {
        u64::from_le_bytes(data[0..8].try_into().unwrap())
    } else {
        0
    };

    let bytes_received = if data.len() >= 16 {
        u64::from_le_bytes(data[8..16].try_into().unwrap())
    } else {
        0
    };

    let connect_time_ms = if data.len() >= 24 {
        u64::from_le_bytes(data[16..24].try_into().unwrap())
    } else {
        0
    };

    let connected = if data.len() >= 32 {
        u32::from_le_bytes(data[24..28].try_into().unwrap()) != 0
    } else {
        false
    };

    SrumData::NetworkUsage {
        bytes_sent,
        bytes_received,
        connect_time_ms,
        connected,
    }
}

fn parse_application_usage(data: &[u8]) -> SrumData {
    let cpu_time_ms = if data.len() >= 8 {
        u64::from_le_bytes(data[0..8].try_into().unwrap())
    } else {
        0
    };

    let disk_bytes_read = if data.len() >= 16 {
        u64::from_le_bytes(data[8..16].try_into().unwrap())
    } else {
        0
    };

    let disk_bytes_written = if data.len() >= 24 {
        u64::from_le_bytes(data[16..24].try_into().unwrap())
    } else {
        0
    };

    let context_switches = if data.len() >= 32 {
        u64::from_le_bytes(data[24..32].try_into().unwrap())
    } else {
        0
    };

    let page_faults = if data.len() >= 40 {
        u64::from_le_bytes(data[32..40].try_into().unwrap())
    } else {
        0
    };

    SrumData::ApplicationUsage {
        cpu_time_ms,
        disk_bytes_read,
        disk_bytes_written,
        context_switches,
        page_faults,
    }
}

fn parse_energy_usage(data: &[u8]) -> SrumData {
    let cpu_energy = if data.len() >= 8 {
        u64::from_le_bytes(data[0..8].try_into().unwrap())
    } else {
        0
    };

    let af_energy = if data.len() >= 16 {
        u64::from_le_bytes(data[8..16].try_into().unwrap())
    } else {
        0
    };

    let disk_energy = if data.len() >= 24 {
        u64::from_le_bytes(data[16..24].try_into().unwrap())
    } else {
        0
    };

    let network_energy = if data.len() >= 32 {
        u64::from_le_bytes(data[24..32].try_into().unwrap())
    } else {
        0
    };

    let display_energy = if data.len() >= 40 {
        u64::from_le_bytes(data[32..40].try_into().unwrap())
    } else {
        0
    };

    SrumData::EnergyUsage {
        cpu_energy,
        af_energy,
        disk_energy,
        network_energy,
        display_energy,
    }
}

fn extract_string_field(data: &[u8], offset: usize) -> String {
    if offset + 64 > data.len() {
        return String::new();
    }

    let field_data = &data[offset..offset + 64];
    let end = field_data.iter().position(|&b| b == 0).unwrap_or(64);
    String::from_utf8_lossy(&field_data[..end]).to_string()
}

fn windows_filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }

    let windows_epoch_diff: i64 = 116_444_736_000_000_000;
    let unix_time = ((filetime as i64) - windows_epoch_diff) / 10_000_000;

    DateTime::from_timestamp(unix_time, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_magic() {
        let data = vec![0u8; 128];
        let result = parse_srum(&data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ForensicError::InvalidMagic));
    }

    #[test]
    fn test_buffer_too_small() {
        let data = vec![0u8; 10];
        let result = parse_srum(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_srum_empty() {
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(SRUM_MAGIC);
        data[4..8].copy_from_slice(&SRUM_VERSION.to_le_bytes());
        let entries = parse_srum(&data).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_srum_valid_header() {
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(SRUM_MAGIC);
        data[4..8].copy_from_slice(&SRUM_VERSION.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        data[12..16].copy_from_slice(&64u32.to_le_bytes());
        let result = parse_srum(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_network_usage() {
        let data = vec![0u8; 32];
        let result = parse_network_usage(&data);
        assert!(matches!(result, SrumData::NetworkUsage { .. }));
    }

    #[test]
    fn test_parse_application_usage() {
        let data = vec![0u8; 40];
        let result = parse_application_usage(&data);
        assert!(matches!(result, SrumData::ApplicationUsage { .. }));
    }

    #[test]
    fn test_parse_energy_usage() {
        let data = vec![0u8; 40];
        let result = parse_energy_usage(&data);
        assert!(matches!(result, SrumData::EnergyUsage { .. }));
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
    fn test_srum_entry_serialization() {
        let entry = SrumEntry {
            entry_type: "NetworkUsage".to_string(),
            application_id: "TestApp".to_string(),
            user_sid: "S-1-5-21".to_string(),
            resource_id: 1,
            timestamp: None,
            data: SrumData::NetworkUsage {
                bytes_sent: 1024,
                bytes_received: 2048,
                connect_time_ms: 5000,
                connected: true,
            },
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("NetworkUsage"));
        assert!(json.contains("TestApp"));
    }
}


