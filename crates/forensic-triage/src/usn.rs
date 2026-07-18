use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UsnReason {
    FileCreate,
    FileDelete,
    FileRename,
    FileModify,
    HardLinkChange,
    DataExtend,
    DataTruncation,
    SecurityChange,
    AclChange,
    XattrChange,
    Unknown(u32),
}

impl UsnReason {
    pub fn from_code(code: u32) -> Self {
        match code {
            0x00000100 => Self::FileCreate,
            0x00000200 => Self::FileDelete,
            0x00000400 | 0x00000004 => Self::FileRename,
            0x00000002 | 0x00000010 | 0x00000020 | 0x00000080 => Self::FileModify,
            0x00001000 => Self::HardLinkChange,
            0x00000008 => Self::DataExtend,
            0x00000001 => Self::DataTruncation,
            0x00000400 => Self::SecurityChange,
            0x00000800 => Self::AclChange,
            0x00002000 => Self::XattrChange,
            _ => Self::Unknown(code),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsnRecord {
    pub file_reference_number: u64,
    pub parent_file_reference_number: u64,
    pub usn: u64,
    pub timestamp: DateTime<Utc>,
    pub reason: UsnReason,
    pub source_info: u32,
    pub file_name: String,
    pub file_name_length: u16,
}

pub struct UsnJournalParser;

impl UsnJournalParser {
    pub fn parse_v2(data: &[u8]) -> Result<Vec<UsnRecord>, String> {
        let mut records = Vec::new();
        let mut offset = 0;
        while offset + 60 <= data.len() {
            let record_len = u32::from_le_bytes(data[offset..offset+4].try_into().map_err(|_| "len")?) as usize;
            let major_version = u16::from_le_bytes(data[offset+4..offset+6].try_into().map_err(|_| "ver")?);
            if major_version != 2 {
                offset += record_len.max(8);
                continue;
            }
            if record_len < 60 || offset + record_len > data.len() {
                break;
            }
            let file_ref = u64::from_le_bytes(data[offset+8..offset+16].try_into().map_err(|_| "fr")?);
            let parent_ref = u64::from_le_bytes(data[offset+16..offset+24].try_into().map_err(|_| "pr")?);
            let usn = u64::from_le_bytes(data[offset+24..offset+32].try_into().map_err(|_| "usn")?);
            let ft = u64::from_le_bytes(data[offset+32..offset+40].try_into().map_err(|_| "ft")?);
            let reason_code = u32::from_le_bytes(data[offset+40..offset+44].try_into().map_err(|_| "rs")?);
            let source_info = u32::from_le_bytes(data[offset+44..offset+48].try_into().map_err(|_| "si")?);
            let file_name_len = u16::from_le_bytes(data[offset+56..offset+58].try_into().map_err(|_| "fnl")?);
            let file_name_offset = u16::from_le_bytes(data[offset+58..offset+60].try_into().map_err(|_| "fno")?) as usize;
            let name_start = offset + file_name_offset;
            let name_end = name_start + file_name_len as usize;
            let file_name = if name_end <= data.len() {
                String::from_utf16_lossy(
                    &data[name_start..name_end]
                        .chunks_exact(2)
                        .filter_map(|c| <[u8; 2]>::try_from(c).ok().map(u16::from_le_bytes))
                        .collect::<Vec<_>>()
                )
            } else { String::new() };
            let timestamp = filetime_to_datetime(ft);
            records.push(UsnRecord {
                file_reference_number: file_ref,
                parent_file_reference_number: parent_ref,
                usn,
                timestamp,
                reason: UsnReason::from_code(reason_code),
                source_info,
                file_name,
                file_name_length: file_name_len,
            });
            offset += record_len;
        }
        Ok(records)
    }
}

fn filetime_to_datetime(ft: u64) -> DateTime<Utc> {
    if ft == 0 { return Utc::now(); }
    let intervals = ft.saturating_sub(116444736000000000);
    let secs = intervals / 10_000_000;
    let nanos = ((intervals % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs as i64, nanos).unwrap_or_else(|| Utc::now())
}

pub type UsnEntry = UsnRecord;

pub fn parse_usn_journal(data: &[u8]) -> Result<Vec<UsnRecord>, String> {
    UsnJournalParser::parse_v2(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_usn_reason_codes() {
        assert_eq!(UsnReason::from_code(0x00000100), UsnReason::FileCreate);
        assert_eq!(UsnReason::from_code(0x00000200), UsnReason::FileDelete);
        assert_eq!(UsnReason::from_code(0x00000008), UsnReason::DataExtend);
        assert!(matches!(UsnReason::from_code(0xDEAD), UsnReason::Unknown(0xDEAD)));
    }
    #[test]
    fn test_parse_empty() {
        let records = UsnJournalParser::parse_v2(&[]).unwrap();
        assert!(records.is_empty());
    }
    #[test]
    fn test_parse_invalid_version() {
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(&64u32.to_le_bytes());
        data[4..6].copy_from_slice(&3u16.to_le_bytes());
        let records = UsnJournalParser::parse_v2(&data).unwrap();
        assert!(records.is_empty());
    }
    #[test]
    fn test_parse_valid_v2() {
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(&128u32.to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        data[8..16].copy_from_slice(&42u64.to_le_bytes());
        data[16..24].copy_from_slice(&10u64.to_le_bytes());
        data[32..40].copy_from_slice(&132000000000000000u64.to_le_bytes());
        data[40..44].copy_from_slice(&0x00000100u32.to_le_bytes());
        data[56..58].copy_from_slice(&8u16.to_le_bytes());
        data[58..60].copy_from_slice(&60u16.to_le_bytes());
        let name_bytes = "test.txt".encode_utf16().collect::<Vec<_>>();
        for (i, ch) in name_bytes.iter().enumerate() {
            let b = ch.to_le_bytes();
            data[60 + i*2] = b[0];
            data[60 + i*2 + 1] = b[1];
        }
        let records = UsnJournalParser::parse_v2(&data).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].file_reference_number, 42);
        assert_eq!(records[0].reason, UsnReason::FileCreate);
    }
    #[test]
    fn test_filetime_conversion() {
        let dt = filetime_to_datetime(132000000000000000);
        assert!(dt > Utc::now() - chrono::Duration::days(365 * 10));
    }
}
