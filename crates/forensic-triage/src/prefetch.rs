use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::{ForensicError, Result};

const PREFETCH_MAGIC: &[u8; 4] = b"SCCA";
const PREFETCH_VERSION_17: u32 = 17;
const PREFETCH_VERSION_23: u32 = 23;
const PREFETCH_VERSION_26: u32 = 26;
const PREFETCH_VERSION_30: u32 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchEntry {
    pub executable_name: String,
    pub run_count: u32,
    pub last_run_time: Option<DateTime<Utc>>,
    pub file_references: Vec<String>,
    pub volume_name: String,
    pub volume_serial: String,
    pub version: u32,
    pub file_size: u64,
    pub mft_entry: u64,
}

#[derive(Debug)]
struct PrefetchHeader {
    version: u32,
    file_name: String,
    run_count: u32,
    last_run_time: u64,
    file_size: u64,
    mft_entry: u64,
    volume_name_offset: u32,
    volume_name_length: u32,
    volume_serial: u32,
    file_refs_offset: u32,
    file_refs_count: u32,
}

pub fn parse_prefetch(data: &[u8]) -> Result<PrefetchEntry> {
    if data.len() < 84 {
        return Err(ForensicError::BufferTooSmall { needed: 84, have: data.len() });
    }

    if &data[0..4] != PREFETCH_MAGIC {
        return Err(ForensicError::InvalidMagic);
    }

    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let header = match version {
        PREFETCH_VERSION_17 => parse_header_v17(data)?,
        PREFETCH_VERSION_23 | PREFETCH_VERSION_26 => parse_header_v23(data)?,
        PREFATCH_VERSION_30 => parse_header_v30(data)?,
        _ => return Err(ForensicError::UnsupportedVersion(version)),
    };

    let file_references = parse_file_references(data, &header)?;
    let volume_name = extract_volume_name(data, &header)?;

    let volume_serial = format!("{:08X}", header.volume_serial);

    let last_run_time = filetime_to_datetime(header.last_run_time);

    Ok(PrefetchEntry {
        executable_name: header.file_name,
        run_count: header.run_count,
        last_run_time,
        file_references,
        volume_name,
        volume_serial,
        version,
        file_size: header.file_size,
        mft_entry: header.mft_entry,
    })
}

fn parse_header_v17(data: &[u8]) -> Result<PrefetchHeader> {
    if data.len() < 156 {
        return Err(ForensicError::BufferTooSmall { needed: 156, have: data.len() });
    }

    let file_name = decode_utf16_le_fixed(&data[16..80]);
    let run_count = u32::from_le_bytes(data[92..96].try_into().unwrap());
    let last_run_time = u64::from_le_bytes(data[128..136].try_into().unwrap());
    let file_size = u32::from_le_bytes(data[80..84].try_into().unwrap()) as u64;
    let mft_entry = u32::from_le_bytes(data[84..88].try_into().unwrap()) as u64;
    let volume_name_offset = u32::from_le_bytes(data[96..100].try_into().unwrap());
    let volume_name_length = u32::from_le_bytes(data[100..104].try_into().unwrap());
    let volume_serial = u32::from_le_bytes(data[104..108].try_into().unwrap());
    let file_refs_offset = u32::from_le_bytes(data[108..112].try_into().unwrap());
    let file_refs_count = u32::from_le_bytes(data[112..116].try_into().unwrap());

    Ok(PrefetchHeader {
        version: 17,
        file_name,
        run_count,
        last_run_time,
        file_size,
        mft_entry,
        volume_name_offset,
        volume_name_length,
        volume_serial,
        file_refs_offset,
        file_refs_count,
    })
}

fn parse_header_v23(data: &[u8]) -> Result<PrefetchHeader> {
    if data.len() < 224 {
        return Err(ForensicError::BufferTooSmall { needed: 224, have: data.len() });
    }

    let file_name = decode_utf16_le_fixed(&data[16..80]);
    let run_count = u32::from_le_bytes(data[208..212].try_into().unwrap());
    let last_run_time = u64::from_le_bytes(data[128..136].try_into().unwrap());
    let file_size = u32::from_le_bytes(data[80..84].try_into().unwrap()) as u64;
    let mft_entry = u64::from_le_bytes(data[84..92].try_into().unwrap());
    let volume_name_offset = u32::from_le_bytes(data[96..100].try_into().unwrap());
    let volume_name_length = u32::from_le_bytes(data[100..104].try_into().unwrap());
    let volume_serial = u32::from_le_bytes(data[104..108].try_into().unwrap());
    let file_refs_offset = u32::from_le_bytes(data[108..112].try_into().unwrap());
    let file_refs_count = u32::from_le_bytes(data[112..116].try_into().unwrap());

    Ok(PrefetchHeader {
        version: 23,
        file_name,
        run_count,
        last_run_time,
        file_size,
        mft_entry,
        volume_name_offset,
        volume_name_length,
        volume_serial,
        file_refs_offset,
        file_refs_count,
    })
}

fn parse_header_v30(data: &[u8]) -> Result<PrefetchHeader> {
    if data.len() < 224 {
        return Err(ForensicError::BufferTooSmall { needed: 224, have: data.len() });
    }

    let file_name = decode_utf16_le_fixed(&data[16..80]);
    let run_count = u32::from_le_bytes(data[208..212].try_into().unwrap());
    let last_run_time = u64::from_le_bytes(data[128..136].try_into().unwrap());
    let file_size = u32::from_le_bytes(data[80..84].try_into().unwrap()) as u64;
    let mft_entry = u64::from_le_bytes(data[84..92].try_into().unwrap());
    let volume_name_offset = u32::from_le_bytes(data[96..100].try_into().unwrap());
    let volume_name_length = u32::from_le_bytes(data[100..104].try_into().unwrap());
    let volume_serial = u32::from_le_bytes(data[104..108].try_into().unwrap());
    let file_refs_offset = u32::from_le_bytes(data[108..112].try_into().unwrap());
    let file_refs_count = u32::from_le_bytes(data[112..116].try_into().unwrap());

    Ok(PrefetchHeader {
        version: 30,
        file_name,
        run_count,
        last_run_time,
        file_size,
        mft_entry,
        volume_name_offset,
        volume_name_length,
        volume_serial,
        file_refs_offset,
        file_refs_count,
    })
}

fn parse_file_references(data: &[u8], header: &PrefetchHeader) -> Result<Vec<String>> {
    let mut refs = Vec::new();
    let offset = header.file_refs_offset as usize;
    let count = header.file_refs_count as usize;

    for i in 0..count {
        let entry_offset = offset + i * 16;
        if entry_offset + 16 > data.len() {
            break;
        }
        let ref_offset = u32::from_le_bytes(data[entry_offset..entry_offset + 4].try_into().unwrap()) as usize;
        let ref_len = u16::from_le_bytes(data[entry_offset + 4..entry_offset + 6].try_into().unwrap()) as usize;

        if ref_offset + ref_len * 2 <= data.len() {
            let name = decode_utf16_le(&data[ref_offset..ref_offset + ref_len * 2]);
            if !name.is_empty() {
                refs.push(name);
            }
        }
    }

    Ok(refs)
}

fn extract_volume_name(data: &[u8], header: &PrefetchHeader) -> Result<String> {
    let offset = header.volume_name_offset as usize;
    let len = header.volume_name_length as usize;

    if offset + len * 2 > data.len() {
        return Ok(String::new());
    }

    Ok(decode_utf16_le(&data[offset..offset + len * 2]))
}

fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
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

    fn make_prefetch_v26() -> Vec<u8> {
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(PREFETCH_MAGIC);
        data[4..8].copy_from_slice(&26u32.to_le_bytes());

        let name = "CMD.EXE";
        for (i, ch) in name.encode_utf16().enumerate() {
            let off = 16 + i * 2;
            data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        data[80..84].copy_from_slice(&12345u32.to_le_bytes());
        data[84..92].copy_from_slice(&67890u64.to_le_bytes());
        data[96..100].copy_from_slice(&136u32.to_le_bytes());
        data[100..104].copy_from_slice(&23u32.to_le_bytes());
        data[104..108].copy_from_slice(&0xABCD1234u32.to_le_bytes());
        data[108..112].copy_from_slice(&224u32.to_le_bytes());
        data[112..116].copy_from_slice(&2u32.to_le_bytes());
        data[208..212].copy_from_slice(&100u32.to_le_bytes());

        let ft: u64 = 130_000_000_000_000_000;
        data[128..136].copy_from_slice(&ft.to_le_bytes());

        let vol_name = "\\DEVICE\\HARDDISKVOLUME1";
        for (i, ch) in vol_name.encode_utf16().enumerate() {
            let off = 136 + i * 2;
            if off + 2 < data.len() {
                data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
            }
        }

        let refs = ["\\WINDOWS\\SYSTEM32\\CMD.EXE", "\\WINDOWS\\SYSTEM32\\NTDLL.DLL"];
        let mut ref_off = 256;
        for (i, r#ref) in refs.iter().enumerate() {
            let entry_offset = 224 + i * 16;
            data[entry_offset..entry_offset + 4].copy_from_slice(&(ref_off as u32).to_le_bytes());
            data[entry_offset + 4..entry_offset + 6].copy_from_slice(&(r#ref.len() as u16).to_le_bytes());
            for (j, ch) in r#ref.encode_utf16().enumerate() {
                let off = ref_off + j * 2;
                if off + 2 < data.len() {
                    data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
                }
            }
            ref_off += r#ref.len() * 2;
        }

        data
    }

    #[test]
    fn test_invalid_magic() {
        let data = vec![0u8; 256];
        let result = parse_prefetch(&data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ForensicError::InvalidMagic));
    }

    #[test]
    fn test_buffer_too_small() {
        let mut data = vec![0u8; 10];
        data[0..4].copy_from_slice(PREFETCH_MAGIC);
        let result = parse_prefetch(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_prefetch_v26() {
        let data = make_prefetch_v26();
        let entry = parse_prefetch(&data).unwrap();
        assert_eq!(entry.executable_name, "CMD.EXE");
        assert_eq!(entry.run_count, 100);
        assert_eq!(entry.version, 26);
    }

    #[test]
    fn test_parse_prefetch_file_refs() {
        let data = make_prefetch_v26();
        let entry = parse_prefetch(&data).unwrap();
        assert_eq!(entry.file_references.len(), 2);
    }

    #[test]
    fn test_parse_prefetch_volume() {
        let data = make_prefetch_v26();
        let entry = parse_prefetch(&data).unwrap();
        assert!(entry.volume_name.contains("HARDDISKVOLUME1"));
        assert_eq!(entry.volume_serial, "ABCD1234");
    }

    #[test]
    fn test_parse_prefetch_timestamp() {
        let data = make_prefetch_v26();
        let entry = parse_prefetch(&data).unwrap();
        assert!(entry.last_run_time.is_some());
    }

    #[test]
    fn test_filetime_to_datetime_zero() {
        assert!(filetime_to_datetime(0).is_none());
    }

    #[test]
    fn test_filetime_to_datetime_valid() {
        let dt = filetime_to_datetime(130_000_000_000_000_000);
        assert!(dt.is_some());
    }
}
