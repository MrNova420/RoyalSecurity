use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::{ForensicError, Result};

const MFT_RECORD_SIZE: usize = 1024;
const MFT_MAGIC: &[u8; 4] = b"FILE";
const STANDARD_INFO_ATTR: u32 = 0x10;
const FILE_NAME_ATTR: u32 = 0x30;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MftEntry {
    pub entry_number: u64,
    pub sequence_number: u16,
    pub flags: u16,
    pub is_directory: bool,
    pub is_active: bool,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub mft_changed: Option<DateTime<Utc>>,
    pub file_size: u64,
    pub file_name: String,
    pub parent_ref: u64,
}

#[derive(Debug)]
struct MftRecordHeader {
    signature: [u8; 4],
    offset_of_fixup_array: u16,
    number_of_entries_in_fixup_array: u16,
    sequence_number: u16,
    sequence_number_age: u16,
    hard_link_count: u16,
    first_attribute_offset: u16,
    flags: u16,
    used_size_of_mft_entry: u32,
    allocated_size_of_mft_entry: u32,
    base_record_reference: u64,
    next_attribute_id: u16,
}

pub fn parse_mft(data: &[u8]) -> Result<Vec<MftEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0;
    let mut entry_number: u64 = 0;

    while offset + MFT_RECORD_SIZE <= data.len() {
        if &data[offset..offset + 4] != MFT_MAGIC {
            offset += MFT_RECORD_SIZE;
            entry_number += 1;
            continue;
        }

        let header = parse_record_header(&data[offset..])?;

        if header.flags & 0x01 == 0 {
            offset += MFT_RECORD_SIZE;
            entry_number += 1;
            continue;
        }

        let mut entry = MftEntry {
            entry_number,
            sequence_number: header.sequence_number,
            flags: header.flags,
            is_directory: header.flags & 0x02 != 0,
            is_active: header.flags & 0x01 != 0,
            created: None,
            modified: None,
            accessed: None,
            mft_changed: None,
            file_size: 0,
            file_name: String::new(),
            parent_ref: 0,
        };

        let first_attr_offset = offset + header.first_attribute_offset as usize;
        let mut attr_offset = first_attr_offset;

        while attr_offset + 4 <= offset + MFT_RECORD_SIZE {
            let attr_type = u32::from_le_bytes([
                data[attr_offset],
                data[attr_offset + 1],
                data[attr_offset + 2],
                data[attr_offset + 3],
            ]);

            if attr_type == 0xFFFFFFFF || attr_offset + 8 > data.len() {
                break;
            }

            let attr_length = u32::from_le_bytes([
                data[attr_offset + 4],
                data[attr_offset + 5],
                data[attr_offset + 6],
                data[attr_offset + 7],
            ]) as usize;

            if attr_length < 24 || attr_offset + attr_length > offset + MFT_RECORD_SIZE {
                break;
            }

            let non_resident = data[attr_offset + 8];

            match attr_type {
                STANDARD_INFO_ATTR if non_resident == 0 => {
                    parse_standard_info(data, attr_offset, &mut entry)?;
                }
                FILE_NAME_ATTR if non_resident == 0 => {
                    parse_file_name(data, attr_offset, &mut entry)?;
                }
                _ => {}
            }

            attr_offset += attr_length;
        }

        entries.push(entry);
        offset += MFT_RECORD_SIZE;
        entry_number += 1;

        if entries.len() >= 100000 {
            break;
        }
    }

    Ok(entries)
}

fn parse_record_header(data: &[u8]) -> Result<MftRecordHeader> {
    if data.len() < 48 {
        return Err(ForensicError::BufferTooSmall { needed: 48, have: data.len() });
    }

    let mut signature = [0u8; 4];
    signature.copy_from_slice(&data[0..4]);

    Ok(MftRecordHeader {
        signature,
        offset_of_fixup_array: u16::from_le_bytes([data[4], data[5]]),
        number_of_entries_in_fixup_array: u16::from_le_bytes([data[6], data[7]]),
        sequence_number: u16::from_le_bytes([data[8], data[9]]),
        sequence_number_age: u16::from_le_bytes([data[10], data[11]]),
        hard_link_count: u16::from_le_bytes([data[12], data[13]]),
        first_attribute_offset: u16::from_le_bytes([data[14], data[15]]),
        flags: u16::from_le_bytes([data[16], data[17]]),
        used_size_of_mft_entry: u32::from_le_bytes([data[18], data[19], data[20], data[21]]),
        allocated_size_of_mft_entry: u32::from_le_bytes([data[22], data[23], data[24], data[25]]),
        base_record_reference: u64::from_le_bytes(data[26..34].try_into().unwrap()),
        next_attribute_id: u16::from_le_bytes([data[34], data[35]]),
    })
}

fn parse_standard_info(data: &[u8], attr_offset: usize, entry: &mut MftEntry) -> Result<()> {
    let content_offset = attr_offset + 24;
    if content_offset + 48 > data.len() {
        return Ok(());
    }

    entry.created = filetime_to_datetime(u64::from_le_bytes(data[content_offset..content_offset + 8].try_into().unwrap()));
    entry.modified = filetime_to_datetime(u64::from_le_bytes(data[content_offset + 8..content_offset + 16].try_into().unwrap()));
    entry.mft_changed = filetime_to_datetime(u64::from_le_bytes(data[content_offset + 16..content_offset + 24].try_into().unwrap()));
    entry.accessed = filetime_to_datetime(u64::from_le_bytes(data[content_offset + 24..content_offset + 32].try_into().unwrap()));

    Ok(())
}

fn parse_file_name(data: &[u8], attr_offset: usize, entry: &mut MftEntry) -> Result<()> {
    let content_offset = attr_offset + 24;
    if content_offset + 66 > data.len() {
        return Ok(());
    }

    let parent_ref = u64::from_le_bytes(data[content_offset..content_offset + 8].try_into().unwrap()) & 0x0000FFFFFFFFFFFF;

    let file_name_len = data[content_offset + 64] as usize;
    let file_name_ns = data[content_offset + 65];

    if file_name_len > 0 && content_offset + 66 + file_name_len * 2 <= data.len() {
        let name_bytes = &data[content_offset + 66..content_offset + 66 + file_name_len * 2];
        let name = decode_utf16_le(name_bytes);
        if !name.is_empty() {
            entry.file_name = name;
        }
    }

    entry.parent_ref = parent_ref;

    if entry.file_size == 0 {
        entry.file_size = u64::from_le_bytes(data[content_offset + 40..content_offset + 48].try_into().unwrap());
    }

    Ok(())
}

fn filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }

    let intervals = filetime;
    let windows_epoch_diff: i64 = 116_444_736_000_000_000;
    let unix_time = ((intervals as i64) - windows_epoch_diff) / 10_000_000;

    DateTime::from_timestamp(unix_time, 0)
}

fn decode_utf16_le(data: &[u8]) -> String {
    let chunks: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&chunks).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mft_entry(data: &[u8]) -> Vec<u8> {
        let mut entry = vec![0u8; 1024];
        entry[0..4].copy_from_slice(MFT_MAGIC);
        entry[4..6].copy_from_slice(&[40, 0]);
        entry[6..8].copy_from_slice(&[1, 0]);
        entry[8..10].copy_from_slice(&[1, 0]);
        entry[14..16].copy_from_slice(&[56, 0]);
        entry[16..18].copy_from_slice(&[3, 0]);

        let si_offset = 56;
        entry[si_offset..si_offset + 4].copy_from_slice(&STANDARD_INFO_ATTR.to_le_bytes());
        entry[si_offset + 4..si_offset + 8].copy_from_slice(&[72, 0, 0, 0]);
        entry[si_offset + 8..si_offset + 9].copy_from_slice(&[0]);

        let si_content = si_offset + 24;
        let ft: u64 = 130_000_000_000_000_000;
        entry[si_content..si_content + 8].copy_from_slice(&ft.to_le_bytes());
        entry[si_content + 8..si_content + 16].copy_from_slice(&ft.to_le_bytes());
        entry[si_content + 16..si_content + 24].copy_from_slice(&ft.to_le_bytes());
        entry[si_content + 24..si_content + 32].copy_from_slice(&ft.to_le_bytes());

        let fn_offset = si_offset + 72;
        entry[fn_offset..fn_offset + 4].copy_from_slice(&FILE_NAME_ATTR.to_le_bytes());
        entry[fn_offset + 4..fn_offset + 8].copy_from_slice(&[80, 0, 0, 0]);
        entry[fn_offset + 8..fn_offset + 9].copy_from_slice(&[0]);

        let fn_content = fn_offset + 24;
        entry[fn_content..fn_content + 8].copy_from_slice(&[0, 0, 0, 0, 5, 0, 0, 0]);
        let name = "test.txt";
        let name_len = name.len() as u8;
        entry[fn_content + 64] = name_len;
        entry[fn_content + 65] = 0;
        for (i, ch) in name.encode_utf16().enumerate() {
            let off = fn_content + 66 + i * 2;
            entry[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        if !data.is_empty() {
            entry.extend_from_slice(data);
        }

        entry
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(b"NOPE");
        let result = parse_mft(&data);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_buffer_too_small() {
        let data = vec![0u8; 10];
        let result = parse_mft(&data);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_mft_valid_entry() {
        let entry_data = make_mft_entry(&[]);
        let entries = parse_mft(&entry_data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_number, 0);
        assert_eq!(entries[0].sequence_number, 1);
    }

    #[test]
    fn test_parse_mft_inactive_entry() {
        let mut entry = vec![0u8; 1024];
        entry[0..4].copy_from_slice(MFT_MAGIC);
        entry[16..18].copy_from_slice(&[0, 0]);
        let entries = parse_mft(&entry).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_mft_directory_flag() {
        let mut entry = vec![0u8; 1024];
        entry[0..4].copy_from_slice(MFT_MAGIC);
        entry[4..6].copy_from_slice(&[40, 0]);
        entry[14..16].copy_from_slice(&[56, 0]);
        entry[16..18].copy_from_slice(&[3, 0]);
        let entries = parse_mft(&entry).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_directory);
        assert!(entries[0].is_active);
    }

    #[test]
    fn test_filetime_to_datetime_valid() {
        let dt = filetime_to_datetime(130_000_000_000_000_000);
        assert!(dt.is_some());
    }

    #[test]
    fn test_filetime_to_datetime_zero() {
        assert!(filetime_to_datetime(0).is_none());
    }
}
