use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::{ForensicError, Result};

const EVTX_MAGIC: &[u8; 8] = b"ElfFile\x00";
const CHUNK_MAGIC: &[u8; 7] = b"ElfChnk";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvtxEvent {
    pub event_id: u32,
    pub timestamp: Option<DateTime<Utc>>,
    pub channel: String,
    pub provider: String,
    pub computer: String,
    pub level: u32,
    pub message: String,
    pub data_fields: Vec<(String, String)>,
    pub record_id: u64,
}

#[derive(Debug)]
struct EvtxHeader {
    chunk_count: u32,
    header_size: u32,
    minor_version: u16,
    major_version: u16,
}

#[derive(Debug)]
struct ChunkHeader {
    first_event_record_number: u64,
    last_event_record_number: u64,
    first_event_record_identifier: u64,
    last_event_record_identifier: u64,
    header_size: u32,
    last_event_record_data_offset: u32,
}

pub fn parse_evtx(data: &[u8]) -> Result<Vec<EvtxEvent>> {
    if data.len() < 128 {
        return Err(ForensicError::BufferTooSmall { needed: 128, have: data.len() });
    }

    if &data[0..8] != EVTX_MAGIC {
        return Err(ForensicError::InvalidMagic);
    }

    let major = u16::from_le_bytes([data[4], data[5]]);
    let minor = u16::from_le_bytes([data[6], data[7]]);
    let _header_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let chunk_count = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);

    let _header = EvtxHeader {
        chunk_count,
        header_size: _header_size,
        minor_version: minor,
        major_version: major,
    };

    let mut events = Vec::new();
    let mut offset = 4096;

    for _ in 0..chunk_count {
        if offset + 512 > data.len() {
            break;
        }

        if &data[offset..offset + 4] != CHUNK_MAGIC {
            offset += 65536;
            continue;
        }

        let chunk_header = parse_chunk_header(&data[offset..])?;

        let mut rec_offset = offset + 512;
        let _start_offset = offset;

        while rec_offset < offset + 65536 - 4 {
            if rec_offset + 8 > data.len() {
                break;
            }

            let rec_size = i32::from_le_bytes([
                data[rec_offset],
                data[rec_offset + 1],
                data[rec_offset + 2],
                data[rec_offset + 3],
            ]);

            if rec_size <= 0 || rec_size > 65536 {
                break;
            }

            let abs_size = rec_size.unsigned_abs() as usize;
            if rec_offset + abs_size > data.len() {
                break;
            }

            let template_id = i16::from_le_bytes([
                data[rec_offset + 4],
                data[rec_offset + 5],
            ]);

            if template_id < 0 {
                rec_offset += abs_size;
                continue;
            }

            let tokens_offset = i16::from_le_bytes([
                data[rec_offset + 6],
                data[rec_offset + 7],
            ]);

            if tokens_offset > 0 {
                let xml_offset = rec_offset + tokens_offset as usize;
                if xml_offset < data.len() {
                    let xml_data = &data[xml_offset..rec_offset + abs_size];
                    if let Some(event) = parse_xml_fragment(xml_data) {
                        events.push(event);
                    }
                }
            }

            rec_offset += abs_size;
        }

        offset += 65536;
    }

    Ok(events)
}

fn parse_chunk_header(data: &[u8]) -> Result<ChunkHeader> {
    if data.len() < 128 {
        return Err(ForensicError::BufferTooSmall { needed: 128, have: data.len() });
    }

    Ok(ChunkHeader {
        first_event_record_number: u64::from_le_bytes(data[24..32].try_into().unwrap()),
        last_event_record_number: u64::from_le_bytes(data[32..40].try_into().unwrap()),
        first_event_record_identifier: u64::from_le_bytes(data[40..48].try_into().unwrap()),
        last_event_record_identifier: u64::from_le_bytes(data[48..56].try_into().unwrap()),
        header_size: u32::from_le_bytes(data[0..4].try_into().unwrap()),
        last_event_record_data_offset: u32::from_le_bytes(data[60..64].try_into().unwrap()),
    })
}

fn parse_xml_fragment(data: &[u8]) -> Option<EvtxEvent> {
    let text = String::from_utf8_lossy(data);
    let text = text.trim_end_matches('\0');

    if text.is_empty() {
        return None;
    }

    let event_id = extract_xml_value(text, "EventID").and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    let channel = extract_xml_value(text, "Channel").unwrap_or_default();
    let provider = extract_xml_value(text, "Provider").unwrap_or_default();
    let computer = extract_xml_value(text, "Computer").unwrap_or_default();
    let level = extract_xml_value(text, "Level").and_then(|v| v.parse::<u32>().ok()).unwrap_or(4);
    let message = extract_xml_value(text, "Message").unwrap_or_default();
    let record_id = extract_xml_value(text, "EventRecordID").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);

    let timestamp = extract_xml_value(text, "TimeCreated").and_then(|ts| {
        chrono::DateTime::parse_from_rfc3339(&ts)
            .map(|dt| dt.with_timezone(&Utc))
            .ok()
    });

    let mut data_fields = Vec::new();
    for name in &["TargetUserName", "TargetDomainName", "IpAddress", "ProcessName",
                   "CommandLine", "NewProcessId", "SubjectUserName", "LogonId",
                   "Status", "SubStatus", "LogonType", "AuthenticationPackageName"] {
        if let Some(val) = extract_xml_value(text, name) {
            data_fields.push((name.to_string(), val));
        }
    }

    Some(EvtxEvent {
        event_id,
        timestamp,
        channel,
        provider,
        computer,
        level,
        message,
        data_fields,
        record_id,
    })
}

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);

    let start = xml.find(&open)?;
    let after_open = xml[start..].find('>')? + start + 1;
    let end = xml[after_open..].find(&close)? + after_open;

    let value = xml[after_open..end].trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_magic() {
        let data = vec![0u8; 128];
        let result = parse_evtx(&data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ForensicError::InvalidMagic));
    }

    #[test]
    fn test_buffer_too_small() {
        let data = vec![0u8; 10];
        let result = parse_evtx(&data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ForensicError::BufferTooSmall { .. }));
    }

    #[test]
    fn test_extract_xml_value() {
        let xml = r#"<EventID>4624</EventID>"#;
        let val = extract_xml_value(xml, "EventID");
        assert_eq!(val, Some("4624".to_string()));
    }

    #[test]
    fn test_extract_xml_value_missing() {
        let xml = r#"<EventID>4624</EventID>"#;
        let val = extract_xml_value(xml, "NonExistent");
        assert_eq!(val, None);
    }

    #[test]
    fn test_extract_xml_value_empty() {
        let xml = r#"<Message></Message>"#;
        let val = extract_xml_value(xml, "Message");
        assert_eq!(val, None);
    }

    #[test]
    fn test_parse_evtx_valid_header_wrong_chunks() {
        let mut data = vec![0u8; 4096 + 512];
        data[0..8].copy_from_slice(EVTX_MAGIC);
        data[8..12].copy_from_slice(&[0, 1, 0, 0]);
        data[16..20].copy_from_slice(&[0, 0, 0, 0]);
        let result = parse_evtx(&data);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_xml_fragment_empty() {
        assert!(parse_xml_fragment(b"").is_none());
    }

    #[test]
    fn test_parse_xml_fragment_valid() {
        let xml = br#"<EventID>4624</EventID><Channel>Security</Channel><Provider>Microsoft-Windows-Security-Auditing</Provider><Computer>TEST-PC</Computer><Level>0</Level><EventRecordID>12345</EventRecordID><TimeCreated>2024-01-15T10:30:00Z</TimeCreated><TargetUserName>SYSTEM</TargetUserName>"#;
        let event = parse_xml_fragment(xml).unwrap();
        assert_eq!(event.event_id, 4624);
        assert_eq!(event.channel, "Security");
        assert_eq!(event.provider, "Microsoft-Windows-Security-Auditing");
        assert_eq!(event.computer, "TEST-PC");
        assert_eq!(event.record_id, 12345);
        assert!(event.timestamp.is_some());
    }
}
