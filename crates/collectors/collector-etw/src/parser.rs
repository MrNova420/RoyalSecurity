use royalsecurity_common::types::*;
use std::collections::HashMap;


pub fn parse_etw_event(raw_data: &[u8]) -> Result<Option<SecurityEventEnvelope>, Box<dyn std::error::Error + Send + Sync>> {
    if raw_data.len() < 8 {
        return Ok(None);
    }

    let event_id = u16::from_le_bytes([raw_data[0], raw_data[1]]);
    let _version = raw_data[2];
    let channel = raw_data[3];

    match channel {
        0x01 => parse_kernel_process(event_id, raw_data),
        0x02 => parse_kernel_fileio(event_id, raw_data),
        0x03 => parse_kernel_network(event_id, raw_data),
        0x04 => parse_kernel_registry(event_id, raw_data),
        0x05 => parse_security_event(event_id, raw_data),
        0x06 => parse_powershell_event(event_id, raw_data),
        _ => {
            Ok(Some(SecurityEventEnvelope {
                severity: EventSeverity::Informational,
                event_type: EventType::ProcessCreated,
                source: "etw-unknown".into(),
                raw: Some(hex::encode(raw_data)),
                ..SecurityEventEnvelope::default()
            }))
        }
    }
}

fn extract_utf16_string(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let bytes = &data[offset..];
    let mut chars = Vec::new();
    for chunk in bytes.chunks(2) {
        if chunk.len() < 2 { break; }
        let c = u16::from_le_bytes([chunk[0], chunk[1]]);
        if c == 0 { break; }
        chars.push(c);
    }
    String::from_utf16_lossy(&chars).to_string()
}

fn parse_kernel_process(event_id: u16, raw_data: &[u8]) -> Result<Option<SecurityEventEnvelope>, Box<dyn std::error::Error + Send + Sync>> {
    let mut details = HashMap::new();

    if raw_data.len() >= 16 {
        let pid = u32::from_le_bytes([raw_data[8], raw_data[9], raw_data[10], raw_data[11]]);
        let ppid = u32::from_le_bytes([raw_data[12], raw_data[13], raw_data[14], raw_data[15]]);
        details.insert("pid".into(), serde_json::json!(pid));
        details.insert("ppid".into(), serde_json::json!(ppid));

        if raw_data.len() > 16 {
            let name = extract_utf16_string(raw_data, 16);
            if !name.is_empty() {
                details.insert("process_name".into(), serde_json::json!(name));
            }
        }
    }

    let (severity, event_type) = match event_id {
        1 => (EventSeverity::Informational, EventType::ProcessCreated),
        2 => (EventSeverity::Informational, EventType::ProcessTerminated),
        _ => (EventSeverity::Informational, EventType::ProcessCreated),
    };

    Ok(Some(SecurityEventEnvelope {
        severity,
        event_type,
        source: "etw-kernel-process".into(),
        raw: Some(hex::encode(raw_data)),
        details,
        ..SecurityEventEnvelope::default()
    }))
}

fn parse_kernel_fileio(event_id: u16, raw_data: &[u8]) -> Result<Option<SecurityEventEnvelope>, Box<dyn std::error::Error + Send + Sync>> {
    let mut details = HashMap::new();

    if raw_data.len() >= 16 {
        let pid = u32::from_le_bytes([raw_data[8], raw_data[9], raw_data[10], raw_data[11]]);
        details.insert("pid".into(), serde_json::json!(pid));
    }

    let (severity, event_type) = match event_id {
        10 => (EventSeverity::Informational, EventType::FileModified),
        11 => (EventSeverity::Informational, EventType::FileModified),
        12 => (EventSeverity::Informational, EventType::FileCreated),
        13 => (EventSeverity::Informational, EventType::FileDeleted),
        14 => (EventSeverity::Informational, EventType::FileRenamed),
        _ => (EventSeverity::Informational, EventType::FileModified),
    };

    if raw_data.len() > 16 {
        let path = extract_utf16_string(raw_data, 16);
        if !path.is_empty() {
            details.insert("file_path".into(), serde_json::json!(path.clone()));
            let path_lower = path.to_lowercase();
            if path_lower.starts_with("c:\\windows\\system32\\config\\")
                || path_lower.contains("\\drivers\\etc\\")
                || path_lower.contains("\\spool\\drivers\\")
                || path_lower.ends_with(".exe")
                || path_lower.ends_with(".dll")
                || path_lower.ends_with(".sys")
                || path_lower.ends_with(".ps1")
                || path_lower.ends_with(".bat")
                || path_lower.ends_with(".cmd")
                || path_lower.ends_with(".vbs")
                || path_lower.ends_with(".js")
            {
                details.insert("suspicious_path".into(), serde_json::json!(true));
            }
        }
    }

    Ok(Some(SecurityEventEnvelope {
        severity,
        event_type,
        source: "etw-kernel-fileio".into(),
        raw: Some(hex::encode(raw_data)),
        details,
        ..SecurityEventEnvelope::default()
    }))
}

fn parse_kernel_network(event_id: u16, raw_data: &[u8]) -> Result<Option<SecurityEventEnvelope>, Box<dyn std::error::Error + Send + Sync>> {
    let mut details = HashMap::new();

    if raw_data.len() >= 32 {
        let pid = u32::from_le_bytes([raw_data[8], raw_data[9], raw_data[10], raw_data[11]]);
        let size = u32::from_le_bytes([raw_data[12], raw_data[13], raw_data[14], raw_data[15]]);
        let daddr = u32::from_le_bytes([raw_data[16], raw_data[17], raw_data[18], raw_data[19]]);
        let saddr = u32::from_le_bytes([raw_data[20], raw_data[21], raw_data[22], raw_data[23]]);
        let dport = u16::from_le_bytes([raw_data[24], raw_data[25]]);
        let sport = u16::from_le_bytes([raw_data[26], raw_data[27]]);

        details.insert("pid".into(), serde_json::json!(pid));
        details.insert("size".into(), serde_json::json!(size));
        details.insert("src_ip".into(), serde_json::json!(format!("{}.{}.{}.{}",
            saddr & 0xff, (saddr >> 8) & 0xff, (saddr >> 16) & 0xff, (saddr >> 24) & 0xff)));
        details.insert("dst_ip".into(), serde_json::json!(format!("{}.{}.{}.{}",
            daddr & 0xff, (daddr >> 8) & 0xff, (daddr >> 16) & 0xff, (daddr >> 24) & 0xff)));
        details.insert("src_port".into(), serde_json::json!(sport));
        details.insert("dst_port".into(), serde_json::json!(dport));

        if dport == 445 || dport == 135 || dport == 139 || dport == 5985 || dport == 5986 || dport == 4444 || dport == 5555 || dport == 6667 || dport == 8443 {
            details.insert("suspicious_port".into(), serde_json::json!(true));
        }
    }

    let (severity, event_type) = match event_id {
        10..=15 => (EventSeverity::Informational, EventType::NetworkConnection),
        _ => (EventSeverity::Informational, EventType::NetworkConnection),
    };

    Ok(Some(SecurityEventEnvelope {
        severity,
        event_type,
        source: "etw-kernel-network".into(),
        raw: Some(hex::encode(raw_data)),
        details,
        ..SecurityEventEnvelope::default()
    }))
}

fn parse_kernel_registry(event_id: u16, raw_data: &[u8]) -> Result<Option<SecurityEventEnvelope>, Box<dyn std::error::Error + Send + Sync>> {
    let mut details = HashMap::new();

    if raw_data.len() >= 16 {
        let pid = u32::from_le_bytes([raw_data[8], raw_data[9], raw_data[10], raw_data[11]]);
        details.insert("pid".into(), serde_json::json!(pid));

        if raw_data.len() > 16 {
            let key_name = extract_utf16_string(raw_data, 16);
            if !key_name.is_empty() {
                details.insert("key_path".into(), serde_json::json!(key_name.clone()));
                let key_lower = key_name.to_lowercase();
                if key_lower.contains("\\currentversion\\run")
                    || key_lower.contains("\\currentversion\\runonce")
                    || key_lower.contains("\\winlogon\\")
                    || key_lower.contains("\\policies\\explorer\\run")
                    || key_lower.contains("\\windows nt\\currentversion\\image file execution")
                    || key_lower.contains("\\appinit_dlls")
                    || key_lower.contains("\\session manager\\bootexec")
                    || key_lower.contains("\\lsa\\")
                {
                    details.insert("suspicious_key".into(), serde_json::json!(true));
                }
            }
        }
    }

    let (severity, event_type) = match event_id {
        10 => (EventSeverity::Informational, EventType::RegistryCreated),
        11 => (EventSeverity::Medium, EventType::RegistryDeleted),
        12 => (EventSeverity::Medium, EventType::RegistryModified),
        13 => (EventSeverity::Medium, EventType::RegistryDeleted),
        14 => (EventSeverity::Informational, EventType::RegistryModified),
        15 => (EventSeverity::Informational, EventType::RegistryModified),
        _ => (EventSeverity::Informational, EventType::RegistryModified),
    };

    Ok(Some(SecurityEventEnvelope {
        severity,
        event_type,
        source: "etw-kernel-registry".into(),
        raw: Some(hex::encode(raw_data)),
        details,
        ..SecurityEventEnvelope::default()
    }))
}

fn parse_security_event(event_id: u16, raw_data: &[u8]) -> Result<Option<SecurityEventEnvelope>, Box<dyn std::error::Error + Send + Sync>> {
    let mut details = HashMap::new();
    details.insert("event_id".into(), serde_json::json!(event_id));

    let (severity, event_type) = match event_id {
        4624 => (EventSeverity::Informational, EventType::AuthSuccess),
        4625 => (EventSeverity::High, EventType::AuthFailure),
        4672 => (EventSeverity::High, EventType::PrivilegeEscalation),
        4688 => (EventSeverity::Informational, EventType::ProcessCreated),
        4720 => (EventSeverity::Medium, EventType::ServiceCreated),
        4732 => (EventSeverity::High, EventType::LateralMovement),
        4697 => (EventSeverity::High, EventType::ServiceCreated),
        4698 => (EventSeverity::Medium, EventType::ScheduledTaskCreated),
        4702 => (EventSeverity::Medium, EventType::ScheduledTaskModified),
        4776 => (EventSeverity::High, EventType::AuthSuccess),
        4778 => (EventSeverity::Medium, EventType::NetworkConnection),
        _ => (EventSeverity::Informational, EventType::ProcessCreated),
    };

    Ok(Some(SecurityEventEnvelope {
        severity,
        event_type,
        source: "etw-security".into(),
        raw: Some(hex::encode(raw_data)),
        details,
        ..SecurityEventEnvelope::default()
    }))
}

fn parse_powershell_event(event_id: u16, raw_data: &[u8]) -> Result<Option<SecurityEventEnvelope>, Box<dyn std::error::Error + Send + Sync>> {
    let mut details = HashMap::new();
    details.insert("event_id".into(), serde_json::json!(event_id));

    let severity = match event_id {
        4103 => EventSeverity::Medium,
        4104 => EventSeverity::High,
        4105 => EventSeverity::Informational,
        4106 => EventSeverity::Medium,
        _ => EventSeverity::Informational,
    };

    Ok(Some(SecurityEventEnvelope {
        severity,
        event_type: EventType::ProcessCreated,
        source: "etw-powershell".into(),
        raw: Some(hex::encode(raw_data)),
        details,
        ..SecurityEventEnvelope::default()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_utf16_string() {
        let data = b"h\0e\0l\0l\0o\0\0\0";
        assert_eq!(extract_utf16_string(data, 0), "hello");
    }

    #[test]
    fn test_extract_utf16_empty() {
        let data = b"\0\0";
        assert_eq!(extract_utf16_string(data, 0), "");
    }

    #[test]
    fn test_parse_kernel_process_start() {
        let mut data = vec![0u8; 64];
        data[0] = 1;
        data[3] = 0x01;
        data[8..12].copy_from_slice(&100u32.to_le_bytes());
        data[12..16].copy_from_slice(&1u32.to_le_bytes());
        let name = "test.exe\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>();
        data[16..16+name.len()].copy_from_slice(&name);
        let result = parse_kernel_process(1, &data).unwrap();
        assert!(result.is_some());
        let env = result.unwrap();
        assert_eq!(env.event_type, EventType::ProcessCreated);
        assert!(env.details.contains_key("pid"));
        assert!(env.details.contains_key("process_name"));
    }

    #[test]
    fn test_parse_kernel_process_terminate() {
        let mut data = vec![0u8; 32];
        data[0] = 2;
        data[3] = 0x01;
        let result = parse_kernel_process(2, &data).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().event_type, EventType::ProcessTerminated);
    }

    #[test]
    fn test_parse_kernel_fileio_write() {
        let mut data = vec![0u8; 64];
        data[0] = 10;
        data[3] = 0x02;
        let result = parse_kernel_fileio(10, &data).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().event_type, EventType::FileModified);
    }

    #[test]
    fn test_parse_kernel_fileio_with_path() {
        let mut data = vec![0u8; 128];
        data[0] = 12;
        data[3] = 0x02;
        let path = "C:\\test.txt\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>();
        data[16..16+path.len()].copy_from_slice(&path);
        let result = parse_kernel_fileio(12, &data).unwrap();
        assert!(result.is_some());
        let env = result.unwrap();
        assert_eq!(env.event_type, EventType::FileCreated);
        assert!(env.details.contains_key("file_path"));
    }

    #[test]
    fn test_parse_kernel_network() {
        let mut data = vec![0u8; 32];
        data[0] = 10;
        data[3] = 0x03;
        data[8..12].copy_from_slice(&42u32.to_le_bytes());
        data[24..26].copy_from_slice(&443u16.to_le_bytes());
        data[26..28].copy_from_slice(&12345u16.to_le_bytes());
        let result = parse_kernel_network(10, &data).unwrap();
        assert!(result.is_some());
        let env = result.unwrap();
        assert!(env.details.contains_key("dst_port"));
    }

    #[test]
    fn test_parse_kernel_network_suspicious_port() {
        let mut data = vec![0u8; 32];
        data[0] = 10;
        data[3] = 0x03;
        data[24..26].copy_from_slice(&4444u16.to_le_bytes());
        let result = parse_kernel_network(10, &data).unwrap();
        assert!(result.unwrap().details.contains_key("suspicious_port"));
    }

    #[test]
    fn test_parse_security_auth_failure() {
        let mut data = vec![0u8; 32];
        data[3] = 0x05;
        let result = parse_security_event(4625, &data).unwrap();
        assert!(result.is_some());
        let env = result.unwrap();
        assert_eq!(env.severity, EventSeverity::High);
        assert_eq!(env.event_type, EventType::AuthFailure);
    }

    #[test]
    fn test_parse_powershell_script_block() {
        let mut data = vec![0u8; 32];
        data[3] = 0x06;
        let result = parse_powershell_event(4104, &data).unwrap();
        assert!(result.is_some());
        let env = result.unwrap();
        assert_eq!(env.severity, EventSeverity::High);
    }

    #[test]
    fn test_parse_short_data() {
        let result = parse_etw_event(&[0, 1]).unwrap();
        assert!(result.is_none());
    }
}
