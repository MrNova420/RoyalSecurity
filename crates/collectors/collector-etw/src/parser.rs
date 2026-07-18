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

fn parse_kernel_process(event_id: u16, raw_data: &[u8]) -> Result<Option<SecurityEventEnvelope>, Box<dyn std::error::Error + Send + Sync>> {
    let mut details = HashMap::new();

    if raw_data.len() >= 16 {
        let pid = u32::from_le_bytes([raw_data[8], raw_data[9], raw_data[10], raw_data[11]]);
        let ppid = u32::from_le_bytes([raw_data[12], raw_data[13], raw_data[14], raw_data[15]]);
        details.insert("pid".into(), serde_json::json!(pid));
        details.insert("ppid".into(), serde_json::json!(ppid));
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

    let (severity, event_type) = match event_id {
        10 => (EventSeverity::Informational, EventType::FileModified),
        11 => (EventSeverity::Informational, EventType::FileModified),
        12 => (EventSeverity::Informational, EventType::FileCreated),
        13 => (EventSeverity::Informational, EventType::FileDeleted),
        14 => (EventSeverity::Informational, EventType::FileRenamed),
        _ => (EventSeverity::Informational, EventType::FileModified),
    };

    if raw_data.len() > 16 {
        let path_bytes = &raw_data[16..];
        let path = String::from_utf8_lossy(path_bytes)
            .trim_matches('\0')
            .to_string();
        if !path.is_empty() {
            details.insert("file_path".into(), serde_json::json!(path));
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

    if raw_data.len() >= 24 {
        let pid = u32::from_le_bytes([raw_data[8], raw_data[9], raw_data[10], raw_data[11]]);
        let size = u32::from_le_bytes([raw_data[12], raw_data[13], raw_data[14], raw_data[15]]);
        let daddr = u32::from_le_bytes([raw_data[16], raw_data[17], raw_data[18], raw_data[19]]);
        let saddr = u32::from_le_bytes([raw_data[20], raw_data[21], raw_data[22], raw_data[23]]);

        details.insert("pid".into(), serde_json::json!(pid));
        details.insert("size".into(), serde_json::json!(size));
        details.insert("src_ip".into(), serde_json::json!(format!("{}.{}.{}.{}",
            saddr & 0xff, (saddr >> 8) & 0xff, (saddr >> 16) & 0xff, (saddr >> 24) & 0xff)));
        details.insert("dst_ip".into(), serde_json::json!(format!("{}.{}.{}.{}",
            daddr & 0xff, (daddr >> 8) & 0xff, (daddr >> 16) & 0xff, (daddr >> 24) & 0xff)));
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
    let details = HashMap::new();

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
