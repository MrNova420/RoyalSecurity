#[cfg(test)]
mod tests {
    use royalsecurity_common::types::*;
    use royalsecurity_common::prelude::*;
    use crate::ecs::EcsNdjsonFormatter;
    use crate::cef::CefFormatter;
    use crate::syslog::SyslogFormatter;
    use crate::json::JsonFormatter;
    use crate::csv::{CsvFormatter, CsvColumn};
    use crate::splunk::SplunkHecFormatter;
    use std::net::IpAddr;

    fn make_process_event() -> SecurityEventEnvelope {
        SecurityEventEnvelope {
            id: uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            severity: EventSeverity::High,
            event_type: EventType::ProcessCreated,
            timestamp: chrono::DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            source: "test-agent".into(),
            raw: None,
            details: std::collections::HashMap::new(),
            payload: SecurityEvent::Process(ProcessInfo {
                pid: 1234,
                ppid: 567,
                name: "malware.exe".into(),
                path: "C:\\Users\\test\\malware.exe".into(),
                command_line: "malware.exe --inject".into(),
                user: "SYSTEM".into(),
                hash_sha256: Some("abc123".into()),
                integrity_level: Some("High".into()),
                timestamp: chrono::Utc::now(),
            }),
        }
    }

    fn make_network_event() -> SecurityEventEnvelope {
        SecurityEventEnvelope {
            id: uuid::Uuid::parse_str("660e8400-e29b-41d4-a716-446655440001").unwrap(),
            severity: EventSeverity::Critical,
            event_type: EventType::NetworkConnection,
            timestamp: chrono::DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            source: "test-agent".into(),
            raw: None,
            details: std::collections::HashMap::new(),
            payload: SecurityEvent::Network(NetworkEvent {
                src_ip: Some("192.168.1.100".parse::<IpAddr>().unwrap()),
                dst_ip: Some("10.0.0.1".parse::<IpAddr>().unwrap()),
                src_port: 49152,
                dst_port: 443,
                protocol: Protocol::Tcp,
                bytes_in: 1024,
                bytes_out: 512,
                process_name: Some("malware.exe".into()),
                process_pid: Some(1234),
                timestamp: chrono::Utc::now(),
            }),
        }
    }

    fn make_file_event() -> SecurityEventEnvelope {
        SecurityEventEnvelope {
            id: uuid::Uuid::parse_str("770e8400-e29b-41d4-a716-446655440002").unwrap(),
            severity: EventSeverity::Medium,
            event_type: EventType::FileCreated,
            timestamp: chrono::DateTime::parse_from_rfc3339("2025-01-15T10:30:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            source: "test-agent".into(),
            raw: None,
            details: std::collections::HashMap::new(),
            payload: SecurityEvent::File(FileEvent {
                path: "C:\\Windows\\Temp\\payload.dll".into(),
                original_path: None,
                action: FileAction::Created,
                hash_sha256: Some("def456".into()),
                size: Some(4096),
                timestamp: chrono::Utc::now(),
            }),
        }
    }

    #[test]
    fn test_ecs_process_event() {
        let fmt = EcsNdjsonFormatter::new();
        let event = make_process_event();
        let mut output = Vec::new();
        let bytes = fmt.format(&event, &mut output).unwrap();
        assert!(bytes > 0);
        let json: serde_json::Value = serde_json::from_slice(&output.trim_ascii_end()).unwrap();
        assert_eq!(json["event.kind"], "state");
        assert_eq!(json["event.category"], "process");
        assert_eq!(json["process.name"], "malware.exe");
        assert_eq!(json["process.pid"], 1234);
        assert_eq!(json["log.level"], "high");
    }

    #[test]
    fn test_ecs_network_event() {
        let fmt = EcsNdjsonFormatter::new();
        let event = make_network_event();
        let mut output = Vec::new();
        fmt.format(&event, &mut output).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&output.trim_ascii_end()).unwrap();
        assert_eq!(json["event.category"], "network");
        assert_eq!(json["source.ip"], "192.168.1.100");
        assert_eq!(json["destination.ip"], "10.0.0.1");
        assert_eq!(json["event.severity"], 99);
    }

    #[test]
    fn test_ecs_batch_format() {
        let fmt = EcsNdjsonFormatter::new();
        let events = vec![make_process_event(), make_network_event(), make_file_event()];
        let mut output = Vec::new();
        let bytes = fmt.format_batch(&events, &mut output).unwrap();
        assert!(bytes > 0);
        let lines: Vec<&[u8]> = output.split(|&b| b == b'\n').filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn test_cef_process_event() {
        let fmt = CefFormatter::new();
        let event = make_process_event();
        let mut output = Vec::new();
        let bytes = fmt.format(&event, &mut output).unwrap();
        assert!(bytes > 0);
        let line = String::from_utf8(output).unwrap();
        assert!(line.starts_with("CEF:0|RoyalSecurity|RoyalSecurity Agent|0.1.0|1001|Process Created|"));
        assert!(line.contains("cs1=malware.exe"));
        assert!(line.contains("cs1Label=process.name"));
    }

    #[test]
    fn test_cef_network_event() {
        let fmt = CefFormatter::new();
        let event = make_network_event();
        let mut output = Vec::new();
        fmt.format(&event, &mut output).unwrap();
        let line = String::from_utf8(output).unwrap();
        assert!(line.contains("src=192.168.1.100"));
        assert!(line.contains("dst=10.0.0.1"));
        assert!(line.contains("spt=49152"));
        assert!(line.contains("dpt=443"));
    }

    #[test]
    fn test_cef_file_event() {
        let fmt = CefFormatter::new();
        let event = make_file_event();
        let mut output = Vec::new();
        fmt.format(&event, &mut output).unwrap();
        let line = String::from_utf8(output).unwrap();
        assert!(line.contains("2001|File Created|"));
        assert!(line.contains("cs1=C:\\Windows\\Temp\\payload.dll"));
    }

    #[test]
    fn test_syslog_format() {
        let fmt = SyslogFormatter::with_identity("testhost", "testapp");
        let event = make_process_event();
        let mut output = Vec::new();
        let bytes = fmt.format(&event, &mut output).unwrap();
        assert!(bytes > 0);
        let line = String::from_utf8(output).unwrap();
        assert!(line.starts_with("<"));
        assert!(line.contains("1 "));
        assert!(line.contains(" testhost "));
        assert!(line.contains(" testapp "));
        assert!(line.contains("[royalsecurity@4857"));
        assert!(line.contains("event_type=\"ProcessCreated\""));
    }

    #[test]
    fn test_syslog_severity_mapping() {
        let fmt = SyslogFormatter::with_identity("h", "a");
        let mut event = make_process_event();
        event.severity = EventSeverity::Critical;
        let mut output = Vec::new();
        fmt.format(&event, &mut output).unwrap();
        let line = String::from_utf8(output).unwrap();
        assert!(line.starts_with("<8>"));
    }

    #[test]
    fn test_syslog_batch() {
        let fmt = SyslogFormatter::new();
        let events = vec![make_process_event(), make_network_event()];
        let mut output = Vec::new();
        let bytes = fmt.format_batch(&events, &mut output).unwrap();
        assert!(bytes > 0);
        let s = String::from_utf8_lossy(&output);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_json_compact() {
        let fmt = JsonFormatter::compact();
        let event = make_process_event();
        let mut output = Vec::new();
        let bytes = fmt.format(&event, &mut output).unwrap();
        assert!(bytes > 0);
        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["event_type"], "ProcessCreated");
        assert_eq!(json["severity"], "High");
    }

    #[test]
    fn test_json_pretty() {
        let fmt = JsonFormatter::pretty();
        let event = make_process_event();
        let result = fmt.format_one(&event).unwrap();
        assert!(result.contains('\n'));
        assert!(result.contains("  "));
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["source"], "test-agent");
    }

    #[test]
    fn test_json_format_one() {
        let fmt = JsonFormatter::new();
        let event = make_network_event();
        let result = fmt.format_one(&event).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["event_type"], "NetworkConnection");
    }

    #[test]
    fn test_csv_default_columns() {
        let fmt = CsvFormatter::new();
        let event = make_process_event();
        let mut output = Vec::new();
        let bytes = fmt.format(&event, &mut output).unwrap();
        assert!(bytes > 0);
        let line = String::from_utf8(output).unwrap();
        let fields: Vec<&str> = line.trim().split(',').collect();
        assert_eq!(fields.len(), 6);
        assert!(fields[2].contains("ProcessCreated"));
    }

    #[test]
    fn test_csv_header() {
        let fmt = CsvFormatter::new();
        let mut output = Vec::new();
        let bytes = fmt.format_header(&mut output).unwrap();
        assert!(bytes > 0);
        let header = String::from_utf8(output).unwrap();
        assert!(header.starts_with("timestamp,event_id,event_type,severity,source,message"));
    }

    #[test]
    fn test_csv_all_fields() {
        let fmt = CsvFormatter::all_fields();
        let event = make_network_event();
        let mut output = Vec::new();
        let bytes = fmt.format(&event, &mut output).unwrap();
        assert!(bytes > 0);
        let line = String::from_utf8(output).unwrap();
        let fields: Vec<&str> = line.trim().split(',').collect();
        assert_eq!(fields.len(), 19);
        assert!(line.contains("192.168.1.100"));
        assert!(line.contains("10.0.0.1"));
    }

    #[test]
    fn test_csv_escaping() {
        let fmt = CsvFormatter::new();
        let mut event = make_process_event();
        event.source = "test,agent".into();
        let mut output = Vec::new();
        fmt.format(&event, &mut output).unwrap();
        let line = String::from_utf8(output).unwrap();
        assert!(line.contains("\"test,agent\""));
    }

    #[test]
    fn test_splunk_hec_single() {
        let fmt = SplunkHecFormatter::new();
        let event = make_process_event();
        let mut output = Vec::new();
        let bytes = fmt.format(&event, &mut output).unwrap();
        assert!(bytes > 0);
        let json: serde_json::Value = serde_json::from_slice(&output.trim_ascii_end()).unwrap();
        assert!(json["event"].is_object());
        assert_eq!(json["source"], "royalsecurity:agent");
        assert_eq!(json["sourcetype"], "royalsecurity:security_event");
    }

    #[test]
    fn test_splunk_hec_batch() {
        let fmt = SplunkHecFormatter::new();
        let events = vec![make_process_event(), make_network_event()];
        let mut output = Vec::new();
        let bytes = fmt.format_batch(&events, &mut output).unwrap();
        assert!(bytes > 0);
        let json: serde_json::Value = serde_json::from_slice(&output.trim_ascii_end()).unwrap();
        assert!(json["events"].is_array());
        assert_eq!(json["events"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_splunk_hec_custom_identity() {
        let fmt = SplunkHecFormatter::with_identity("my:source", "my:type", "myhost");
        let event = make_process_event();
        let mut output = Vec::new();
        fmt.format(&event, &mut output).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&output.trim_ascii_end()).unwrap();
        assert_eq!(json["source"], "my:source");
        assert_eq!(json["sourcetype"], "my:type");
        assert_eq!(json["host"], "myhost");
    }
}
