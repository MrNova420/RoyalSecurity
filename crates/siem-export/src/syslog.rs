use royalsecurity_common::types::{SecurityEventEnvelope, EventSeverity};
use std::io::Write;

pub struct SyslogFormatter {
    hostname: String,
    app_name: String,
}

impl SyslogFormatter {
    pub fn new() -> Self {
        Self {
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "unknown".into()),
            app_name: "royalsecurity-agent".into(),
        }
    }

    pub fn with_identity(hostname: &str, app_name: &str) -> Self {
        Self {
            hostname: hostname.to_string(),
            app_name: app_name.to_string(),
        }
    }

    pub fn format<W: Write>(&self, event: &SecurityEventEnvelope, writer: &mut W) -> std::io::Result<usize> {
        let line = self.format_rfc5424(event);
        let bytes = line.as_bytes();
        let len = bytes.len();
        writer.write_all(bytes)?;
        writer.write_all(b"\n")?;
        Ok(len + 1)
    }

    pub fn format_batch<W: Write>(&self, events: &[SecurityEventEnvelope], writer: &mut W) -> std::io::Result<usize> {
        let mut total = 0;
        for event in events {
            total += self.format(event, writer)?;
        }
        Ok(total)
    }

    fn format_rfc5424(&self, event: &SecurityEventEnvelope) -> String {
        let priority = self.calculate_priority(&event.severity);
        let timestamp = event.timestamp.format("%Y-%m-%dT%H:%M:%S%.fZ").to_string();
        let structured_data = format!(
            "[royalsecurity@4857 event_type=\"{}\" event_id=\"{}\" source=\"{}\"]",
            event.event_type,
            event.id,
            event.source,
        );
        let message = serde_json::to_string(event).unwrap_or_default();

        format!(
            "<{}>1 {} {} {} {} {} {}",
            priority,
            timestamp,
            self.hostname,
            self.app_name,
            event.id,
            structured_data,
            message,
        )
    }

    fn calculate_priority(&self, severity: &EventSeverity) -> u8 {
        let facility = 1u8;
        let sev = match severity {
            EventSeverity::Critical => 0,
            EventSeverity::High => 2,
            EventSeverity::Medium => 4,
            EventSeverity::Low => 5,
            EventSeverity::Informational => 6,
        };
        facility * 8 + sev
    }
}

impl Default for SyslogFormatter {
    fn default() -> Self {
        Self::new()
    }
}