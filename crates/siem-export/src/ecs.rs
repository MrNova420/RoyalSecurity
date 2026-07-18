use royalsecurity_common::types::{SecurityEventEnvelope, EventType, EventSeverity, SecurityEvent};
use serde::Serialize;
use std::io::Write;

pub struct EcsNdjsonFormatter;

#[derive(Serialize)]
struct EcsEvent<'a> {
    #[serde(rename = "@timestamp")]
    timestamp: String,
    #[serde(rename = "event.kind")]
    event_kind: &'a str,
    #[serde(rename = "event.category")]
    event_category: &'a str,
    #[serde(rename = "event.outcome")]
    event_outcome: &'a str,
    #[serde(rename = "event.severity")]
    event_severity: u8,
    #[serde(rename = "log.level")]
    log_level: &'a str,
    #[serde(rename = "log.logger")]
    log_logger: &'a str,
    #[serde(rename = "agent.name")]
    agent_name: &'a str,
    #[serde(rename = "agent.version")]
    agent_version: &'a str,
    #[serde(rename = "source.ip", skip_serializing_if = "Option::is_none")]
    source_ip: Option<String>,
    #[serde(rename = "destination.ip", skip_serializing_if = "Option::is_none")]
    destination_ip: Option<String>,
    #[serde(rename = "process.name", skip_serializing_if = "Option::is_none")]
    process_name: Option<&'a str>,
    #[serde(rename = "process.pid", skip_serializing_if = "Option::is_none")]
    process_pid: Option<u32>,
    #[serde(rename = "file.name", skip_serializing_if = "Option::is_none")]
    file_name: Option<String>,
    #[serde(rename = "rule.name", skip_serializing_if = "Option::is_none")]
    rule_name: Option<&'a str>,
    #[serde(rename = "rule.id", skip_serializing_if = "Option::is_none")]
    rule_id: Option<&'a str>,
    #[serde(rename = "rule.category", skip_serializing_if = "Option::is_none")]
    rule_category: Option<&'a str>,
    #[serde(rename = "threat.framework", skip_serializing_if = "Option::is_none")]
    threat_framework: Option<&'a str>,
    #[serde(rename = "threat.technique.id", skip_serializing_if = "Option::is_none")]
    threat_technique_id: Option<&'a str>,
    message: String,
    tags: Vec<&'a str>,
}

impl EcsNdjsonFormatter {
    pub fn new() -> Self {
        Self
    }

    pub fn format<W: Write>(&self, event: &SecurityEventEnvelope, writer: &mut W) -> std::io::Result<usize> {
        let ecs = self.to_ecs(event);
        let mut line = serde_json::to_vec(&ecs)?;
        line.push(b'\n');
        let len = line.len();
        writer.write_all(&line)?;
        Ok(len)
    }

    pub fn format_batch<W: Write>(&self, events: &[SecurityEventEnvelope], writer: &mut W) -> std::io::Result<usize> {
        let mut total = 0;
        for event in events {
            total += self.format(event, writer)?;
        }
        Ok(total)
    }

    fn to_ecs<'a>(&self, event: &'a SecurityEventEnvelope) -> EcsEvent<'a> {
        let ts = event.timestamp.to_rfc3339();
        let (kind, category, outcome) = classify_event_type(&event.event_type);
        let severity_num = severity_to_number(&event.severity);
        let severity_label = severity_to_label(&event.severity);
        let (process_name, process_pid, file_name, src_ip, dst_ip) = extract_fields(&event.payload);
        let techniques = royalsecurity_common::mitre::classify_event_to_technique(&event.event_type);
        let threat_framework = if techniques.is_empty() { None } else { Some("mitre-attack") };
        let threat_technique_id = techniques.first().map(|t| t.id);
        let mut tags = vec![kind];
        if severity_num >= 7 {
            tags.push("critical");
        }
        tags.push(severity_label);
        EcsEvent {
            timestamp: ts,
            event_kind: kind,
            event_category: category,
            event_outcome: outcome,
            event_severity: severity_num,
            log_level: severity_label,
            log_logger: &event.source,
            agent_name: &event.source,
            agent_version: "0.1.0",
            source_ip: src_ip,
            destination_ip: dst_ip,
            process_name,
            process_pid,
            file_name,
            rule_name: None,
            rule_id: None,
            rule_category: None,
            threat_framework,
            threat_technique_id,
            message: event.id.to_string(),
            tags,
        }
    }
}

fn classify_event_type(et: &EventType) -> (&'static str, &'static str, &'static str) {
    match et {
        EventType::ProcessCreated | EventType::ProcessTerminated | EventType::ProcessInjected => {
            ("state", "process", "change")
        }
        EventType::FileCreated | EventType::FileModified | EventType::FileDeleted | EventType::FileRenamed => {
            ("state", "file", "change")
        }
        EventType::RegistryCreated | EventType::RegistryModified | EventType::RegistryDeleted => {
            ("state", "registry", "change")
        }
        EventType::NetworkConnection | EventType::NetworkListen => ("state", "network", "start"),
        EventType::DnsQuery | EventType::DnsResponse => ("state", "network", "success"),
        EventType::AuthSuccess => ("info", "authentication", "success"),
        EventType::AuthFailure => ("info", "authentication", "failure"),
        EventType::PrivilegeEscalation | EventType::PrivilegeDeactivation => ("info", "iam", "change"),
        EventType::LateralMovement => ("info", "network", "start"),
        EventType::PersistenceInstalled | EventType::PersistenceRemoved => ("state", "host", "change"),
        EventType::DriverLoaded | EventType::DriverUnloaded => ("state", "driver", "change"),
        EventType::ServiceCreated | EventType::ServiceStarted | EventType::ServiceStopped => {
            ("state", "host", "change")
        }
        EventType::ScheduledTaskCreated
        | EventType::ScheduledTaskModified
        | EventType::ScheduledTaskDeleted => ("state", "host", "change"),
        EventType::WmiEvent => ("state", "host", "change"),
        EventType::NamedPipeCreated | EventType::NamedPipeConnected => ("state", "network", "start"),
        EventType::MemoryAllocation | EventType::MemoryProtection => ("state", "process", "change"),
        EventType::ThreadCreated | EventType::ThreadRemote => ("state", "process", "change"),
        EventType::ModuleLoaded => ("state", "library", "start"),
        EventType::HandleOpened | EventType::ClipboardAccess | EventType::PrintSpool => {
            ("info", "process", "info")
        }
        EventType::UsbDeviceConnected | EventType::UsbDeviceDisconnected => ("state", "host", "change"),
        EventType::BluetoothDeviceConnected => ("state", "host", "change"),
        EventType::WifiConnected | EventType::WifiDisconnected => ("state", "network", "change"),
        EventType::FirmwareUpdated | EventType::BootIntegrityChanged => ("info", "host", "change"),
        EventType::PolicyChanged => ("info", "iam", "change"),
        EventType::ComplianceViolation => ("alert", "configuration", "failure"),
        EventType::ThreatDetected => ("alert", "threat", "outcome"),
        EventType::AnomalyDetected => ("alert", "anomaly", "outcome"),
        EventType::AlertTriggered | EventType::IncidentCreated => ("alert", "security", "outcome"),
    }
}

fn severity_to_number(s: &EventSeverity) -> u8 {
    match s {
        EventSeverity::Critical => 99,
        EventSeverity::High => 75,
        EventSeverity::Medium => 50,
        EventSeverity::Low => 25,
        EventSeverity::Informational => 10,
    }
}

fn severity_to_label(s: &EventSeverity) -> &'static str {
    match s {
        EventSeverity::Critical => "critical",
        EventSeverity::High => "high",
        EventSeverity::Medium => "medium",
        EventSeverity::Low => "low",
        EventSeverity::Informational => "informational",
    }
}

fn extract_fields(
    payload: &SecurityEvent,
) -> (
    Option<&str>,
    Option<u32>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    match payload {
        SecurityEvent::Process(p) => (Some(&p.name), Some(p.pid), None, None, None),
        SecurityEvent::File(f) => {
            let fname = f.path.rsplit(['\\', '/']).next().map(|s| s.to_string());
            (None, None, fname, None, None)
        }
        SecurityEvent::Network(n) => {
            let src = n.src_ip.map(|i| i.to_string());
            let dst = n.dst_ip.map(|i| i.to_string());
            (n.process_name.as_deref(), n.process_pid, None, src, dst)
        }
        SecurityEvent::Dns(d) => (Some(&d.query), None, None, None, None),
        SecurityEvent::Registry(r) => {
            let kname = r.key_path.rsplit(['\\', '/']).next().map(|s| s.to_string());
            (None, None, kname, None, None)
        }
        SecurityEvent::Service(s) => (Some(&s.name), None, None, None, None),
        SecurityEvent::Memory(m) => (None, Some(m.process_id), None, None, None),
        SecurityEvent::Thread(t) => (None, Some(t.process_id), None, None, None),
    }
}