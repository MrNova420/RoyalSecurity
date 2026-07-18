use royalsecurity_common::types::{
    SecurityEventEnvelope, EventType, EventSeverity, SecurityEvent,
};
use std::io::Write;

pub struct CefFormatter;

impl CefFormatter {
    pub fn new() -> Self {
        Self
    }

    pub fn format<W: Write>(&self, event: &SecurityEventEnvelope, writer: &mut W) -> std::io::Result<usize> {
        let line = self.format_line(event);
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

    fn format_line(&self, event: &SecurityEventEnvelope) -> String {
        let (sig_id, name) = event_type_to_sig(&event.event_type);
        let severity = severity_to_cef(&event.severity);
        let extensions = self.build_extensions(event);
        format!(
            "CEF:0|RoyalSecurity|RoyalSecurity Agent|0.1.0|{}|{}|{}|{}",
            sig_id, name, severity, extensions
        )
    }

    fn build_extensions(&self, event: &SecurityEventEnvelope) -> String {
        let mut exts = Vec::new();
        match &event.payload {
            SecurityEvent::Network(n) => {
                if let Some(src) = &n.src_ip {
                    exts.push(format!("src={}", src));
                }
                if let Some(dst) = &n.dst_ip {
                    exts.push(format!("dst={}", dst));
                }
                exts.push(format!("spt={}", n.src_port));
                exts.push(format!("dpt={}", n.dst_port));
                exts.push(format!("app={}", n.protocol));
                exts.push(format!("deviceDirection=0"));
            }
            SecurityEvent::Process(p) => {
                exts.push(format!("cs1={}", p.name));
                exts.push("cs1Label=process.name".into());
                exts.push(format!("cs2={}", p.pid));
                exts.push("cs2Label=process.pid".into());
                exts.push(format!("cs3={}", p.command_line));
                exts.push("cs3Label=process.command_line".into());
                exts.push(format!("cs4={}", p.user));
                exts.push("cs4Label=user.name".into());
            }
            SecurityEvent::File(f) => {
                exts.push(format!("cs1={}", f.path));
                exts.push("cs1Label=file.path".into());
                exts.push(format!("cs2={}", f.action));
                exts.push("cs2Label=file.action".into());
                if let Some(hash) = &f.hash_sha256 {
                    exts.push(format!("cs3={}", hash));
                    exts.push("cs3Label=file.hash.sha256".into());
                }
            }
            SecurityEvent::Dns(d) => {
                exts.push(format!("cs1={}", d.query));
                exts.push("cs1Label=dns.query".into());
                exts.push(format!("cs2={}", d.query_type));
                exts.push("cs2Label=dns.query_type".into());
                if let Some(resp) = &d.response {
                    exts.push(format!("cs3={}", resp));
                    exts.push("cs3Label=dns.response".into());
                }
            }
            SecurityEvent::Registry(r) => {
                exts.push(format!("cs1={}", r.key_path));
                exts.push("cs1Label=registry.key".into());
                exts.push(format!("cs2={}", r.action));
                exts.push("cs2Label=registry.action".into());
                if let Some(val) = &r.value_name {
                    exts.push(format!("cs3={}", val));
                    exts.push("cs3Label=registry.value".into());
                }
            }
            SecurityEvent::Service(s) => {
                exts.push(format!("cs1={}", s.name));
                exts.push("cs1Label=service.name".into());
                exts.push(format!("cs2={}", s.action));
                exts.push("cs2Label=service.action".into());
                exts.push(format!("cs3={}", s.status));
                exts.push("cs3Label=service.status".into());
            }
            SecurityEvent::Memory(m) => {
                exts.push(format!("cs1={:#x}", m.base_address));
                exts.push("cs1Label=memory.base_address".into());
                exts.push(format!("cs2={}", m.region_size));
                exts.push("cs2Label=memory.region_size".into());
                exts.push(format!("cs3={}", m.protection));
                exts.push("cs3Label=memory.protection".into());
            }
            SecurityEvent::Thread(t) => {
                exts.push(format!("cs1={}", t.thread_id));
                exts.push("cs1Label=thread.id".into());
                exts.push(format!("cs2={}", t.action));
                exts.push("cs2Label=thread.action".into());
                exts.push(format!("cs3={:#x}", t.start_address));
                exts.push("cs3Label=thread.start_address".into());
            }
        }

        let techniques = royalsecurity_common::mitre::classify_event_to_technique(&event.event_type);
        if let Some(tech) = techniques.first() {
            exts.push(format!("cs5={}", tech.id));
            exts.push("cs5Label=threat.technique.id".into());
        }

        exts.push(format!("rt={}", event.timestamp.to_rfc3339()));
        exts.join(" ")
    }
}

fn event_type_to_sig(et: &EventType) -> (&'static str, &'static str) {
    match et {
        EventType::ProcessCreated => ("1001", "Process Created"),
        EventType::ProcessTerminated => ("1002", "Process Terminated"),
        EventType::ProcessInjected => ("1003", "Process Injected"),
        EventType::FileCreated => ("2001", "File Created"),
        EventType::FileModified => ("2002", "File Modified"),
        EventType::FileDeleted => ("2003", "File Deleted"),
        EventType::FileRenamed => ("2004", "File Renamed"),
        EventType::RegistryCreated => ("3001", "Registry Key Created"),
        EventType::RegistryModified => ("3002", "Registry Key Modified"),
        EventType::RegistryDeleted => ("3003", "Registry Key Deleted"),
        EventType::NetworkConnection => ("4001", "Network Connection"),
        EventType::NetworkListen => ("4002", "Network Listen"),
        EventType::DnsQuery => ("4003", "DNS Query"),
        EventType::DnsResponse => ("4004", "DNS Response"),
        EventType::AuthSuccess => ("5001", "Authentication Success"),
        EventType::AuthFailure => ("5002", "Authentication Failure"),
        EventType::PrivilegeEscalation => ("5003", "Privilege Escalation"),
        EventType::PrivilegeDeactivation => ("5004", "Privilege Deactivation"),
        EventType::LateralMovement => ("5005", "Lateral Movement"),
        EventType::PersistenceInstalled => ("6001", "Persistence Installed"),
        EventType::PersistenceRemoved => ("6002", "Persistence Removed"),
        EventType::DriverLoaded => ("6003", "Driver Loaded"),
        EventType::DriverUnloaded => ("6004", "Driver Unloaded"),
        EventType::ServiceCreated => ("6005", "Service Created"),
        EventType::ServiceStarted => ("6006", "Service Started"),
        EventType::ServiceStopped => ("6007", "Service Stopped"),
        EventType::ScheduledTaskCreated => ("6008", "Scheduled Task Created"),
        EventType::ScheduledTaskModified => ("6009", "Scheduled Task Modified"),
        EventType::ScheduledTaskDeleted => ("6010", "Scheduled Task Deleted"),
        EventType::WmiEvent => ("6011", "WMI Event"),
        EventType::NamedPipeCreated => ("6012", "Named Pipe Created"),
        EventType::NamedPipeConnected => ("6013", "Named Pipe Connected"),
        EventType::MemoryAllocation => ("7001", "Memory Allocation"),
        EventType::MemoryProtection => ("7002", "Memory Protection Change"),
        EventType::ThreadCreated => ("7003", "Thread Created"),
        EventType::ThreadRemote => ("7004", "Remote Thread Created"),
        EventType::ModuleLoaded => ("7005", "Module Loaded"),
        EventType::HandleOpened => ("7006", "Handle Opened"),
        EventType::ClipboardAccess => ("8001", "Clipboard Access"),
        EventType::PrintSpool => ("8002", "Print Spool Access"),
        EventType::UsbDeviceConnected => ("8003", "USB Device Connected"),
        EventType::UsbDeviceDisconnected => ("8004", "USB Device Disconnected"),
        EventType::BluetoothDeviceConnected => ("8005", "Bluetooth Device Connected"),
        EventType::WifiConnected => ("8006", "WiFi Connected"),
        EventType::WifiDisconnected => ("8007", "WiFi Disconnected"),
        EventType::FirmwareUpdated => ("8008", "Firmware Updated"),
        EventType::BootIntegrityChanged => ("8009", "Boot Integrity Changed"),
        EventType::PolicyChanged => ("9001", "Policy Changed"),
        EventType::ComplianceViolation => ("9002", "Compliance Violation"),
        EventType::ThreatDetected => ("9003", "Threat Detected"),
        EventType::AnomalyDetected => ("9004", "Anomaly Detected"),
        EventType::AlertTriggered => ("9005", "Alert Triggered"),
        EventType::IncidentCreated => ("9006", "Incident Created"),
    }
}

fn severity_to_cef(s: &EventSeverity) -> u8 {
    match s {
        EventSeverity::Critical => 10,
        EventSeverity::High => 7,
        EventSeverity::Medium => 5,
        EventSeverity::Low => 3,
        EventSeverity::Informational => 1,
    }
}