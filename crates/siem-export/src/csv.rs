use royalsecurity_common::types::SecurityEventEnvelope;
use std::io::Write;

pub struct CsvFormatter {
    columns: Vec<CsvColumn>,
    include_header: bool,
}

#[derive(Clone, Debug)]
pub enum CsvColumn {
    Timestamp,
    EventId,
    EventType,
    Severity,
    Source,
    Message,
    ProcessName,
    ProcessPid,
    FilePath,
    FileAction,
    SrcIp,
    DstIp,
    SrcPort,
    DstPort,
    Protocol,
    DnsQuery,
    RegistryKey,
    ServiceName,
    MitreTechnique,
}

impl CsvColumn {
    pub fn header(&self) -> &'static str {
        match self {
            CsvColumn::Timestamp => "timestamp",
            CsvColumn::EventId => "event_id",
            CsvColumn::EventType => "event_type",
            CsvColumn::Severity => "severity",
            CsvColumn::Source => "source",
            CsvColumn::Message => "message",
            CsvColumn::ProcessName => "process_name",
            CsvColumn::ProcessPid => "process_pid",
            CsvColumn::FilePath => "file_path",
            CsvColumn::FileAction => "file_action",
            CsvColumn::SrcIp => "src_ip",
            CsvColumn::DstIp => "dst_ip",
            CsvColumn::SrcPort => "src_port",
            CsvColumn::DstPort => "dst_port",
            CsvColumn::Protocol => "protocol",
            CsvColumn::DnsQuery => "dns_query",
            CsvColumn::RegistryKey => "registry_key",
            CsvColumn::ServiceName => "service_name",
            CsvColumn::MitreTechnique => "mitre_technique",
        }
    }

    pub fn default_columns() -> Vec<CsvColumn> {
        vec![
            CsvColumn::Timestamp,
            CsvColumn::EventId,
            CsvColumn::EventType,
            CsvColumn::Severity,
            CsvColumn::Source,
            CsvColumn::Message,
        ]
    }

    pub fn all_columns() -> Vec<CsvColumn> {
        vec![
            CsvColumn::Timestamp,
            CsvColumn::EventId,
            CsvColumn::EventType,
            CsvColumn::Severity,
            CsvColumn::Source,
            CsvColumn::Message,
            CsvColumn::ProcessName,
            CsvColumn::ProcessPid,
            CsvColumn::FilePath,
            CsvColumn::FileAction,
            CsvColumn::SrcIp,
            CsvColumn::DstIp,
            CsvColumn::SrcPort,
            CsvColumn::DstPort,
            CsvColumn::Protocol,
            CsvColumn::DnsQuery,
            CsvColumn::RegistryKey,
            CsvColumn::ServiceName,
            CsvColumn::MitreTechnique,
        ]
    }
}

impl CsvFormatter {
    pub fn new() -> Self {
        Self {
            columns: CsvColumn::default_columns(),
            include_header: true,
        }
    }

    pub fn with_columns(columns: Vec<CsvColumn>) -> Self {
        Self {
            columns,
            include_header: true,
        }
    }

    pub fn all_fields() -> Self {
        Self {
            columns: CsvColumn::all_columns(),
            include_header: true,
        }
    }

    pub fn no_header(mut self) -> Self {
        self.include_header = false;
        self
    }

    pub fn format<W: Write>(&self, event: &SecurityEventEnvelope, writer: &mut W) -> std::io::Result<usize> {
        let line = self.format_line(event);
        let bytes = line.as_bytes();
        let len = bytes.len();
        writer.write_all(bytes)?;
        writer.write_all(b"\n")?;
        Ok(len + 1)
    }

    pub fn format_header<W: Write>(&self, writer: &mut W) -> std::io::Result<usize> {
        if !self.include_header {
            return Ok(0);
        }
        let headers: Vec<&str> = self.columns.iter().map(|c| c.header()).collect();
        let line = csv_join(&headers);
        let bytes = line.as_bytes();
        let len = bytes.len();
        writer.write_all(bytes)?;
        writer.write_all(b"\n")?;
        Ok(len + 1)
    }

    pub fn format_batch<W: Write>(&self, events: &[SecurityEventEnvelope], writer: &mut W) -> std::io::Result<usize> {
        let mut total = self.format_header(writer)?;
        for event in events {
            total += self.format(event, writer)?;
        }
        Ok(total)
    }

    fn format_line(&self, event: &SecurityEventEnvelope) -> String {
        let values: Vec<String> = self
            .columns
            .iter()
            .map(|col| extract_value(event, col))
            .collect();
        let refs: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
        csv_join(&refs)
    }
}

impl Default for CsvFormatter {
    fn default() -> Self {
        Self::new()
    }
}

fn csv_join(fields: &[&str]) -> String {
    let escaped: Vec<String> = fields
        .iter()
        .map(|f| csv_escape(f))
        .collect();
    escaped.join(",")
}

fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        let escaped = field.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        field.to_string()
    }
}

fn extract_value(event: &SecurityEventEnvelope, col: &CsvColumn) -> String {
    use royalsecurity_common::types::SecurityEvent;
    match col {
        CsvColumn::Timestamp => event.timestamp.to_rfc3339(),
        CsvColumn::EventId => event.id.to_string(),
        CsvColumn::EventType => event.event_type.to_string(),
        CsvColumn::Severity => event.severity.to_string(),
        CsvColumn::Source => event.source.clone(),
        CsvColumn::Message => event.id.to_string(),
        CsvColumn::ProcessName => match &event.payload {
            SecurityEvent::Process(p) => p.name.clone(),
            _ => String::new(),
        },
        CsvColumn::ProcessPid => match &event.payload {
            SecurityEvent::Process(p) => p.pid.to_string(),
            _ => String::new(),
        },
        CsvColumn::FilePath => match &event.payload {
            SecurityEvent::File(f) => f.path.clone(),
            _ => String::new(),
        },
        CsvColumn::FileAction => match &event.payload {
            SecurityEvent::File(f) => f.action.to_string(),
            _ => String::new(),
        },
        CsvColumn::SrcIp => match &event.payload {
            SecurityEvent::Network(n) => n.src_ip.map(|i| i.to_string()).unwrap_or_default(),
            _ => String::new(),
        },
        CsvColumn::DstIp => match &event.payload {
            SecurityEvent::Network(n) => n.dst_ip.map(|i| i.to_string()).unwrap_or_default(),
            _ => String::new(),
        },
        CsvColumn::SrcPort => match &event.payload {
            SecurityEvent::Network(n) => n.src_port.to_string(),
            _ => String::new(),
        },
        CsvColumn::DstPort => match &event.payload {
            SecurityEvent::Network(n) => n.dst_port.to_string(),
            _ => String::new(),
        },
        CsvColumn::Protocol => match &event.payload {
            SecurityEvent::Network(n) => n.protocol.to_string(),
            _ => String::new(),
        },
        CsvColumn::DnsQuery => match &event.payload {
            SecurityEvent::Dns(d) => d.query.clone(),
            _ => String::new(),
        },
        CsvColumn::RegistryKey => match &event.payload {
            SecurityEvent::Registry(r) => r.key_path.clone(),
            _ => String::new(),
        },
        CsvColumn::ServiceName => match &event.payload {
            SecurityEvent::Service(s) => s.name.clone(),
            _ => String::new(),
        },
        CsvColumn::MitreTechnique => {
            let techniques = royalsecurity_common::mitre::classify_event_to_technique(&event.event_type);
            techniques
                .iter()
                .map(|t| t.id)
                .collect::<Vec<_>>()
                .join(";")
        }
    }
}