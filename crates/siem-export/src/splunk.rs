use royalsecurity_common::types::SecurityEventEnvelope;
use serde::Serialize;
use std::io::Write;

pub struct SplunkHecFormatter {
    source: String,
    sourcetype: String,
    host: String,
}

#[derive(Serialize)]
struct HecEvent<'a> {
    event: &'a SecurityEventEnvelope,
    source: &'a str,
    sourcetype: &'a str,
    host: &'a str,
}

#[derive(Serialize)]
struct HecBatch<'a> {
    events: Vec<&'a SecurityEventEnvelope>,
    source: &'a str,
    sourcetype: &'a str,
    host: &'a str,
}

impl SplunkHecFormatter {
    pub fn new() -> Self {
        Self {
            source: "royalsecurity:agent".into(),
            sourcetype: "royalsecurity:security_event".into(),
            host: hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "unknown".into()),
        }
    }

    pub fn with_identity(source: &str, sourcetype: &str, host: &str) -> Self {
        Self {
            source: source.into(),
            sourcetype: sourcetype.into(),
            host: host.into(),
        }
    }

    pub fn format<W: Write>(&self, event: &SecurityEventEnvelope, writer: &mut W) -> std::io::Result<usize> {
        let hec = HecEvent {
            event,
            source: &self.source,
            sourcetype: &self.sourcetype,
            host: &self.host,
        };
        let mut line = serde_json::to_vec(&hec)?;
        line.push(b'\n');
        let len = line.len();
        writer.write_all(&line)?;
        Ok(len)
    }

    pub fn format_batch<W: Write>(&self, events: &[SecurityEventEnvelope], writer: &mut W) -> std::io::Result<usize> {
        let refs: Vec<&SecurityEventEnvelope> = events.iter().collect();
        let hec = HecBatch {
            events: refs,
            source: &self.source,
            sourcetype: &self.sourcetype,
            host: &self.host,
        };
        let mut data = serde_json::to_vec(&hec)?;
        data.push(b'\n');
        let len = data.len();
        writer.write_all(&data)?;
        Ok(len)
    }
}

impl Default for SplunkHecFormatter {
    fn default() -> Self {
        Self::new()
    }
}