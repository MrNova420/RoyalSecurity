use royalsecurity_common::types::SecurityEventEnvelope;
use std::io::Write;

pub struct JsonFormatter {
    pretty: bool,
}

impl JsonFormatter {
    pub fn new() -> Self {
        Self { pretty: false }
    }

    pub fn pretty() -> Self {
        Self { pretty: true }
    }

    pub fn compact() -> Self {
        Self { pretty: false }
    }

    pub fn format<W: Write>(&self, event: &SecurityEventEnvelope, writer: &mut W) -> std::io::Result<usize> {
        let line = if self.pretty {
            serde_json::to_vec_pretty(event)?
        } else {
            serde_json::to_vec(event)?
        };
        let mut output = line;
        output.push(b'\n');
        let len = output.len();
        writer.write_all(&output)?;
        Ok(len)
    }

    pub fn format_batch<W: Write>(&self, events: &[SecurityEventEnvelope], writer: &mut W) -> std::io::Result<usize> {
        let mut total = 0;
        for event in events {
            total += self.format(event, writer)?;
        }
        Ok(total)
    }

    pub fn format_one(&self, event: &SecurityEventEnvelope) -> std::io::Result<String> {
        if self.pretty {
            serde_json::to_string_pretty(event).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        } else {
            serde_json::to_string(event).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        }
    }
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self::compact()
    }
}