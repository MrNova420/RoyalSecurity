use royalsecurity_common::types::SecurityEventEnvelope;
use std::io::Write;

use crate::ecs::EcsNdjsonFormatter;
use crate::cef::CefFormatter;
use crate::syslog::SyslogFormatter;
use crate::json::JsonFormatter;
use crate::csv::CsvFormatter;
use crate::splunk::SplunkHecFormatter;

#[derive(Clone, Debug)]
pub enum ExportFormat {
    EcsNdjson,
    Cef,
    Syslog,
    Json { pretty: bool },
    Csv { all_fields: bool },
    SplunkHec,
}

#[derive(Clone, Debug)]
pub enum Destination {
    File { path: String, max_size_bytes: u64, max_files: usize },
    Stdout,
    Http { url: String, token: Option<String>, batch_size: usize },
}

#[derive(Clone, Debug)]
pub struct ExporterConfig {
    pub format: ExportFormat,
    pub destination: Destination,
    pub buffer_size: usize,
    pub flush_interval_ms: u64,
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            format: ExportFormat::EcsNdjson,
            destination: Destination::Stdout,
            buffer_size: 1024,
            flush_interval_ms: 1000,
        }
    }
}

pub struct Exporter {
    config: ExporterConfig,
    buffer: Vec<SecurityEventEnvelope>,
    file_rotation: Option<FileRotationState>,
}

struct FileRotationState {
    current_path: String,
    current_size: u64,
    current_index: usize,
}

impl Exporter {
    pub fn new(config: ExporterConfig) -> Self {
        Self {
            config,
            buffer: Vec::new(),
            file_rotation: None,
        }
    }

    pub async fn send(&mut self, event: SecurityEventEnvelope) -> std::io::Result<()> {
        self.buffer.push(event);
        if self.buffer.len() >= self.config.buffer_size {
            self.flush().await?;
        }
        Ok(())
    }

    pub async fn flush(&mut self) -> std::io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let events: Vec<SecurityEventEnvelope> = self.buffer.drain(..).collect();
        let dest = self.config.destination.clone();
        match &dest {
            Destination::Stdout => {
                let mut stdout = std::io::stdout();
                self.write_events(&events, &mut stdout)?;
            }
            Destination::File { path, max_size_bytes, max_files } => {
                self.write_to_file(&events, path, *max_size_bytes, *max_files)?;
            }
            Destination::Http { url, token, batch_size } => {
                self.send_to_http(&events, url, token.as_deref(), *batch_size).await?;
            }
        }
        Ok(())
    }

    fn write_events<W: Write>(&self, events: &[SecurityEventEnvelope], writer: &mut W) -> std::io::Result<usize> {
        match &self.config.format {
            ExportFormat::EcsNdjson => {
                let fmt = EcsNdjsonFormatter::new();
                fmt.format_batch(events, writer)
            }
            ExportFormat::Cef => {
                let fmt = CefFormatter::new();
                fmt.format_batch(events, writer)
            }
            ExportFormat::Syslog => {
                let fmt = SyslogFormatter::new();
                fmt.format_batch(events, writer)
            }
            ExportFormat::Json { pretty } => {
                let fmt = if *pretty { JsonFormatter::pretty() } else { JsonFormatter::compact() };
                fmt.format_batch(events, writer)
            }
            ExportFormat::Csv { all_fields } => {
                let fmt = if *all_fields { CsvFormatter::all_fields() } else { CsvFormatter::new() };
                fmt.format_batch(events, writer)
            }
            ExportFormat::SplunkHec => {
                let fmt = SplunkHecFormatter::new();
                fmt.format_batch(events, writer)
            }
        }
    }

    fn write_to_file(
        &mut self,
        events: &[SecurityEventEnvelope],
        base_path: &str,
        max_size: u64,
        max_files: usize,
    ) -> std::io::Result<()> {
        let estimated_size: usize = events.iter().map(|e| estimate_event_size(e)).sum();

        let needs_rotate = match &self.file_rotation {
            Some(state) => state.current_size + estimated_size as u64 > max_size,
            None => false,
        };

        if needs_rotate {
            if let Some(ref mut state) = self.file_rotation {
                rotate_file(state, base_path, max_files)?;
            }
        }

        if self.file_rotation.is_none() {
            self.file_rotation = Some(FileRotationState {
                current_path: format!("{}.1", base_path),
                current_size: 0,
                current_index: 1,
            });
        }

        let path = self.file_rotation.as_ref().unwrap().current_path.clone();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        let written = self.write_events(events, &mut file)?;

        if let Some(ref mut state) = self.file_rotation {
            state.current_size += written as u64;
        }

        Ok(())
    }

    async fn send_to_http(
        &self,
        events: &[SecurityEventEnvelope],
        url: &str,
        token: Option<&str>,
        batch_size: usize,
    ) -> std::io::Result<()> {
        let client = reqwest::Client::new();
        for chunk in events.chunks(batch_size) {
            let fmt = SplunkHecFormatter::new();
            let mut body = Vec::new();
            fmt.format_batch(chunk, &mut body)?;

            let mut req = client.post(url)
                .header("Content-Type", "application/json")
                .body(body);

            if let Some(tok) = token {
                req = req.header("Authorization", format!("Splunk {}", tok));
            }

            req.send().await.map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, format!("HTTP send error: {}", e))
            })?;
        }
        Ok(())
    }
}

fn rotate_file(
    state: &mut FileRotationState,
    base_path: &str,
    max_files: usize,
) -> std::io::Result<()> {
    if state.current_index >= max_files {
        let oldest = format!("{}.{}", base_path, max_files);
        let _ = std::fs::remove_file(&oldest);
    }

    for i in (2..=state.current_index).rev() {
        let src = format!("{}.{}", base_path, i);
        let dst = format!("{}.{}", base_path, i + 1);
        let _ = std::fs::rename(&src, &dst);
    }

    let new_path = format!("{}.1", base_path);
    state.current_path = new_path;
    state.current_size = 0;
    state.current_index = std::cmp::min(state.current_index + 1, max_files);

    Ok(())
}

fn estimate_event_size(event: &SecurityEventEnvelope) -> usize {
    200 + event.details.len() * 50 + event.source.len()
}

pub async fn start_exporter(config: ExporterConfig) {
    let mut exporter = Exporter::new(config.clone());

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(
            std::time::Duration::from_millis(config.flush_interval_ms),
        );
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = exporter.flush().await {
                        eprintln!("SIEM export flush error: {}", e);
                    }
                }
            }
        }
    });
}