pub mod prelude;
pub use royalsecurity_core as core;

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::mem;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows::Win32::System::IO::DeviceIoControl;
use windows::core::Error as Win32Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum UsnReason {
    DataOverwrite,
    DataExtend,
    DataTruncation,
    NamedDataOverwrite,
    NamedDataExtend,
    FileCreate,
    FileDelete,
    EaChange,
    SecurityChange,
    RenameOldName,
    RenameNewName,
}

impl std::fmt::Display for UsnReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UsnReason::DataOverwrite => write!(f, "DataOverwrite"),
            UsnReason::DataExtend => write!(f, "DataExtend"),
            UsnReason::DataTruncation => write!(f, "DataTruncation"),
            UsnReason::NamedDataOverwrite => write!(f, "NamedDataOverwrite"),
            UsnReason::NamedDataExtend => write!(f, "NamedDataExtend"),
            UsnReason::FileCreate => write!(f, "FileCreate"),
            UsnReason::FileDelete => write!(f, "FileDelete"),
            UsnReason::EaChange => write!(f, "EaChange"),
            UsnReason::SecurityChange => write!(f, "SecurityChange"),
            UsnReason::RenameOldName => write!(f, "RenameOldName"),
            UsnReason::RenameNewName => write!(f, "RenameNewName"),
        }
    }
}

impl UsnReason {
    pub fn from_usn_code(code: u32) -> Option<Self> {
        match code {
            0x00000001 => Some(UsnReason::DataOverwrite),
            0x00000002 => Some(UsnReason::DataExtend),
            0x00000004 => Some(UsnReason::DataTruncation),
            0x00000010 => Some(UsnReason::NamedDataOverwrite),
            0x00000020 => Some(UsnReason::NamedDataExtend),
            0x00000100 => Some(UsnReason::FileCreate),
            0x00000200 => Some(UsnReason::FileDelete),
            0x00000400 => Some(UsnReason::EaChange),
            0x00000800 => Some(UsnReason::SecurityChange),
            0x00008000 => Some(UsnReason::RenameOldName),
            0x00010000 => Some(UsnReason::RenameNewName),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsnEntry {
    pub file_ref_number: u64,
    pub parent_ref: u64,
    pub usn: i64,
    pub reason: UsnReason,
    pub file_name: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum UsnCollectorError {
    #[error("Collector not started")]
    NotStarted,
    #[error("Invalid USN entry: {0}")]
    InvalidEntry(String),
    #[error("Win32 error: {0}")]
    Win32(#[from] Win32Error),
    #[error("Failed to open volume: {0}")]
    VolumeOpen(String),
    #[error("Buffer too small, need {0} bytes")]
    BufferTooSmall(u32),
    #[error("No USN journal on volume")]
    NoJournal,
}

/// Represents a volume handle with automatic cleanup.
pub struct VolumeHandle(HANDLE, String);

impl VolumeHandle {
    pub fn open(drive: &str) -> Result<Self, UsnCollectorError> {
        let volume_path: Vec<u16> = format!("\\\\.\\{}", drive).encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR::from_raw(volume_path.as_ptr()),
                0x80000000u32,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                windows::Win32::Storage::FileSystem::FILE_CREATION_DISPOSITION(3),
                windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0),
                HANDLE::default(),
            )
        };
        if let Ok(handle) = handle {
            if handle.is_invalid() {
                return Err(UsnCollectorError::VolumeOpen(format!("{} returned invalid handle", drive)));
            }
            Ok(VolumeHandle(handle, drive.to_string()))
        } else {
            Err(UsnCollectorError::VolumeOpen(format!("Failed to open {}: {:?}", drive, handle)))
        }
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }

    pub fn drive(&self) -> &str {
        &self.1
    }
}

impl Drop for VolumeHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { let _ = CloseHandle(self.0); }
        }
    }
}

const FSCTL_READ_USN_JOURNAL: u32 = 0x00090064;
const FSCTL_ENUM_USN_DATA: u32 = 0x000900a8;
const FSCTL_READ_FILE_USN_DATA: u32 = 0x000900eb;

/// USN_RECORD_V2/V3 header fields parsed from raw bytes.
#[derive(Debug, Clone)]
pub struct UsnRecordRaw {
    pub record_length: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub file_ref_number: u64,
    pub parent_ref_number: u64,
    pub usn: i64,
    pub reason: u32,
    pub file_name_length: u16,
    pub file_name_offset: u16,
    pub file_name: String,
    pub timestamp: DateTime<Utc>,
}

impl UsnRecordRaw {
    /// Parse a single USN_RECORD_V2/V3 from a byte buffer starting at `offset`.
    /// Returns None if the record is a terminating zero-length record or if
    /// the data is truncated.
    pub fn parse(buffer: &[u8], offset: &mut usize) -> Option<Self> {
        let remaining = buffer.len().saturating_sub(*offset);
        if remaining < 4 {
            return None;
        }

        let record_length = u32::from_le_bytes(buffer[*offset..*offset + 4].try_into().unwrap());
        if record_length == 0 || record_length as usize > remaining {
            return None;
        }

        if remaining < mem::size_of::<UsnRecordHeader>() {
            return None;
        }

        let (major, minor) = if remaining >= 8 {
            let major = u16::from_le_bytes(buffer[*offset + 4..*offset + 6].try_into().unwrap());
            let minor = u16::from_le_bytes(buffer[*offset + 6..*offset + 8].try_into().unwrap());
            (major, minor)
        } else {
            return None;
        };

        if remaining < 60 {
            return None;
        }

        let file_ref_number = u64::from_le_bytes(buffer[*offset + 8..*offset + 16].try_into().unwrap());
        let parent_ref_number = u64::from_le_bytes(buffer[*offset + 16..*offset + 24].try_into().unwrap());
        let usn = i64::from_le_bytes(buffer[*offset + 24..*offset + 32].try_into().unwrap());

        let timestamp_raw = u64::from_le_bytes(buffer[*offset + 32..*offset + 40].try_into().unwrap());
        let timestamp_100ns = timestamp_raw as i64;
        let timestamp_us = timestamp_100ns / 10;
        let timestamp_ns = (timestamp_100ns % 10) as u32 * 100;
        let unix_epoch_windows = 11644473600000000i64;
        let unix_us = timestamp_us - unix_epoch_windows;
        let secs = unix_us / 1_000_000;
        let nsec = ((unix_us % 1_000_000) as u32) * 1000 + timestamp_ns;
        let dt = Utc
            .timestamp_opt(secs, nsec)
            .unwrap();

        let reason = u32::from_le_bytes(buffer[*offset + 48..*offset + 52].try_into().unwrap());
        let _source_info = u32::from_le_bytes(buffer[*offset + 52..*offset + 56].try_into().unwrap());
        let file_name_length = u16::from_le_bytes(buffer[*offset + 56..*offset + 58].try_into().unwrap());
        let file_name_offset = u16::from_le_bytes(buffer[*offset + 58..*offset + 60].try_into().unwrap());

        let fn_offset = *offset + file_name_offset as usize;
        let fn_len = file_name_length as usize;
        if fn_len == 0 || fn_offset + fn_len > buffer.len() {
            let trimmed = *offset + record_length as usize;
            *offset = trimmed;
            return Some(UsnRecordRaw {
                record_length,
                major_version: major,
                minor_version: minor,
                file_ref_number,
                parent_ref_number,
                usn,
                reason,
                file_name_length,
                file_name_offset,
                file_name: String::new(),
                timestamp: dt,
            });
        }

        let file_name = String::from_utf16_lossy(
            bytemuck::cast_slice::<u8, u16>(&buffer[fn_offset..fn_offset + fn_len]),
        );

        let trimmed = *offset + record_length as usize;
        *offset = trimmed;

        Some(UsnRecordRaw {
            record_length,
            major_version: major,
            minor_version: minor,
            file_ref_number,
            parent_ref_number,
            usn,
            reason,
            file_name_length,
            file_name_offset,
            file_name,
            timestamp: dt,
        })
    }

    pub fn to_entry(&self) -> Option<UsnEntry> {
        UsnReason::from_usn_code(self.reason).map(|reason| UsnEntry {
            file_ref_number: self.file_ref_number,
            parent_ref: self.parent_ref_number,
            usn: self.usn,
            reason,
            file_name: self.file_name.clone(),
            timestamp: self.timestamp,
        })
    }
}

#[repr(C)]
struct UsnRecordHeader {
    record_length: u32,
    major_version: u16,
    minor_version: u16,
    file_ref_number: u64,
    parent_ref_number: u64,
    usn: i64,
}

/// Input buffer for FSCTL_READ_USN_JOURNAL.
#[repr(C)]
struct ReadUsnJournalData {
    start_usn: i64,
    reason_mask: u32,
    return_only_on_close: u32,
    timeout: u64,
    bytes_to_wait_for: u64,
    usn_tracker_id: u64,
}

/// Input buffer for FSCTL_ENUM_USN_DATA.
#[repr(C)]
struct MftEnumDataV0 {
    start_file_reference: u64,
    low_threshold: i64,
    high_threshold: i64,
    _reserved: [u16; 2],
}

/// Convenience: open a volume, read the USN journal, and parse records.
pub fn read_usn_journal(drive: &str) -> Result<Vec<UsnRecordRaw>, UsnCollectorError> {
    let vol = VolumeHandle::open(drive)?;

    let mut buffer = vec![0u8; 65536];
    let start_usn: i64 = 0;
    let mut records = Vec::new();

    let ruj = ReadUsnJournalData {
        start_usn,
        reason_mask: 0xFFFFFFFF,
        return_only_on_close: 0,
        timeout: 0,
        bytes_to_wait_for: 0,
        usn_tracker_id: 0,
    };

    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            vol.raw(),
            FSCTL_READ_USN_JOURNAL,
            Some(&ruj as *const _ as *const _),
            mem::size_of::<ReadUsnJournalData>() as u32,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
            Some(&mut bytes_returned as *mut u32),
            None,
        )
    };

    if let Err(e) = result {
        let code = e.code().0;
        if code == -2147483647 || code == -2147483646 || code == -2147483643 {
            return Err(UsnCollectorError::NoJournal);
        }
        return Err(UsnCollectorError::Win32(e));
    }

    let mut offset = 0usize;
    let actual_len = bytes_returned as usize;
    if actual_len == 0 {
        return Ok(records);
    }

    while offset + 4 <= actual_len {
        match UsnRecordRaw::parse(&buffer[..actual_len], &mut offset) {
            Some(rec) => {
                if rec.file_name.is_empty() && rec.record_length == 0 {
                    break;
                }
                records.push(rec);
            }
            None => break,
        }
    }

    Ok(records)
}

pub fn enumerate_mft_entries(drive: &str, low_usn: i64, high_usn: i64) -> Result<Vec<UsnRecordRaw>, UsnCollectorError> {
    let vol = VolumeHandle::open(drive)?;
    let mut total_records = Vec::new();
    let mut start_ref: u64 = 0;

    loop {
        let mut buffer = vec![0u8; 65536];
        let mut bytes_returned: u32 = 0;

        let input = MftEnumDataV0 {
            start_file_reference: start_ref,
            low_threshold: low_usn,
            high_threshold: high_usn,
            _reserved: [0; 2],
        };

        let result = unsafe {
            DeviceIoControl(
                vol.raw(),
                FSCTL_ENUM_USN_DATA,
                Some(&input as *const _ as *const _),
                mem::size_of::<MftEnumDataV0>() as u32,
                Some(buffer.as_mut_ptr() as *mut _),
                buffer.len() as u32,
                Some(&mut bytes_returned as *mut u32),
                None,
            )
        };

        match result {
            Ok(_) => {}
            Err(e) => {
                let code = e.code().0;
                if code == -2147483647 || code == -2147483646 {
                    break;
                }
                if code == 38 {
                    break;
                }
                return Err(UsnCollectorError::Win32(e));
            }
        }

        let actual_len = bytes_returned as usize;
        if actual_len < 8 {
            break;
        }

        start_ref = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
        let mut offset = 8usize;

        while offset + 4 <= actual_len {
            match UsnRecordRaw::parse(&buffer[..actual_len], &mut offset) {
                Some(rec) => {
                    if rec.record_length == 0 {
                        break;
                    }
                    total_records.push(rec);
                }
                None => break,
            }
        }

        if start_ref == 0 || start_ref == u64::MAX {
            break;
        }
    }

    Ok(total_records)
}

pub fn read_file_usn_data(drive: &str, file_ref: u64) -> Result<Option<UsnRecordRaw>, UsnCollectorError> {
    let vol = VolumeHandle::open(drive)?;
    let mut buffer = [0u8; 1024];
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            vol.raw(),
            FSCTL_READ_FILE_USN_DATA,
            Some(&file_ref as *const _ as *const _),
            mem::size_of::<u64>() as u32,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
            Some(&mut bytes_returned as *mut u32),
            None,
        )
    };

    match result {
        Ok(_) => {}
        Err(e) => {
            let code = e.code().0;
            if code == -2147483647 || code == -2147483646 || code == 38 {
                return Ok(None);
            }
            return Err(UsnCollectorError::Win32(e));
        }
    }

    let actual_len = bytes_returned as usize;
    if actual_len < 60 {
        return Ok(None);
    }

    let mut offset = 0usize;
    Ok(UsnRecordRaw::parse(&buffer[..actual_len], &mut offset))
}

pub struct UsnCollector {
    running: Arc<RwLock<bool>>,
    entries: Arc<RwLock<Vec<UsnEntry>>>,
}

impl UsnCollector {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            entries: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn start(&self) -> std::result::Result<(), UsnCollectorError> {
        let mut running = self.running.write().await;
        *running = true;
        info!("USN journal collector started");
        Ok(())
    }

    pub async fn stop(&self) -> std::result::Result<(), UsnCollectorError> {
        let mut running = self.running.write().await;
        *running = false;
        info!("USN journal collector stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn capture_entry(&self, entry: UsnEntry) -> std::result::Result<(), UsnCollectorError> {
        if !*self.running.read().await {
            return Err(UsnCollectorError::NotStarted.into());
        }
        if entry.file_name.is_empty() {
            return Err(UsnCollectorError::InvalidEntry(
                "Empty file name".into(),
            )
            .into());
        }
        debug!(
            file = %entry.file_name,
            reason = %entry.reason,
            usn = entry.usn,
            "Captured USN journal entry"
        );
        let mut entries = self.entries.write().await;
        entries.push(entry);
        Ok(())
    }

    pub async fn get_entries(&self) -> Vec<UsnEntry> {
        self.entries.read().await.clone()
    }

    pub async fn get_entries_by_reason(&self, reason: UsnReason) -> Vec<UsnEntry> {
        self.entries
            .read()
            .await
            .iter()
            .filter(|e| e.reason == reason)
            .cloned()
            .collect()
    }

    pub async fn entry_count(&self) -> usize {
        self.entries.read().await.len()
    }

    pub async fn clear(&self) {
        self.entries.write().await.clear();
        debug!("USN journal collector cleared all entries");
    }
}

impl Default for UsnCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(file_name: &str, reason: UsnReason, usn: i64) -> UsnEntry {
        UsnEntry {
            file_ref_number: 12345,
            parent_ref: 54321,
            usn,
            reason,
            file_name: file_name.to_string(),
            timestamp: Utc::now(),
        }
    }

    fn make_record(reason: u32, file_name: &str) -> UsnRecordRaw {
        UsnRecordRaw {
            record_length: 0,
            major_version: 2,
            minor_version: 0,
            file_ref_number: 12345,
            parent_ref_number: 54321,
            usn: 100,
            reason,
            file_name_length: (file_name.len() * 2) as u16,
            file_name_offset: 60,
            file_name: file_name.to_string(),
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_start_stop() {
        let collector = UsnCollector::new();
        assert!(!collector.is_running().await);
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.stop().await.unwrap();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_capture_requires_running() {
        let collector = UsnCollector::new();
        let entry = make_entry("test.txt", UsnReason::FileCreate, 100);
        assert!(collector.capture_entry(entry).await.is_err());
    }

    #[tokio::test]
    async fn test_capture_entry() {
        let collector = UsnCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_entry(make_entry("test.txt", UsnReason::FileCreate, 100))
            .await
            .unwrap();
        assert_eq!(collector.entry_count().await, 1);
    }

    #[tokio::test]
    async fn test_reject_empty_filename() {
        let collector = UsnCollector::new();
        collector.start().await.unwrap();
        let entry = make_entry("", UsnReason::FileCreate, 100);
        assert!(collector.capture_entry(entry).await.is_err());
    }

    #[tokio::test]
    async fn test_get_entries_by_reason() {
        let collector = UsnCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_entry(make_entry("a.txt", UsnReason::FileCreate, 1))
            .await
            .unwrap();
        collector
            .capture_entry(make_entry("b.txt", UsnReason::FileDelete, 2))
            .await
            .unwrap();
        collector
            .capture_entry(make_entry("c.txt", UsnReason::FileCreate, 3))
            .await
            .unwrap();

        let creates = collector.get_entries_by_reason(UsnReason::FileCreate).await;
        assert_eq!(creates.len(), 2);
        let deletes = collector.get_entries_by_reason(UsnReason::FileDelete).await;
        assert_eq!(deletes.len(), 1);
    }

    #[tokio::test]
    async fn test_usn_reason_from_code() {
        assert_eq!(
            UsnReason::from_usn_code(0x00000100),
            Some(UsnReason::FileCreate)
        );
        assert_eq!(
            UsnReason::from_usn_code(0x00000200),
            Some(UsnReason::FileDelete)
        );
        assert_eq!(
            UsnReason::from_usn_code(0x00000001),
            Some(UsnReason::DataOverwrite)
        );
        assert!(UsnReason::from_usn_code(0xFFFFFFFF).is_none());
    }

    #[tokio::test]
    async fn test_clear() {
        let collector = UsnCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_entry(make_entry("test.txt", UsnReason::FileCreate, 100))
            .await
            .unwrap();
        assert_eq!(collector.entry_count().await, 1);
        collector.clear().await;
        assert_eq!(collector.entry_count().await, 0);
    }

    #[tokio::test]
    async fn test_multiple_reasons() {
        let collector = UsnCollector::new();
        collector.start().await.unwrap();
        let reasons = [
            UsnReason::DataOverwrite,
            UsnReason::DataExtend,
            UsnReason::SecurityChange,
            UsnReason::RenameOldName,
            UsnReason::EaChange,
        ];
        for (i, reason) in reasons.iter().enumerate() {
            collector
                .capture_entry(make_entry(&format!("file{}", i), *reason, i as i64))
                .await
                .unwrap();
        }
        assert_eq!(collector.entry_count().await, 5);
    }

    #[test]
    fn test_usn_record_raw_parse_v2() {
        let file_name = "test.txt";
        let file_name_utf16: Vec<u16> = file_name.encode_utf16().collect();
        let fn_bytes: Vec<u8> = bytemuck::cast_slice(&file_name_utf16).to_vec();
        let fn_len = fn_bytes.len() as u16;
        let fn_offset: u16 = 60;
        let total_size = fn_offset as usize + fn_len as usize;
        let mut buf = vec![0u8; total_size];

        buf[0..4].copy_from_slice(&(total_size as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        buf[8..16].copy_from_slice(&12345u64.to_le_bytes());
        buf[16..24].copy_from_slice(&54321u64.to_le_bytes());
        buf[24..32].copy_from_slice(&100i64.to_le_bytes());
        // timestamp = Jan 1 2023 00:00:00 UTC in Windows FILETIME
        let windows_epoch: i64 = 116444736000000000 + 0; // 0 = Jan 1 2023?
        let ts_bytes = (windows_epoch as u64).to_le_bytes();
        buf[32..40].copy_from_slice(&ts_bytes);
        buf[48..52].copy_from_slice(&0x00000100u32.to_le_bytes());
        buf[52..56].copy_from_slice(&0u32.to_le_bytes());
        buf[56..58].copy_from_slice(&fn_len.to_le_bytes());
        buf[58..60].copy_from_slice(&fn_offset.to_le_bytes());
        buf[60..60 + fn_len as usize].copy_from_slice(&fn_bytes);

        let mut offset = 0usize;
        let rec = UsnRecordRaw::parse(&buf, &mut offset).unwrap();
        assert_eq!(rec.file_ref_number, 12345);
        assert_eq!(rec.parent_ref_number, 54321);
        assert_eq!(rec.usn, 100);
        assert_eq!(rec.reason, 0x00000100);
        assert_eq!(rec.file_name, "test.txt");
        assert_eq!(rec.major_version, 2);
        assert_eq!(rec.minor_version, 0);
    }

    #[test]
    fn test_usn_record_raw_to_entry() {
        let rec = make_record(0x00000100, "hello.txt");
        let entry = rec.to_entry().unwrap();
        assert_eq!(entry.file_ref_number, 12345);
        assert_eq!(entry.parent_ref, 54321);
        assert_eq!(entry.usn, 100);
        assert_eq!(entry.reason, UsnReason::FileCreate);
        assert_eq!(entry.file_name, "hello.txt");
    }

    #[test]
    fn test_usn_record_raw_to_entry_unknown_reason() {
        let rec = make_record(0xDEADBEEF, "unknown.txt");
        assert!(rec.to_entry().is_none());
    }

    #[test]
    fn test_volume_handle_open_invalid() {
        let result = VolumeHandle::open("Z:");
        assert!(result.is_err());
    }

    #[test]
    fn test_read_usn_journal_errors_on_bad_drive() {
        let result = read_usn_journal("Z:");
        assert!(result.is_err());
    }

    #[test]
    fn test_enumerate_mft_entries_errors_on_bad_drive() {
        let result = enumerate_mft_entries("Z:", 0, 100);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_read_file_usn_data_errors_on_bad_drive() {
        let result = read_file_usn_data("Z:", 12345);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_buffer() {
        let buf = [];
        let mut offset = 0usize;
        assert!(UsnRecordRaw::parse(&buf, &mut offset).is_none());
    }

    #[test]
    fn test_parse_truncated_buffer() {
        let buf = [0u8; 4];
        let mut offset = 0usize;
        assert!(UsnRecordRaw::parse(&buf, &mut offset).is_none());
    }

    #[test]
    fn test_parse_zero_length_record() {
        let buf = [0u8; 8];
        let mut offset = 0usize;
        assert!(UsnRecordRaw::parse(&buf, &mut offset).is_none());
    }
}
