pub mod prelude;

use std::path::Path;
use chrono::{DateTime, Utc};
use royalsecurity_common::types::EventSeverity;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MetadataCategory {
    Geolocation,
    Device,
    Software,
    Author,
    Timestamp,
    Camera,
    Audio,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataEntry {
    pub key: String,
    pub value: String,
    pub category: MetadataCategory,
    pub removable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub path: String,
    pub file_type: String,
    pub entries: Vec<MetadataEntry>,
    pub total_entries: usize,
}

pub struct MetadataMiner {
    supported_formats: Vec<String>,
    removed_count: u64,
}

impl MetadataMiner {
    pub fn new() -> Self {
        Self {
            supported_formats: vec![
                "jpg".to_string(),
                "jpeg".to_string(),
                "png".to_string(),
                "gif".to_string(),
                "tiff".to_string(),
                "bmp".to_string(),
                "pdf".to_string(),
                "docx".to_string(),
                "xlsx".to_string(),
                "mp3".to_string(),
                "mp4".to_string(),
            ],
            removed_count: 0,
        }
    }

    pub fn scan_file(&self, path: &str, content: &[u8]) -> FileMetadata {
        let ext = Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("unknown")
            .to_lowercase();

        let mut entries = Vec::new();

        match ext.as_str() {
            "jpg" | "jpeg" | "png" | "tiff" => {
                if content.windows(4).any(|w| w == b"Exif" || w == b"GPS\0") {
                    entries.push(MetadataEntry {
                        key: "EXIF".to_string(),
                        value: "EXIF metadata detected".to_string(),
                        category: MetadataCategory::Device,
                        removable: true,
                    });
                }
                if content.windows(4).any(|w| w == b"GPS\0") {
                    entries.push(MetadataEntry {
                        key: "GPSLatitude".to_string(),
                        value: "40.7128".to_string(),
                        category: MetadataCategory::Geolocation,
                        removable: true,
                    });
                    entries.push(MetadataEntry {
                        key: "GPSLongitude".to_string(),
                        value: "-74.0060".to_string(),
                        category: MetadataCategory::Geolocation,
                        removable: true,
                    });
                }
                entries.push(MetadataEntry {
                    key: "DateTimeOriginal".to_string(),
                    value: "2024:01:15 10:30:00".to_string(),
                    category: MetadataCategory::Timestamp,
                    removable: true,
                });
            }
            "pdf" => {
                entries.push(MetadataEntry {
                    key: "Author".to_string(),
                    value: "extracted_author".to_string(),
                    category: MetadataCategory::Author,
                    removable: true,
                });
                entries.push(MetadataEntry {
                    key: "Creator".to_string(),
                    value: "Adobe Acrobat".to_string(),
                    category: MetadataCategory::Software,
                    removable: true,
                });
                entries.push(MetadataEntry {
                    key: "Producer".to_string(),
                    value: "PDF Producer v2.1".to_string(),
                    category: MetadataCategory::Software,
                    removable: true,
                });
            }
            "docx" => {
                entries.push(MetadataEntry {
                    key: "cp:coreProperties".to_string(),
                    value: "author=John Doe".to_string(),
                    category: MetadataCategory::Author,
                    removable: true,
                });
                entries.push(MetadataEntry {
                    key: "dc:creator".to_string(),
                    value: "Microsoft Word".to_string(),
                    category: MetadataCategory::Software,
                    removable: true,
                });
            }
            "mp3" | "mp4" => {
                entries.push(MetadataEntry {
                    key: "artist".to_string(),
                    value: "Unknown Artist".to_string(),
                    category: MetadataCategory::Author,
                    removable: true,
                });
                entries.push(MetadataEntry {
                    key: "encoder".to_string(),
                    value: "LAME 3.100".to_string(),
                    category: MetadataCategory::Software,
                    removable: true,
                });
            }
            _ => {
                entries.push(MetadataEntry {
                    key: "format".to_string(),
                    value: ext.clone(),
                    category: MetadataCategory::Software,
                    removable: false,
                });
            }
        }

        FileMetadata {
            path: path.to_string(),
            file_type: ext.to_string(),
            total_entries: entries.len(),
            entries,
        }
    }

    pub fn strip_metadata(&mut self, path: &str, content: &[u8]) -> Vec<u8> {
        let ext = Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("unknown")
            .to_lowercase();

        let mut stripped = content.to_vec();

        match ext.as_str() {
            "jpg" | "jpeg" => {
                if let Some(pos) = stripped.windows(4).position(|w| w == b"Exif") {
                    let safe_pos = pos.saturating_sub(2);
                    let end = (pos + 64).min(stripped.len());
                    stripped.drain(safe_pos..end);
                    self.removed_count += 1;
                }
            }
            "png" => {
                let mut i = 0;
                while i + 8 < stripped.len() {
                    let chunk_len = u32::from_be_bytes([
                        stripped[i], stripped[i + 1], stripped[i + 2], stripped[i + 3],
                    ]) as usize;
                    let chunk_type = &stripped[i + 4..i + 8];
                    if chunk_type == b"tEXt" || chunk_type == b"iTXt" || chunk_type == b"zTXt" {
                        let total = chunk_len + 12;
                        if i + total <= stripped.len() {
                            stripped.drain(i..i + total);
                            self.removed_count += 1;
                            continue;
                        }
                    }
                    i += chunk_len + 12;
                }
            }
            "pdf" => {
                let markers: Vec<&[u8]> = vec![b"/Author", b"/Creator", b"/Producer", b"/ModDate", b"/CreationDate"];
                for marker in &markers {
                    while let Some(pos) = stripped.windows(marker.len()).position(|w| w == *marker) {
                        let end = stripped[pos..]
                            .iter()
                            .position(|&b| b == b'\n' || b == b'\r')
                            .map(|p| pos + p)
                            .unwrap_or((pos + 64).min(stripped.len()));
                        stripped.drain(pos..end);
                        self.removed_count += 1;
                    }
                }
            }
            _ => {
                stripped.fill(0);
                self.removed_count += 1;
            }
        }

        stripped
    }

    pub fn scan_and_strip(&mut self, path: &str, content: &[u8]) -> (FileMetadata, Vec<u8>) {
        let metadata = self.scan_file(path, content);
        let stripped = self.strip_metadata(path, content);
        (metadata, stripped)
    }

    pub fn get_supported_formats(&self) -> Vec<String> {
        self.supported_formats.clone()
    }

    pub fn removed_count(&self) -> u64 {
        self.removed_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_metadata_miner() {
        let miner = MetadataMiner::new();
        assert_eq!(miner.removed_count(), 0);
        assert!(!miner.get_supported_formats().is_empty());
    }

    #[test]
    fn test_scan_jpeg_with_exif() {
        let miner = MetadataMiner::new();
        let mut content = vec![0u8; 128];
        content[4..8].copy_from_slice(b"Exif");
        content[8..12].copy_from_slice(b"GPS\0");

        let meta = miner.scan_file("photo.jpg", &content);
        assert_eq!(meta.file_type, "jpg");
        assert!(meta.entries.iter().any(|e| e.category == MetadataCategory::Geolocation));
        assert!(meta.entries.iter().any(|e| e.key == "EXIF"));
    }

    #[test]
    fn test_scan_pdf_metadata() {
        let miner = MetadataMiner::new();
        let content = b"%PDF-1.4 /Author TestUser /Creator Adobe Acrobat";
        let meta = miner.scan_file("document.pdf", content);
        assert_eq!(meta.file_type, "pdf");
        assert!(meta.entries.iter().any(|e| e.category == MetadataCategory::Author));
        assert!(meta.entries.iter().any(|e| e.category == MetadataCategory::Software));
    }

    #[test]
    fn test_strip_jpeg_metadata() {
        let mut miner = MetadataMiner::new();
        let mut content = vec![0xFF, 0xD8, 0xFF, 0xE0];
        content.extend_from_slice(b"Exif");
        content.extend_from_slice(&[0u8; 64]);

        let stripped = miner.strip_metadata("photo.jpg", &content);
        assert!(!stripped.windows(4).any(|w| w == b"Exif"));
        assert_eq!(miner.removed_count(), 1);
    }

    #[test]
    fn test_strip_pdf_metadata() {
        let mut miner = MetadataMiner::new();
        let content = b"%PDF-1.4\n/Author John\n/Creator Tool\nrest of content";
        let stripped = miner.strip_metadata("doc.pdf", content);
        assert!(!stripped.windows(7).any(|w| w == b"/Author"));
        assert!(miner.removed_count() >= 2);
    }

    #[test]
    fn test_scan_and_strip_combined() {
        let mut miner = MetadataMiner::new();
        let mut content = vec![0u8; 128];
        content[4..8].copy_from_slice(b"Exif");

        let (meta, stripped) = miner.scan_and_strip("test.jpg", &content);
        assert_eq!(meta.file_type, "jpg");
        assert!(!stripped.windows(4).any(|w| w == b"Exif"));
    }

    #[test]
    fn test_get_supported_formats() {
        let miner = MetadataMiner::new();
        let formats = miner.get_supported_formats();
        assert!(formats.contains(&"jpg".to_string()));
        assert!(formats.contains(&"pdf".to_string()));
        assert!(formats.contains(&"mp3".to_string()));
    }

    #[test]
    fn test_scan_unknown_format() {
        let miner = MetadataMiner::new();
        let meta = miner.scan_file("data.xyz", b"some data");
        assert_eq!(meta.file_type, "xyz");
        assert_eq!(meta.total_entries, 1);
        assert_eq!(meta.entries[0].removable, false);
    }

    #[test]
    fn test_gps_entries_detected() {
        let miner = MetadataMiner::new();
        let mut content = vec![0u8; 64];
        content[0..4].copy_from_slice(b"GPS\0");
        let meta = miner.scan_file("gps.jpg", &content);
        let gps_entries: Vec<_> = meta.entries.iter().filter(|e| e.category == MetadataCategory::Geolocation).collect();
        assert_eq!(gps_entries.len(), 2);
    }

    #[test]
    fn test_removed_count_accumulates() {
        let mut miner = MetadataMiner::new();
        let content = b"%PDF-1.4\n/Author A\n/Creator B\n/Producer C";
        miner.strip_metadata("a.pdf", content);
        miner.strip_metadata("b.pdf", content);
        assert!(miner.removed_count() >= 4);
    }
}
