use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub sha3_256: String,
    pub original_hash: String,
    pub quarantined_at: DateTime<Utc>,
    pub reason: String,
    pub metadata: HashMap<String, String>,
    pub size_bytes: u64,
}

pub struct QuarantineStore {
    quarantine_dir: PathBuf,
    items: Vec<QuarantineItem>,
}

impl QuarantineStore {
    pub fn new() -> Self {
        let dir = dirs().join("Quarantine");
        Self { quarantine_dir: dir, items: Vec::new() }
    }

    pub fn quarantine_file(&mut self, path: &str, reason: &str) -> Result<QuarantineItem, String> {
        use sha3::{Sha3_256, Digest};
        let src = std::path::Path::new(path);
        if !src.exists() { return Err(format!("File not found: {}", path)); }
        let data = std::fs::read(src).map_err(|e| e.to_string())?;
        let mut hasher = Sha3_256::new();
        hasher.update(&data);
        let hash = format!("{:x}", hasher.finalize());
        let file_name = src.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let id = uuid::Uuid::new_v4().to_string();
        let q_path = self.quarantine_dir.join(format!("{}_{}", &id[..8], file_name));
        std::fs::create_dir_all(&self.quarantine_dir).map_err(|e| e.to_string())?;
        std::fs::write(&q_path, &data).map_err(|e| e.to_string())?;
        let item = QuarantineItem {
            id,
            original_path: path.to_string(),
            quarantine_path: q_path.to_string_lossy().to_string(),
            sha3_256: hash.clone(),
            original_hash: hash,
            quarantined_at: Utc::now(),
            reason: reason.to_string(),
            metadata: HashMap::new(),
            size_bytes: data.len() as u64,
        };
        self.items.push(item.clone());
        Ok(item)
    }

    pub fn restore_file(&self, item_id: &str) -> Result<String, String> {
        let item = self.items.iter().find(|i| i.id == item_id).ok_or("Item not found")?;
        use sha3::{Sha3_256, Digest};
        let data = std::fs::read(&item.quarantine_path).map_err(|e| e.to_string())?;
        let mut hasher = Sha3_256::new();
        hasher.update(&data);
        let current_hash = format!("{:x}", hasher.finalize());
        if current_hash != item.sha3_256 { return Err("Integrity check failed".into()); }
        std::fs::write(&item.original_path, &data).map_err(|e| e.to_string())?;
        Ok(item.original_path.clone())
    }

    pub fn list_quarantined(&self) -> &[QuarantineItem] { &self.items }

    pub fn delete_quarantined(&mut self, item_id: &str) -> Result<(), String> {
        let idx = self.items.iter().position(|i| i.id == item_id).ok_or("Not found")?;
        let item = &self.items[idx];
        let _ = std::fs::remove_file(&item.quarantine_path);
        self.items.remove(idx);
        Ok(())
    }

    pub fn count(&self) -> usize { self.items.len() }
}

fn dirs() -> PathBuf {
    std::env::var("PROGRAMDATA")
        .map(|p| PathBuf::from(p).join("RoyalSecurity"))
        .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData\\RoyalSecurity"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_quarantine_store_new() {
        let store = QuarantineStore::new();
        assert_eq!(store.count(), 0);
    }
    #[test]
    fn test_quarantine_file_not_found() {
        let mut store = QuarantineStore::new();
        assert!(store.quarantine_file("C:\\nonexistent.exe", "test").is_err());
    }
    #[test]
    fn test_list_empty() {
        let store = QuarantineStore::new();
        assert!(store.list_quarantined().is_empty());
    }
    #[test]
    fn test_delete_not_found() {
        let mut store = QuarantineStore::new();
        assert!(store.delete_quarantined("nonexistent").is_err());
    }
    #[test]
    fn test_restore_not_found() {
        let store = QuarantineStore::new();
        assert!(store.restore_file("nonexistent").is_err());
    }
}
