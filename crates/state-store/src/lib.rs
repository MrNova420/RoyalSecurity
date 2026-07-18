pub mod store;
pub mod schema;

pub use royalsecurity_core as core;
pub use royalsecurity_common as common;
pub use store::*;
pub use schema::*;

#[cfg(test)]
mod tests {
    use crate::store::StateStore;
    use crate::schema::*;
    use std::fs;

    fn test_db_path() -> String {
        let dir = std::env::temp_dir().join("royalsecurity_test");
        fs::create_dir_all(&dir).ok();
        dir.join(format!("test_{}.redb", uuid::Uuid::new_v4())).display().to_string()
    }

    #[test]
    fn test_store_creation() {
        let path = test_db_path();
        let store = StateStore::new(&path).unwrap();
        assert_eq!(store.event_count().unwrap(), 0);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_insert_and_get_event() {
        let path = test_db_path();
        let store = StateStore::new(&path).unwrap();
        
        let event = StoredEvent {
            id: "test-1".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            severity: "High".into(),
            event_type: "ProcessCreated".into(),
            source: "test".into(),
            data: serde_json::json!({"pid": 1234}),
        };
        
        store.insert_event(&event).unwrap();
        assert_eq!(store.event_count().unwrap(), 1);
        
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_upsert_process() {
        let path = test_db_path();
        let store = StateStore::new(&path).unwrap();
        
        let proc = StoredProcess {
            pid: 9999,
            ppid: 1,
            name: "test.exe".into(),
            path: "C:\\test.exe".into(),
            command_line: "test.exe".into(),
            user: "SYSTEM".into(),
            first_seen: chrono::Utc::now().to_rfc3339(),
            last_seen: chrono::Utc::now().to_rfc3339(),
        };
        
        store.upsert_process(&proc).unwrap();
        let retrieved = store.get_process(9999).unwrap().unwrap();
        assert_eq!(retrieved.pid, 9999);
        assert_eq!(retrieved.name, "test.exe");
        
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_insert_and_get_threat() {
        let path = test_db_path();
        let store = StateStore::new(&path).unwrap();
        
        let threat = StoredThreat {
            id: "threat-1".into(),
            name: "Test Malware".into(),
            severity: "Critical".into(),
            status: "Active".into(),
            first_seen: chrono::Utc::now().to_rfc3339(),
            last_seen: chrono::Utc::now().to_rfc3339(),
            description: "Test threat".into(),
            mitre_tactic: Some("TA0002".into()),
            mitre_technique: Some("T1059".into()),
        };
        
        store.insert_threat(&threat).unwrap();
        let threats = store.get_threats().unwrap();
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].name, "Test Malware");
        
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_config_storage() {
        let path = test_db_path();
        let store = StateStore::new(&path).unwrap();
        
        store.insert_config("key1", "value1").unwrap();
        let val = store.get_config("key1").unwrap();
        assert_eq!(val, Some("value1".into()));
        
        let missing = store.get_config("nonexistent").unwrap();
        assert_eq!(missing, None);
        
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_clear_events() {
        let path = test_db_path();
        let store = StateStore::new(&path).unwrap();
        
        for i in 0..5 {
            let event = StoredEvent {
                id: format!("ev-{}", i),
                timestamp: chrono::Utc::now().to_rfc3339(),
                severity: "Low".into(),
                event_type: "Test".into(),
                source: "test".into(),
                data: serde_json::json!({}),
            };
            store.insert_event(&event).unwrap();
        }
        
        assert_eq!(store.event_count().unwrap(), 5);
        store.clear_events().unwrap();
        assert_eq!(store.event_count().unwrap(), 0);
        
        fs::remove_file(&path).ok();
    }
}
