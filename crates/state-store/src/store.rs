use redb::*;
use tracing::info;
use crate::schema::*;
use std::path::Path;
use std::fs;

pub struct StateStore {
    db: Database,
}

impl StateStore {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let path_display = path.as_ref().display().to_string();
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let db = Database::create(&path)?;

        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(EVENTS_TABLE)?;
            write_txn.open_table(PROCESSES_TABLE)?;
            write_txn.open_table(NETWORK_TABLE)?;
            write_txn.open_table(THREATS_TABLE)?;
            write_txn.open_table(AUDIT_TABLE)?;
            write_txn.open_table(RULES_TABLE)?;
            write_txn.open_table(IOCS_TABLE)?;
            write_txn.open_table(CONFIG_TABLE)?;
            write_txn.open_table(MODULES_TABLE)?;
        }
        write_txn.commit()?;

        info!("StateStore initialized at {}", path_display);
        Ok(Self { db })
    }

    pub fn insert_event(&self, event: &StoredEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bytes = bincode::serialize(event)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(EVENTS_TABLE)?;
            table.insert(event.id.as_str(), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_event(&self, id: &str) -> Result<Option<StoredEvent>, Box<dyn std::error::Error + Send + Sync>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(EVENTS_TABLE)?;
        match table.get(id)? {
            Some(data) => {
                let event: StoredEvent = bincode::deserialize(data.value())?;
                Ok(Some(event))
            }
            None => Ok(None),
        }
    }

    pub fn upsert_process(&self, proc: &StoredProcess) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bytes = bincode::serialize(proc)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PROCESSES_TABLE)?;
            table.insert(proc.pid, bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_process(&self, pid: u32) -> Result<Option<StoredProcess>, Box<dyn std::error::Error + Send + Sync>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PROCESSES_TABLE)?;
        match table.get(pid)? {
            Some(data) => {
                let proc: StoredProcess = bincode::deserialize(data.value())?;
                Ok(Some(proc))
            }
            None => Ok(None),
        }
    }

    pub fn insert_threat(&self, threat: &StoredThreat) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bytes = bincode::serialize(threat)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(THREATS_TABLE)?;
            table.insert(threat.id.as_str(), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_threats(&self) -> Result<Vec<StoredThreat>, Box<dyn std::error::Error + Send + Sync>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(THREATS_TABLE)?;
        let mut threats = Vec::new();
        for item in table.iter()? {
            let (_, data) = item?;
            let threat: StoredThreat = bincode::deserialize(data.value())?;
            threats.push(threat);
        }
        Ok(threats)
    }

    pub fn insert_ioc(&self, ioc: &StoredIoc) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bytes = bincode::serialize(ioc)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(IOCS_TABLE)?;
            table.insert(ioc.value.as_str(), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_ioc(&self, value: &str) -> Result<Option<StoredIoc>, Box<dyn std::error::Error + Send + Sync>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(IOCS_TABLE)?;
        match table.get(value)? {
            Some(data) => {
                let ioc: StoredIoc = bincode::deserialize(data.value())?;
                Ok(Some(ioc))
            }
            None => Ok(None),
        }
    }

    pub fn insert_config(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(CONFIG_TABLE)?;
            table.insert(key, value.as_bytes())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_config(&self, key: &str) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(CONFIG_TABLE)?;
        match table.get(key)? {
            Some(data) => Ok(Some(String::from_utf8(data.value().to_vec())?)),
            None => Ok(None),
        }
    }

    pub fn event_count(&self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(EVENTS_TABLE)?;
        Ok(table.len()? as usize)
    }

    pub fn process_count(&self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PROCESSES_TABLE)?;
        Ok(table.len()? as usize)
    }

    pub fn get_recent_events(&self, limit: usize) -> Result<Vec<StoredEvent>, Box<dyn std::error::Error + Send + Sync>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(EVENTS_TABLE)?;
        let mut events: Vec<StoredEvent> = Vec::new();
        for item in table.iter()? {
            let (_, data) = item?;
            let event: StoredEvent = bincode::deserialize(data.value())?;
            events.push(event);
        }
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        events.truncate(limit);
        Ok(events)
    }

    pub fn clear_events(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let txn = self.db.begin_write()?;
        {
            let _ = txn.delete_table(EVENTS_TABLE)?;
            txn.open_table(EVENTS_TABLE)?;
        }
        txn.commit()?;
        info!("Events table cleared");
        Ok(())
    }

    pub fn prune_events_before(&self, _max_events: usize) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        Ok(0)
    }
}
