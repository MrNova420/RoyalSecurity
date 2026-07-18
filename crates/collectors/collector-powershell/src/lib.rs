pub mod prelude;
pub use royalsecurity_core as core;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PsLevel {
    Error,
    Warning,
    Information,
    Verbose,
}

impl std::fmt::Display for PsLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PsLevel::Error => write!(f, "Error"),
            PsLevel::Warning => write!(f, "Warning"),
            PsLevel::Information => write!(f, "Information"),
            PsLevel::Verbose => write!(f, "Verbose"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptBlockEvent {
    pub process_id: u32,
    pub script_text: String,
    pub hash: String,
    pub level: PsLevel,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleLoadEvent {
    pub process_id: u32,
    pub module_name: String,
    pub module_path: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandExecution {
    pub process_id: u32,
    pub command: String,
    pub invocation_info: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum PowershellCollectorError {
    #[error("Collector not started")]
    NotStarted,
    #[error("Invalid script block: {0}")]
    InvalidScriptBlock(String),
    #[error("Collector error: {0}")]
    Internal(String),
}

pub struct PowershellCollector {
    running: Arc<RwLock<bool>>,
    script_blocks: Arc<RwLock<Vec<ScriptBlockEvent>>>,
    module_loads: Arc<RwLock<Vec<ModuleLoadEvent>>>,
    command_executions: Arc<RwLock<Vec<CommandExecution>>>,
}

impl PowershellCollector {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            script_blocks: Arc::new(RwLock::new(Vec::new())),
            module_loads: Arc::new(RwLock::new(Vec::new())),
            command_executions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn start(&self)  -> std::result::Result<(), PowershellCollectorError> {
        let mut running = self.running.write().await;
        *running = true;
        info!("PowerShell collector started");
        Ok(())
    }

    pub async fn stop(&self)  -> std::result::Result<(), PowershellCollectorError> {
        let mut running = self.running.write().await;
        *running = false;
        info!("PowerShell collector stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn capture_script_block(&self, event: ScriptBlockEvent)  -> std::result::Result<(), PowershellCollectorError> {
        if !*self.running.read().await {
            return Err(PowershellCollectorError::NotStarted.into());
        }
        if event.script_text.is_empty() {
            return Err(PowershellCollectorError::InvalidScriptBlock(
                "Empty script text".into(),
            )
            .into());
        }
        debug!(
            pid = event.process_id,
            level = %event.level,
            hash = %event.hash,
            "Captured PowerShell script block"
        );
        let mut blocks = self.script_blocks.write().await;
        blocks.push(event);
        Ok(())
    }

    pub async fn capture_module_load(&self, event: ModuleLoadEvent)  -> std::result::Result<(), PowershellCollectorError> {
        if !*self.running.read().await {
            return Err(PowershellCollectorError::NotStarted.into());
        }
        debug!(
            pid = event.process_id,
            module = %event.module_name,
            "Captured PowerShell module load"
        );
        let mut loads = self.module_loads.write().await;
        loads.push(event);
        Ok(())
    }

    pub async fn capture_command_execution(&self, event: CommandExecution)  -> std::result::Result<(), PowershellCollectorError> {
        if !*self.running.read().await {
            return Err(PowershellCollectorError::NotStarted.into());
        }
        debug!(
            pid = event.process_id,
            command = %event.command,
            "Captured PowerShell command execution"
        );
        let mut execs = self.command_executions.write().await;
        execs.push(event);
        Ok(())
    }

    pub async fn get_script_blocks(&self) -> Vec<ScriptBlockEvent> {
        self.script_blocks.read().await.clone()
    }

    pub async fn get_blocks_for_process(&self, pid: u32) -> Vec<ScriptBlockEvent> {
        self.script_blocks
            .read()
            .await
            .iter()
            .filter(|b| b.process_id == pid)
            .cloned()
            .collect()
    }

    pub async fn block_count(&self) -> usize {
        self.script_blocks.read().await.len()
    }

    pub async fn get_module_loads(&self) -> Vec<ModuleLoadEvent> {
        self.module_loads.read().await.clone()
    }

    pub async fn get_command_executions(&self) -> Vec<CommandExecution> {
        self.command_executions.read().await.clone()
    }

    pub async fn clear(&self) {
        self.script_blocks.write().await.clear();
        self.module_loads.write().await.clear();
        self.command_executions.write().await.clear();
        debug!("PowerShell collector cleared all events");
    }
}

impl Default for PowershellCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_script_block(pid: u32, text: &str, level: PsLevel) -> ScriptBlockEvent {
        let hash_val: u64 = text.bytes().fold(0u64, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(b as u64)
        });
        let hash_bytes = hash_val.to_be_bytes();
        ScriptBlockEvent {
            process_id: pid,
            script_text: text.to_string(),
            hash: hash_bytes.iter().map(|b| format!("{:02x}", b)).collect(),
            level,
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_new_collector_is_not_running() {
        let collector = PowershellCollector::new();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let collector = PowershellCollector::new();
        collector.start().await.unwrap();
        assert!(collector.is_running().await);
        collector.stop().await.unwrap();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_capture_requires_running() {
        let collector = PowershellCollector::new();
        let event = make_script_block(100, "Get-Process", PsLevel::Information);
        let result = collector.capture_script_block(event).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_capture_script_block() {
        let collector = PowershellCollector::new();
        collector.start().await.unwrap();
        let event = make_script_block(100, "Get-Process", PsLevel::Information);
        collector.capture_script_block(event).await.unwrap();
        assert_eq!(collector.block_count().await, 1);
    }

    #[tokio::test]
    async fn test_reject_empty_script_block() {
        let collector = PowershellCollector::new();
        collector.start().await.unwrap();
        let event = make_script_block(100, "", PsLevel::Error);
        let result = collector.capture_script_block(event).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_blocks_for_process() {
        let collector = PowershellCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_script_block(make_script_block(1, "cmd1", PsLevel::Information))
            .await
            .unwrap();
        collector
            .capture_script_block(make_script_block(2, "cmd2", PsLevel::Warning))
            .await
            .unwrap();
        collector
            .capture_script_block(make_script_block(1, "cmd3", PsLevel::Error))
            .await
            .unwrap();

        let blocks = collector.get_blocks_for_process(1).await;
        assert_eq!(blocks.len(), 2);

        let blocks = collector.get_blocks_for_process(2).await;
        assert_eq!(blocks.len(), 1);
    }

    #[tokio::test]
    async fn test_clear() {
        let collector = PowershellCollector::new();
        collector.start().await.unwrap();
        collector
            .capture_script_block(make_script_block(1, "test", PsLevel::Verbose))
            .await
            .unwrap();
        assert_eq!(collector.block_count().await, 1);
        collector.clear().await;
        assert_eq!(collector.block_count().await, 0);
    }

    #[tokio::test]
    async fn test_multiple_levels() {
        let collector = PowershellCollector::new();
        collector.start().await.unwrap();
        let levels = [PsLevel::Error, PsLevel::Warning, PsLevel::Information, PsLevel::Verbose];
        for (i, level) in levels.iter().enumerate() {
            let event = make_script_block(i as u32, &format!("script{}", i), *level);
            collector.capture_script_block(event).await.unwrap();
        }
        assert_eq!(collector.block_count().await, 4);
    }
}

