use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use crate::module::{SecurityModule, ModuleEntry, ModuleConfig};
use crate::common::types::{SecurityEvent, ModuleHealth, ModuleStatus};
use crate::bus::EventBus;
use tracing::{info, warn, error};

pub struct ModuleRegistry {
    modules: Arc<RwLock<HashMap<String, ModuleEntry>>>,
    bus: EventBus,
}

impl ModuleRegistry {
    pub fn new(bus: EventBus) -> Self {
        Self {
            modules: Arc::new(RwLock::new(HashMap::new())),
            bus,
        }
    }

    pub fn register(&self, module: Box<dyn SecurityModule>, config: ModuleConfig) {
        let name = module.name().to_string();
        info!(module = %name, "Registering security module");
        let entry = ModuleEntry {
            module,
            config,
            health: ModuleHealth {
                status: ModuleStatus::Uninitialized,
                ..Default::default()
            },
        };
        self.modules.write().insert(name, entry);
    }

    pub async fn initialize_all(&self) {
        let mut modules = self.modules.write();
        for (name, entry) in modules.iter_mut() {
            if entry.config.enabled {
                match entry.module.initialize(entry.config.clone()).await {
                    Ok(()) => {
                        entry.health.status = ModuleStatus::Initialized;
                        info!(module = %name, "Module initialized");
                    }
                    Err(e) => {
                        entry.health.status = ModuleStatus::Failed;
                        error!(module = %name, error = %e, "Module initialization failed");
                    }
                }
            }
        }
    }

    pub async fn start_all(&self) {
        let mut modules = self.modules.write();
        for (name, entry) in modules.iter_mut() {
            if entry.config.enabled && entry.health.status == ModuleStatus::Initialized {
                match entry.module.start().await {
                    Ok(()) => {
                        entry.health.status = ModuleStatus::Running;
                        info!(module = %name, "Module started");
                    }
                    Err(e) => {
                        entry.health.status = ModuleStatus::Failed;
                        error!(module = %name, error = %e, "Module start failed");
                    }
                }
            }
        }
    }

    pub async fn stop_all(&self) {
        let mut modules = self.modules.write();
        for (name, entry) in modules.iter_mut() {
            if entry.health.status == ModuleStatus::Running {
                if let Err(e) = entry.module.stop().await {
                    error!(module = %name, error = %e, "Module stop failed");
                }
                entry.health.status = ModuleStatus::Stopped;
            }
        }
    }

    pub async fn dispatch_event(&self, event: SecurityEvent) {
        let modules = self.modules.read();
        for (name, entry) in modules.iter() {
            if entry.config.enabled && entry.health.status == ModuleStatus::Running {
                if let Some(response) = entry.module.handle_event(&event).await {
                    if let Err(e) = self.bus.publish(response) {
                        warn!(module = %name, error = %e, "Failed to publish response event");
                    }
                }
            }
        }
    }

    pub fn get_health(&self) -> HashMap<String, ModuleHealth> {
        self.modules.read()
            .iter()
            .map(|(k, v)| (k.clone(), v.health.clone()))
            .collect()
    }

    pub fn module_count(&self) -> usize {
        self.modules.read().len()
    }

    pub fn enabled_count(&self) -> usize {
        self.modules.read()
            .values()
            .filter(|e| e.config.enabled)
            .count()
    }
}
