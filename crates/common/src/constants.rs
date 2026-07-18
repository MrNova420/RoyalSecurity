pub const APP_NAME: &str = "RoyalSecurity";
pub const SERVICE_NAME: &str = "RoyalSecurityAgent";
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const MIN_MEMORY_MB: u64 = 80;
pub const MAX_MEMORY_MB: u64 = 256;
pub const TARGET_CPU_IDLE_PERCENT: f64 = 0.3;

pub const MAX_EVENTS_PER_SECOND: u64 = 100_000;
pub const TARGET_P99_LATENCY_US: u64 = 5;
pub const MAX_RULES_LOADED: usize = 100_000;
pub const MAX_IOC_CACHE_ENTRIES: usize = 1_000_000;
pub const MAX_PROCESSES_MONITORED: u32 = 50_000;

pub const EVENT_RETENTION_DAYS: u32 = 90;
pub const AUDIT_RETENTION_DAYS: u32 = 365;
pub const THREAT_INTEL_UPDATE_INTERVAL_MINUTES: u64 = 15;
pub const HEARTBEAT_INTERVAL_SECONDS: u64 = 5;
pub const PLUGIN_HOT_RELOAD_DELAY_MS: u64 = 500;

pub const QUARANTINE_FOLDER: &str = "C:\\ProgramData\\RoyalSecurity\\Quarantine";
pub const BACKUP_FOLDER: &str = "C:\\ProgramData\\RoyalSecurity\\Backups";
pub const LOG_FOLDER: &str = "C:\\ProgramData\\RoyalSecurity\\Logs";
pub const CONFIG_FOLDER: &str = "C:\\ProgramData\\RoyalSecurity\\Config";
pub const STATE_FOLDER: &str = "C:\\ProgramData\\RoyalSecurity\\State";
pub const PLUGIN_FOLDER: &str = "C:\\ProgramData\\RoyalSecurity\\Plugins";
pub const RULES_FOLDER: &str = "C:\\ProgramData\\RoyalSecurity\\Rules";
pub const INTEL_FOLDER: &str = "C:\\ProgramData\\RoyalSecurity\\Intel";
pub const DB_FOLDER: &str = "C:\\ProgramData\\RoyalSecurity\\Database";

pub const IPC_PIPE_NAME: &str = "\\\\.\\pipe\\RoyalSecurity";
pub const IPC_TIMEOUT_MS: u64 = 5000;
pub const WATCHDOG_INTERVAL_SECONDS: u64 = 10;

pub const LICENSE_KEY: &str = "royalsec-enterprise-2025";
