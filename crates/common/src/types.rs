use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;
use std::net::IpAddr;
use strum_macros::{EnumIter, EnumString, IntoStaticStr, Display};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord, Display, EnumIter, EnumString, IntoStaticStr)]
pub enum EventSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl Default for EventSeverity {
    fn default() -> Self {
        EventSeverity::Informational
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Display, EnumIter, EnumString, IntoStaticStr)]
pub enum EventType {
    ProcessCreated,
    ProcessTerminated,
    ProcessInjected,
    FileCreated,
    FileModified,
    FileDeleted,
    FileRenamed,
    RegistryCreated,
    RegistryModified,
    RegistryDeleted,
    NetworkConnection,
    NetworkListen,
    DnsQuery,
    DnsResponse,
    AuthSuccess,
    AuthFailure,
    PrivilegeEscalation,
    PrivilegeDeactivation,
    LateralMovement,
    PersistenceInstalled,
    PersistenceRemoved,
    DriverLoaded,
    DriverUnloaded,
    ServiceCreated,
    ServiceStarted,
    ServiceStopped,
    ScheduledTaskCreated,
    ScheduledTaskModified,
    ScheduledTaskDeleted,
    WmiEvent,
    NamedPipeCreated,
    NamedPipeConnected,
    MemoryAllocation,
    MemoryProtection,
    ThreadCreated,
    ThreadRemote,
    ModuleLoaded,
    HandleOpened,
    ClipboardAccess,
    PrintSpool,
    UsbDeviceConnected,
    UsbDeviceDisconnected,
    BluetoothDeviceConnected,
    WifiConnected,
    WifiDisconnected,
    FirmwareUpdated,
    BootIntegrityChanged,
    PolicyChanged,
    ComplianceViolation,
    ThreatDetected,
    AnomalyDetected,
    AlertTriggered,
    IncidentCreated,
}

impl Default for EventType {
    fn default() -> Self {
        EventType::ProcessCreated
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Display, EnumString, IntoStaticStr)]
pub enum FileAction {
    Created,
    Modified,
    Deleted,
    Renamed,
    Copied,
}

impl Default for FileAction {
    fn default() -> Self {
        FileAction::Created
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Display, EnumString, IntoStaticStr)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Any,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Tcp
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Display, EnumString, IntoStaticStr)]
pub enum RegistryAction {
    Created,
    Modified,
    Deleted,
}

impl Default for RegistryAction {
    fn default() -> Self {
        RegistryAction::Created
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Display, EnumString, IntoStaticStr)]
pub enum ServiceStatus {
    Running,
    Stopped,
    Paused,
    StartPending,
    StopPending,
}

impl Default for ServiceStatus {
    fn default() -> Self {
        ServiceStatus::Stopped
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Display, EnumString, IntoStaticStr)]
pub enum ServiceAction {
    Created,
    Started,
    Stopped,
    Deleted,
    Modified,
}

impl Default for ServiceAction {
    fn default() -> Self {
        ServiceAction::Created
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Display, EnumString, IntoStaticStr)]
pub enum MemoryProtection {
    NoAccess,
    ReadOnly,
    ReadWrite,
    ReadExecute,
    ReadWriteExecute,
    ExecuteWriteCopy,
}

impl Default for MemoryProtection {
    fn default() -> Self {
        MemoryProtection::NoAccess
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Display, EnumString, IntoStaticStr)]
pub enum ThreadAction {
    Created,
    RemoteCreated,
    Suspended,
    Resumed,
    Terminated,
}

impl Default for ThreadAction {
    fn default() -> Self {
        ThreadAction::Created
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Display, EnumString, IntoStaticStr)]
pub enum ThreatStatus {
    Active,
    Investigating,
    Contained,
    Eradicated,
    Recovered,
    FalsePositive,
}

impl Default for ThreatStatus {
    fn default() -> Self {
        ThreatStatus::Active
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Display, EnumString, IntoStaticStr)]
pub enum ModuleStatus {
    Uninitialized,
    Initializing,
    Initialized,
    Running,
    Degraded,
    Stopped,
    Failed,
    Recovering,
}

impl Default for ModuleStatus {
    fn default() -> Self {
        ModuleStatus::Uninitialized
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConfigValue {
    String(String),
    Bool(bool),
    Integer(i64),
    Float(f64),
    Array(Vec<ConfigValue>),
    Object(HashMap<String, ConfigValue>),
}

impl Default for ConfigValue {
    fn default() -> Self {
        ConfigValue::String(String::new())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub command_line: String,
    pub user: String,
    pub hash_sha256: Option<String>,
    pub integrity_level: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileEvent {
    pub path: String,
    pub original_path: Option<String>,
    pub action: FileAction,
    pub hash_sha256: Option<String>,
    pub size: Option<u64>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkEvent {
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsEvent {
    pub query: String,
    pub query_type: String,
    pub response: Option<String>,
    pub response_code: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryEvent {
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub action: RegistryAction,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceEvent {
    pub name: String,
    pub display_name: Option<String>,
    pub status: ServiceStatus,
    pub action: ServiceAction,
    pub image_path: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryEvent {
    pub process_id: u32,
    pub base_address: u64,
    pub region_size: u64,
    pub protection: MemoryProtection,
    pub allocation_type: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreadEvent {
    pub process_id: u32,
    pub thread_id: u32,
    pub start_address: u64,
    pub action: ThreadAction,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEvent {
    Process(ProcessInfo),
    File(FileEvent),
    Network(NetworkEvent),
    Dns(DnsEvent),
    Registry(RegistryEvent),
    Service(ServiceEvent),
    Memory(MemoryEvent),
    Thread(ThreadEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventEnvelope {
    pub id: Uuid,
    pub severity: EventSeverity,
    pub event_type: EventType,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub raw: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
    pub payload: SecurityEvent,
}

impl Default for SecurityEventEnvelope {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            severity: EventSeverity::default(),
            event_type: EventType::default(),
            timestamp: Utc::now(),
            source: String::new(),
            raw: None,
            details: HashMap::new(),
            payload: SecurityEvent::Process(ProcessInfo::default()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatInfo {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub severity: EventSeverity,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub iocs: Vec<String>,
    pub affected_hosts: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub status: ThreatStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModuleHealth {
    pub status: ModuleStatus,
    pub last_heartbeat: DateTime<Utc>,
    pub error_count: u64,
    pub events_processed: u64,
    pub events_per_second: f64,
    pub memory_usage_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub actor: String,
    pub target: String,
    pub details: HashMap<String, serde_json::Value>,
    pub previous_hash: String,
    pub current_hash: String,
    pub sequence: u64,
}
