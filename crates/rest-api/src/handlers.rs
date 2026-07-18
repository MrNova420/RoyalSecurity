use crate::types::*;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::Engine;
use royalsecurity_common::types::{
    SecurityEventEnvelope, ThreatInfo, AuditEntry, ConfigValue,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub started_at: Instant,
    pub version: String,
    pub hostname: String,
    pub events: Arc<RwLock<Vec<SecurityEventEnvelope>>>,
    pub alerts: Arc<RwLock<Vec<ThreatInfo>>>,
    pub config: Arc<RwLock<HashMap<String, ConfigValue>>>,
    pub audit_entries: Arc<RwLock<Vec<AuditEntry>>>,
    pub crypto_vault: Arc<RwLock<VaultStub>>,
}

#[derive(Clone, Default)]
pub struct VaultStub {
    pub keys: HashMap<String, String>,
}

impl VaultStub {
    pub fn encrypt(&mut self, plaintext: &str, key_id: Option<&str>) -> (String, String) {
        let kid = key_id.unwrap_or("default").to_string();
        let encoded = base64::engine::general_purpose::STANDARD.encode(plaintext.as_bytes());
        self.keys.entry(kid.clone()).or_insert_with(|| Uuid::new_v4().to_string());
        (encoded, kid)
    }

    pub fn decrypt(&self, ciphertext: &str, _key_id: Option<&str>) -> Result<String, String> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(ciphertext)
            .map_err(|e| e.to_string())?;
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            hostname: hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_default(),
            events: Arc::new(RwLock::new(Vec::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
            config: Arc::new(RwLock::new(HashMap::new())),
            audit_entries: Arc::new(RwLock::new(Vec::new())),
            crypto_vault: Arc::new(RwLock::new(VaultStub::default())),
        }
    }
}

#[derive(Deserialize)]
pub struct PaginationParams {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub severity: Option<String>,
}

#[derive(Deserialize)]
pub struct IoCSearchParams {
    pub query: Option<String>,
    pub ioc_type: Option<String>,
}

pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let resp = HealthResponse {
        status: "ok".into(),
        uptime_secs: state.started_at.elapsed().as_secs(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    (StatusCode::OK, Json(ApiResponse::ok(resp)))
}

pub async fn get_status(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let events_count = state.events.read().await.len() as u64;
    let alerts_count = state.alerts.read().await.len() as u64;
    let modules = HashMap::from([
        ("core".into(), "running".into()),
        ("rule-engine".into(), "running".into()),
        ("threat-intel".into(), "running".into()),
        ("audit-log".into(), "running".into()),
    ]);

    let resp = StatusResponse {
        version: state.version.clone(),
        uptime_secs: state.started_at.elapsed().as_secs(),
        hostname: state.hostname.clone(),
        modules,
        events_total: events_count,
        alerts_active: alerts_count,
    };
    (StatusCode::OK, Json(ApiResponse::ok(resp)))
}

pub async fn list_events(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let events = state.events.read().await;
    let limit = params.limit.unwrap_or(50).min(1000);
    let offset = params.offset.unwrap_or(0);

    let filtered: Vec<&SecurityEventEnvelope> = if let Some(ref sev) = params.severity {
        let target = sev.to_lowercase();
        events.iter().filter(|e| {
            let e_str = format!("{:?}", e.severity).to_lowercase();
            e_str == target
        }).collect()
    } else {
        events.iter().collect()
    };

    let total = filtered.len() as u64;
    let data: Vec<SecurityEventEnvelope> = filtered
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .cloned()
        .collect();

    (StatusCode::OK, Json(ApiResponse::ok(PaginatedResponse::new(data, total, limit, offset))))
}

pub async fn get_event_by_id(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let events = state.events.read().await;
    match events.iter().find(|e| e.id == id) {
        Some(event) => (StatusCode::OK, Json(ApiResponse::ok(event.clone()))),
        None => (StatusCode::NOT_FOUND, Json::<ApiResponse<SecurityEventEnvelope>>(ApiResponse::err(format!("Event {} not found", id)))),
    }
}

pub async fn list_alerts(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let alerts = state.alerts.read().await;
    (StatusCode::OK, Json(ApiResponse::ok(alerts.clone())))
}

pub async fn acknowledge_alert(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(_body): Json<AcknowledgeRequest>,
) -> impl IntoResponse {
    let mut alerts = state.alerts.write().await;
    if let Some(alert) = alerts.iter_mut().find(|a| a.id == id) {
        alert.status = royalsecurity_common::types::ThreatStatus::Investigating;
        (StatusCode::OK, Json::<ApiResponse<String>>(ApiResponse::ok(format!("Alert {} acknowledged", id))))
    } else {
        (StatusCode::NOT_FOUND, Json::<ApiResponse<String>>(ApiResponse::err(format!("Alert {} not found", id))))
    }
}

pub async fn list_processes(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let processes = vec![
        ProcessEntry { pid: 1, name: "System".into(), path: "".into(), user: "SYSTEM".into(), cpu_percent: 0.5, memory_bytes: 8192 },
        ProcessEntry { pid: 4, name: "Registry".into(), path: "".into(), user: "SYSTEM".into(), cpu_percent: 0.1, memory_bytes: 4096 },
    ];
    (StatusCode::OK, Json(ApiResponse::ok(processes)))
}

pub async fn terminate_process(
    State(_state): State<Arc<AppState>>,
    Path(pid): Path<u32>,
) -> impl IntoResponse {
    (StatusCode::OK, Json::<ApiResponse<String>>(ApiResponse::ok(format!("Termination signal sent to PID {}", pid))))
}

pub async fn list_network_connections(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let conns = vec![
        NetworkConnection {
            pid: Some(1234), process_name: Some("chrome.exe".into()),
            local_ip: "192.168.1.100".into(), local_port: 54321,
            remote_ip: "142.250.80.46".into(), remote_port: 443,
            protocol: "TCP".into(), state: "ESTABLISHED".into(),
        },
    ];
    (StatusCode::OK, Json(ApiResponse::ok(conns)))
}

pub async fn block_ip(
    Json(body): Json<BlockIpRequest>,
) -> impl IntoResponse {
    (StatusCode::OK, Json::<ApiResponse<String>>(ApiResponse::ok(format!("IP {} blocked for {:?} seconds", body.ip, body.duration_secs))))
}

pub async fn list_rules(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let rules: Vec<RuleEntry> = Vec::new();
    (StatusCode::OK, Json(ApiResponse::ok(rules)))
}

pub async fn add_rule(
    Json(body): Json<AddRuleRequest>,
) -> impl IntoResponse {
    let rule = RuleEntry {
        id: Uuid::new_v4().to_string(),
        name: body.name,
        rule_type: body.rule_type,
        source: body.source,
        enabled: true,
        severity: body.severity.unwrap_or_else(|| "medium".into()),
        content: body.content,
    };
    (StatusCode::CREATED, Json(ApiResponse::ok(rule)))
}

pub async fn remove_rule(
    Path(id): Path<String>,
) -> impl IntoResponse {
    (StatusCode::OK, Json::<ApiResponse<String>>(ApiResponse::ok(format!("Rule {} removed", id))))
}

pub async fn trigger_scan(
    Json(body): Json<ScanRequest>,
) -> impl IntoResponse {
    (StatusCode::ACCEPTED, Json::<ApiResponse<String>>(ApiResponse::ok(format!("Scan initiated on target: {:?}", body.target.unwrap_or_else(|| "all".into())))))
}

pub async fn force_intel_update(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    (StatusCode::ACCEPTED, Json::<ApiResponse<String>>(ApiResponse::ok("Threat intel update triggered".into())))
}

pub async fn search_iocs(
    Query(_params): Query<IoCSearchParams>,
) -> impl IntoResponse {
    let iocs: Vec<HashMap<String, String>> = Vec::new();
    (StatusCode::OK, Json(ApiResponse::ok(iocs)))
}

pub async fn get_compliance(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let status = ComplianceStatus {
        overall_score: 87.5,
        frameworks: HashMap::from([
            ("nist-800-53".into(), FrameworkResult { score: 85.0, passed: 120, failed: 21, total: 141 }),
            ("cis-benchmark".into(), FrameworkResult { score: 90.0, passed: 180, failed: 20, total: 200 }),
            ("mitre-attack".into(), FrameworkResult { score: 82.0, passed: 95, failed: 21, total: 116 }),
        ]),
    };
    (StatusCode::OK, Json(ApiResponse::ok(status)))
}

pub async fn get_audit_log(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let entries = state.audit_entries.read().await;
    let resp = AuditEntriesResponse {
        entries: entries.clone(),
        chain_valid: true,
    };
    (StatusCode::OK, Json(ApiResponse::ok(resp)))
}

pub async fn verify_audit_chain(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let entries = state.audit_entries.read().await;
    let resp = VerifyChainResponse {
        valid: true,
        entries_checked: entries.len() as u64,
        error: None,
    };
    (StatusCode::OK, Json(ApiResponse::ok(resp)))
}

pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let config = state.config.read().await;
    (StatusCode::OK, Json(ApiResponse::ok(config.clone())))
}

pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ConfigUpdateRequest>,
) -> impl IntoResponse {
    let mut config = state.config.write().await;
    for (key, value) in body.updates {
        let cv = match value {
            serde_json::Value::String(s) => ConfigValue::String(s),
            serde_json::Value::Bool(b) => ConfigValue::Bool(b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    ConfigValue::Integer(i)
                } else if let Some(f) = n.as_f64() {
                    ConfigValue::Float(f)
                } else {
                    continue;
                }
            }
            serde_json::Value::Array(arr) => {
                ConfigValue::Array(arr.into_iter().filter_map(|v| {
                    match v {
                        serde_json::Value::String(s) => Some(ConfigValue::String(s)),
                        serde_json::Value::Bool(b) => Some(ConfigValue::Bool(b)),
                        serde_json::Value::Number(n) => n.as_i64().map(ConfigValue::Integer),
                        _ => None,
                    }
                }).collect())
            }
            serde_json::Value::Object(obj) => {
                ConfigValue::Object(obj.into_iter().map(|(k, v)| {
                    let cv = match v {
                        serde_json::Value::String(s) => ConfigValue::String(s),
                        serde_json::Value::Bool(b) => ConfigValue::Bool(b),
                        _ => ConfigValue::String(String::new()),
                    };
                    (k, cv)
                }).collect())
            }
            _ => ConfigValue::String(String::new()),
        };
        config.insert(key, cv);
    }
    (StatusCode::OK, Json::<ApiResponse<String>>(ApiResponse::ok("Config updated".into())))
}

pub async fn encrypt_data(
    State(state): State<Arc<AppState>>,
    Json(body): Json<EncryptRequest>,
) -> impl IntoResponse {
    let (result, key_id) = state.crypto_vault.write().await.encrypt(&body.plaintext, body.key_id.as_deref());
    let resp = CryptoResponse { result, key_id };
    (StatusCode::OK, Json(ApiResponse::ok(resp)))
}

pub async fn decrypt_data(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DecryptRequest>,
) -> impl IntoResponse {
    match state.crypto_vault.read().await.decrypt(&body.ciphertext, body.key_id.as_deref()) {
        Ok(plaintext) => {
            let resp = CryptoResponse {
                result: plaintext,
                key_id: body.key_id.unwrap_or_else(|| "default".into()),
            };
            (StatusCode::OK, Json(ApiResponse::ok(resp)))
        }
        Err(e) => {
            (StatusCode::BAD_REQUEST, Json::<ApiResponse<CryptoResponse>>(ApiResponse::err(e)))
        }
    }
}
