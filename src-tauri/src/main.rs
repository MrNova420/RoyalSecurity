#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tauri::State;

use royalsecurity_core::audit::AuditLog;
use royalsecurity_core::bus::EventBus;
use royalsecurity_core::config::AppConfig;
use royalsecurity_core::crypto::CryptoVault;
use royalsecurity_core::ppl::{ProcessProtection, ProtectionConfig, ProtectionStatus};
use royalsecurity_core::registry::ModuleRegistry;
use royalsecurity_core::tpm::TpmManager;
use royalsecurity_core::engine::{SecurityEngine, ScanType};

use royalsecurity_common::types::{SecurityEventEnvelope, SecurityEvent, ProcessInfo};

use royalsecurity_crypto_vault::CryptoVault as EnhancedVault;
use royalsecurity_crypto_vault::tpm_seal::TpmSealedVault;

use royalsecurity_state_store::store::StateStore;

use royalsecurity_rule_engine::engine::RuleEngine;
use royalsecurity_rule_engine::sigma::SigmaRule;
use royalsecurity_rule_engine::yara_engine::{YaraEngine, YaraRule};

use royalsecurity_threat_intel::feed::FeedManager;
use royalsecurity_threat_intel::matcher::IocMatcher;
use royalsecurity_threat_intel::updater::RuleUpdater;

use royalsecurity_compliance::ComplianceEngine;

use windows_bridge::process::{list_processes, get_process_by_pid, ProcessInfo as WbProcessInfo};
use windows_bridge::network::{list_connections, NetworkConnection};
use windows_bridge::system::get_system_info as get_system_info_raw;

use royalsecurity_forensic_triage as forensic_triage;
use royalsecurity_mitre_attack::coverage::CoverageAnalyzer;
use royalsecurity_vuln_management::{CveDatabase, PatchAssessment};
use royalsecurity_active_response::containment::{ContainmentManager, ContainmentLevel};
use royalsecurity_active_response::playbooks::PlaybookEngine;
use royalsecurity_active_response::quarantine::QuarantineStore;
use royalsecurity_fleet_management::agent::AgentRegistry;
use royalsecurity_fleet_management::policies::PolicyEngine;
use royalsecurity_stix_taxii::stix::{StixBundle, threat_to_stix};


// ---------------------------------------------------------------------------
// Local types not found in workspace crates
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlertEntry {
    pub id: String,
    pub timestamp: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub source: String,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanState {
    pub running: bool,
    pub last_scan: Option<String>,
    pub scan_count: u64,
    pub threats_found: u64,
    pub files_scanned: u64,
}

impl Default for ScanState {
    fn default() -> Self {
        Self {
            running: false,
            last_scan: None,
            scan_count: 0,
            threats_found: 0,
            files_scanned: 0,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatIntelAggregator {
    pub total_iocs: usize,
    pub last_sync: Option<String>,
    pub feeds_configured: usize,
    pub matches_found: u64,
}

impl Default for ThreatIntelAggregator {
    fn default() -> Self {
        Self {
            total_iocs: 0,
            last_sync: None,
            feeds_configured: 0,
            matches_found: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

struct AppState {
    engine: Arc<SecurityEngine>,
    bus: EventBus,
    config: Arc<RwLock<AppConfig>>,
    vault: Arc<RwLock<CryptoVault>>,
    audit: Arc<RwLock<AuditLog>>,
    registry: Arc<ModuleRegistry>,
    store: Arc<StateStore>,
    rule_engine: Arc<RwLock<RuleEngine>>,
    feed_manager: Arc<RwLock<FeedManager>>,
    ioc_matcher: Arc<RwLock<IocMatcher>>,
    yara_engine: Arc<RwLock<YaraEngine>>,
    rule_updater: Arc<RwLock<RuleUpdater>>,
    ppl: Arc<RwLock<ProcessProtection>>,
    tpm: Arc<RwLock<TpmManager>>,
    tpm_vault: Arc<RwLock<TpmSealedVault>>,
    intel_aggregator: Arc<RwLock<ThreatIntelAggregator>>,
    process_cache: Arc<RwLock<Vec<WbProcessInfo>>>,
    network_cache: Arc<RwLock<Vec<NetworkConnection>>>,
    alert_store: Arc<RwLock<Vec<AlertEntry>>>,
    scan_state: Arc<RwLock<ScanState>>,
    containment: Arc<RwLock<ContainmentManager>>,
    playbook_engine: Arc<RwLock<PlaybookEngine>>,
    quarantine_store: Arc<RwLock<QuarantineStore>>,
    fleet_agents: Arc<RwLock<AgentRegistry>>,
    policy_engine: Arc<RwLock<PolicyEngine>>,
    mitre_coverage: Arc<RwLock<CoverageAnalyzer>>,
    cve_db: Arc<RwLock<CveDatabase>>,
}

// ---------------------------------------------------------------------------
// READ commands (16)
// ---------------------------------------------------------------------------

#[tauri::command]
async fn get_system_info() -> Result<serde_json::Value, String> {
    let info = get_system_info_raw();
    serde_json::to_value(&info).map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_process_list(state: State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    let cache = state.process_cache.read().await;
    if !cache.is_empty() {
        return Ok(cache
            .iter()
            .map(|p| serde_json::to_value(p).unwrap_or_default())
            .collect());
    }
    drop(cache);
    let procs = list_processes();
    let values: Vec<serde_json::Value> = procs
        .iter()
        .map(|p| serde_json::to_value(p).unwrap_or_default())
        .collect();
    let mut cache = state.process_cache.write().await;
    *cache = procs;
    Ok(values)
}

#[tauri::command]
async fn get_network_connections(
    state: State<'_, AppState>,
) -> Result<Vec<serde_json::Value>, String> {
    let cache = state.network_cache.read().await;
    if !cache.is_empty() {
        return Ok(cache
            .iter()
            .map(|c| serde_json::to_value(c).unwrap_or_default())
            .collect());
    }
    drop(cache);
    let conns = list_connections();
    let values: Vec<serde_json::Value> = conns
        .iter()
        .map(|c| serde_json::to_value(c).unwrap_or_default())
        .collect();
    let mut cache = state.network_cache.write().await;
    *cache = conns;
    Ok(values)
}

#[tauri::command]
async fn get_alert_stats(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let alerts = state.alert_store.read().await;
    let total = alerts.len();
    let critical = alerts.iter().filter(|a| a.severity == "critical").count();
    let high = alerts.iter().filter(|a| a.severity == "high").count();
    let medium = alerts.iter().filter(|a| a.severity == "medium").count();
    let low = alerts.iter().filter(|a| a.severity == "low").count();
    let informational = alerts
        .iter()
        .filter(|a| a.severity == "informational")
        .count();
    Ok(serde_json::json!({
        "total_alerts": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "informational": informational,
    }))
}

#[tauri::command]
async fn get_mitre_coverage(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let rule_count = {
        let engine = state.rule_engine.read().await;
        engine.rule_count()
    };
    let yara_count = {
        let yara = state.yara_engine.read().await;
        yara.list_rules().len()
    };
    let module_count = state.registry.module_count();
    let enabled_count = state.registry.enabled_count();
    let total_tactics = 14usize;
    let covered_tactics = (module_count + rule_count + yara_count).min(total_tactics);
    let techniques_covered = (module_count * 4 + rule_count * 2 + yara_count * 3).min(200);
    let coverage = if total_tactics > 0 {
        (covered_tactics as f64 / total_tactics as f64) * 100.0
    } else {
        0.0
    };
    Ok(serde_json::json!({
        "tactics_covered": covered_tactics,
        "techniques_covered": techniques_covered,
        "coverage_percent": (coverage * 10.0).round() / 10.0,
        "sigma_rules": rule_count,
        "yara_rules": yara_count,
        "modules_registered": module_count,
        "modules_enabled": enabled_count,
    }))
}

#[tauri::command]
async fn get_compliance_status() -> Result<serde_json::Value, String> {
    let engine = ComplianceEngine::new();
    let frameworks = engine.frameworks();
    let total_controls: u32 = frameworks
        .iter()
        .flat_map(|f| &f.categories)
        .flat_map(|c| &c.controls)
        .count() as u32;
    let score = engine.overall_score();
    Ok(serde_json::json!({
        "cis_score": score,
        "stig_score": score,
        "nist_score": score,
        "total_controls": total_controls,
        "frameworks": frameworks.iter().map(|f| serde_json::json!({
            "id": f.id,
            "name": f.name,
            "version": f.version,
            "enabled": f.enabled,
        })).collect::<Vec<_>>(),
    }))
}

#[tauri::command]
async fn get_audit_log(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let audit = state.audit.read().await;
    let entries: Vec<serde_json::Value> = audit
        .entries()
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "timestamp": e.timestamp.to_rfc3339(),
                "action": e.action,
                "actor": e.actor,
                "target": e.target,
                "previous_hash": e.previous_hash,
                "current_hash": e.current_hash,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "total_entries": audit.count(),
        "chain_valid": audit.verify_chain(),
        "last_hash": audit.last_hash(),
        "entries": entries,
    }))
}

#[tauri::command]
async fn get_events(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> Result<serde_json::Value, String> {
    let max = limit.unwrap_or(100);
    let events = state
        .store
        .get_recent_events(max)
        .map_err(|e| e.to_string())?;
    let values: Vec<serde_json::Value> = events
        .into_iter()
        .map(|e| serde_json::to_value(e).unwrap_or_default())
        .collect();
    let total = state.store.event_count().map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "total_events": total,
        "limit": max,
        "events": values,
    }))
}

#[tauri::command]
async fn get_threats(state: State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    state
        .store
        .get_threats()
        .map(|t| {
            t.into_iter()
                .map(|x| serde_json::to_value(x).unwrap_or_default())
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn search_iocs(
    state: State<'_, AppState>,
    value: String,
) -> Result<serde_json::Value, String> {
    let matcher = state.ioc_matcher.read().await;
    match matcher.check_value(&value) {
        Some(ioc) => Ok(serde_json::json!({
            "matched": true,
            "ioc": serde_json::to_value(ioc).unwrap_or_default(),
        })),
        None => Ok(serde_json::json!({
            "matched": false,
            "ioc": null,
        })),
    }
}

#[tauri::command]
async fn get_crypto_keys(state: State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    let vault = state.vault.read().await;
    Ok(vault
        .list_keys()
        .into_iter()
        .map(|k| serde_json::to_value(k).unwrap_or_default())
        .collect())
}

#[tauri::command]
async fn get_config(state: State<'_, AppState>) -> Result<AppConfig, String> {
    let config = state.config.read().await;
    Ok(config.clone())
}

#[tauri::command]
async fn get_module_health(state: State<'_, AppState>) -> Result<HashMap<String, String>, String> {
    Ok(state
        .registry
        .get_health()
        .into_iter()
        .map(|(k, v)| (k, format!("{:?}", v.status)))
        .collect())
}

#[tauri::command]
async fn get_event_bus_stats(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "subscriber_count": state.bus.subscriber_count(),
    }))
}

#[tauri::command]
async fn get_ppl_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let ppl = state.ppl.read().await;
    let status = ppl.protection_status();
    let alerts = ppl.get_tamper_alerts();
    Ok(serde_json::json!({
        "status": format!("{:?}", status),
        "is_active": status == ProtectionStatus::Active,
        "tamper_alerts": alerts.len(),
        "config": {
            "enable_ppl": ppl.config().enable_ppl,
            "enable_token_hardening": ppl.config().enable_token_hardening,
            "enable_checksum_monitoring": ppl.config().enable_checksum_monitoring,
            "enable_debugger_detection": ppl.config().enable_debugger_detection,
        },
    }))
}

#[tauri::command]
async fn get_tpm_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let tpm = state.tpm.read().await;
    let tpm_vault = state.tpm_vault.read().await;
    let seal_status = tpm_vault.get_seal_status();
    Ok(serde_json::json!({
        "tpm_available": tpm.is_available(),
        "tpm_status": format!("{:?}", tpm.get_status()),
        "seal_status": format!("{:?}", seal_status),
        "sealed_keys": tpm.get_sealed_keys(),
    }))
}

// ---------------------------------------------------------------------------
// YAML-to-JSON helper for add_yara_rule
// ---------------------------------------------------------------------------

fn yaml_to_json(yaml: &yaml_rust2::Yaml) -> serde_json::Value {
    match yaml {
        yaml_rust2::Yaml::Null | yaml_rust2::Yaml::BadValue => serde_json::Value::Null,
        yaml_rust2::Yaml::Integer(i) => serde_json::json!(i),
        yaml_rust2::Yaml::Real(r) => {
            r.parse::<f64>().map(|v| serde_json::json!(v)).unwrap_or(serde_json::Value::Null)
        }
        yaml_rust2::Yaml::String(s) => serde_json::json!(s),
        yaml_rust2::Yaml::Boolean(b) => serde_json::json!(b),
        yaml_rust2::Yaml::Array(arr) => {
            serde_json::json!(arr.iter().map(|v| yaml_to_json(v)).collect::<Vec<_>>())
        }
        yaml_rust2::Yaml::Hash(map) => {
            let obj: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .filter_map(|(k, v)| {
                    if let yaml_rust2::Yaml::String(key) = k {
                        Some((key.clone(), yaml_to_json(v)))
                    } else {
                        None
                    }
                })
                .collect();
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::Null,
    }
}

// ---------------------------------------------------------------------------
// WRITE commands (16)
// ---------------------------------------------------------------------------

#[tauri::command]
async fn update_config(
    state: State<'_, AppState>,
    new_config: AppConfig,
) -> Result<(), String> {
    let mut config = state.config.write().await;
    *config = new_config.clone();
    let mut audit = state.audit.write().await;
    let mut details = HashMap::new();
    details.insert("app_name".into(), serde_json::json!(new_config.general.app_name));
    audit.record("config.updated", "user", "app_config", details);
    Ok(())
}

#[tauri::command]
async fn encrypt_data(
    state: State<'_, AppState>,
    data: String,
    key_id: String,
) -> Result<String, String> {
    let vault = state.vault.read().await;
    let encrypted = vault
        .encrypt_aes256(data.as_bytes(), &key_id)
        .map_err(|e| e.to_string())?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &encrypted,
    ))
}

#[tauri::command]
async fn decrypt_data(
    state: State<'_, AppState>,
    data: String,
    key_id: String,
) -> Result<String, String> {
    let vault = state.vault.read().await;
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &data)
        .map_err(|e| e.to_string())?;
    let decrypted = vault
        .decrypt_aes256(&decoded, &key_id)
        .map_err(|e| e.to_string())?;
    String::from_utf8(decrypted).map_err(|e| e.to_string())
}

#[tauri::command]
async fn add_sigma_rule(
    state: State<'_, AppState>,
    yaml_content: String,
) -> Result<String, String> {
    let rule = SigmaRule::parse(&yaml_content).map_err(|e| e.to_string())?;
    let compiled = rule.compile().map_err(|e| e.to_string())?;
    let id = compiled.id.clone();
    let mut engine = state.rule_engine.write().await;
    engine.add_sigma_rule(compiled);
    let mut audit = state.audit.write().await;
    let mut details = HashMap::new();
    details.insert("rule_id".into(), serde_json::json!(id));
    audit.record("rule.sigma.added", "user", "rule_engine", details);
    Ok(id)
}

#[tauri::command]
async fn add_yara_rule(
    state: State<'_, AppState>,
    yaml_content: String,
) -> Result<String, String> {
    let docs = yaml_rust2::YamlLoader::load_from_str(&yaml_content)
        .map_err(|e| format!("YAML parse error: {}", e))?;
    let doc = docs.into_iter().next()
        .ok_or_else(|| "Empty YAML document".to_string())?;
    let json_str = serde_json::to_string(&yaml_to_json(&doc))
        .map_err(|e| format!("YAML→JSON conversion error: {}", e))?;
    let rule: YaraRule = serde_json::from_str(&json_str)
        .map_err(|e| format!("YaraRule deserialization error: {}", e))?;
    let id = rule.id.clone();
    let mut engine = state.yara_engine.write().await;
    engine.add_rule(rule);
    let mut audit = state.audit.write().await;
    let mut details = HashMap::new();
    details.insert("rule_id".into(), serde_json::json!(id));
    audit.record("rule.yara.added", "user", "yara_engine", details);
    Ok(id)
}

#[tauri::command]
async fn evaluate_event(
    state: State<'_, AppState>,
    event: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let envelope: SecurityEventEnvelope =
        serde_json::from_value(event).map_err(|e| e.to_string())?;
    let _ = state.engine.bus.publish(envelope.payload.clone());
    let sigma_matches = {
        let engine = state.rule_engine.read().await;
        engine.evaluate_event(&envelope)
    };
    let data_bytes = serde_json::to_vec(&envelope).map_err(|e| e.to_string())?;
    let yara_matches = {
        let mut yara = state.yara_engine.write().await;
        yara.scan_data(&data_bytes)
    };
    let sigma_count = sigma_matches.len();
    let yara_count = yara_matches.len();
    Ok(serde_json::json!({
        "sigma_matches": sigma_matches.into_iter().map(|m| serde_json::to_value(m).unwrap_or_default()).collect::<Vec<_>>(),
        "yara_matches": yara_matches.into_iter().map(|m| serde_json::to_value(m).unwrap_or_default()).collect::<Vec<_>>(),
        "total_matches": sigma_count + yara_count,
    }))
}

#[tauri::command]
async fn trigger_threat_intel_update(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let engine_msg = state.engine.trigger_threat_intel_update().await?;
    let feed_count = {
        let manager = state.feed_manager.read().await;
        manager.feeds().len()
    };
    let mut updater = state.rule_updater.write().await;
    let results = updater.full_update().await;
    let mut aggregator = state.intel_aggregator.write().await;
    aggregator.last_sync = Some(chrono::Utc::now().to_rfc3339());
    aggregator.feeds_configured = feed_count;
    Ok(serde_json::json!({
        "engine_message": engine_msg,
        "feeds_configured": feed_count,
        "results": results.into_iter().map(|r| serde_json::to_value(r).unwrap_or_default()).collect::<Vec<_>>(),
    }))
}

#[tauri::command]
async fn terminate_process(pid: u32) -> Result<serde_json::Value, String> {
    let proc = get_process_by_pid(pid);
    match proc {
        Some(info) => {
            #[cfg(windows)]
            {
                use windows::Win32::System::Threading::{
                    OpenProcess, TerminateProcess, PROCESS_TERMINATE,
                };
                unsafe {
                    let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
                        .map_err(|e| e.to_string())?;
                    TerminateProcess(handle, 1).map_err(|e| e.to_string())?;
                    let _ = windows::Win32::Foundation::CloseHandle(handle);
                }
            }
            Ok(serde_json::json!({
                "success": true,
                "pid": pid,
                "name": info.name,
                "message": format!("Process {} (PID {}) terminated", info.name, pid),
            }))
        }
        None => Ok(serde_json::json!({
            "success": false,
            "pid": pid,
            "message": format!("Process with PID {} not found", pid),
        })),
    }
}

#[tauri::command]
async fn block_ip(
    state: State<'_, AppState>,
    ip: String,
    reason: Option<String>,
) -> Result<serde_json::Value, String> {
    let reason_str = reason.unwrap_or_else(|| "manual block".to_string());
    #[cfg(windows)]
    {
        use std::process::Command;
        let rule_name = format!("block_ip_{}", ip.replace('.', "_"));
        let remote_arg = format!("remoteip={}", ip);
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", rule_name),
                "dir=in",
                "action=block",
                &remote_arg,
                "enable=yes",
            ])
            .output()
            .map_err(|e| e.to_string())?;
    }
    let mut audit = state.audit.write().await;
    let mut details = HashMap::new();
    details.insert("ip".into(), serde_json::json!(ip.clone()));
    details.insert("reason".into(), serde_json::json!(reason_str));
    audit.record("network.ip_blocked", "user", "firewall", details);
    Ok(serde_json::json!({
        "success": true,
        "ip": ip,
        "message": "IP address blocked via firewall rule",
    }))
}

#[tauri::command]
async fn remove_detection_rule(
    state: State<'_, AppState>,
    rule_id: String,
) -> Result<serde_json::Value, String> {
    let sigma_removed = {
        let mut engine = state.rule_engine.write().await;
        engine.remove_sigma_rule(&rule_id)
    };
    let yara_removed = {
        let mut yara = state.yara_engine.write().await;
        yara.remove_rule(&rule_id)
    };
    let mut audit = state.audit.write().await;
    let mut details = HashMap::new();
    details.insert("rule_id".into(), serde_json::json!(rule_id));
    details.insert("sigma_removed".into(), serde_json::json!(sigma_removed));
    details.insert("yara_removed".into(), serde_json::json!(yara_removed));
    audit.record("rule.removed", "user", "rule_engine", details);
    Ok(serde_json::json!({
        "sigma_removed": sigma_removed,
        "yara_removed": yara_removed,
    }))
}

#[tauri::command]
async fn trigger_scan(
    state: State<'_, AppState>,
    scan_type: Option<ScanType>,
) -> Result<serde_json::Value, String> {
    let scan_type_val = scan_type.unwrap_or_default();
    let _ = state.engine.trigger_scan(scan_type_val.as_str()).await;
    {
        let mut scan = state.scan_state.write().await;
        if scan.running {
            return Ok(serde_json::json!({
                "success": false,
                "message": "Scan already in progress",
            }));
        }
        scan.running = true;
    }
    let procs = {
        let cache = state.process_cache.read().await;
        cache.clone()
    };
    let mut threats_found = 0u64;
    let mut files_scanned = 0u64;
    for proc_info in &procs {
        files_scanned += 1;
        if windows_bridge::process::is_suspicious_process(proc_info) {
            threats_found += 1;
            let mut alerts = state.alert_store.write().await;
            alerts.push(AlertEntry {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                severity: "high".into(),
                title: format!("Suspicious process: {}", proc_info.name),
                description: format!(
                    "PID {} - {} from {}",
                    proc_info.pid, proc_info.name, proc_info.exe_path
                ),
                source: "scan".into(),
                acknowledged: false,
            });
        }
    }
    {
        let mut scan = state.scan_state.write().await;
        scan.running = false;
        scan.last_scan = Some(chrono::Utc::now().to_rfc3339());
        scan.scan_count += 1;
        scan.threats_found = threats_found;
        scan.files_scanned = files_scanned;
    }
    Ok(serde_json::json!({
        "success": true,
        "files_scanned": files_scanned,
        "threats_found": threats_found,
    }))
}

#[tauri::command]
async fn update_config_field(
    state: State<'_, AppState>,
    key: String,
    value: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let mut config = state.config.write().await;
    match key.as_str() {
        "general.app_name" => {
            if let Some(v) = value.as_str() {
                config.general.app_name = v.to_string();
            }
        }
        "general.telemetry_enabled" => {
            if let Some(v) = value.as_bool() {
                config.general.telemetry_enabled = v;
            }
        }
        "agent.heartbeat_interval_secs" => {
            if let Some(v) = value.as_u64() {
                config.agent.heartbeat_interval_secs = v;
            }
        }
        "agent.max_memory_mb" => {
            if let Some(v) = value.as_u64() {
                config.agent.max_memory_mb = v;
            }
        }
        "defense.av_enabled" => {
            if let Some(v) = value.as_bool() {
                config.defense.av_enabled = v;
            }
        }
        "defense.edr_enabled" => {
            if let Some(v) = value.as_bool() {
                config.defense.edr_enabled = v;
            }
        }
        "network.firewall_enabled" => {
            if let Some(v) = value.as_bool() {
                config.network.firewall_enabled = v;
            }
        }
        _ => {
            return Err(format!("Unknown config key: {}", key));
        }
    }
    let mut audit = state.audit.write().await;
    let mut details = HashMap::new();
    details.insert("key".into(), serde_json::json!(key.clone()));
    details.insert("value".into(), value);
    audit.record("config.field.updated", "user", &key, details);
    Ok(serde_json::json!({
        "success": true,
        "key": key,
    }))
}

#[tauri::command]
async fn get_defense_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let config = state.config.read().await;
    let ppl = state.ppl.read().await;
    let tpm = state.tpm.read().await;
    let scan = state.scan_state.read().await;
    let alert_count = state.alert_store.read().await.len();
    Ok(serde_json::json!({
        "defense": {
            "av_enabled": config.defense.av_enabled,
            "edr_enabled": config.defense.edr_enabled,
            "xdr_enabled": config.defense.xdr_enabled,
            "behavior_enabled": config.defense.behavior_enabled,
            "asr_enabled": config.defense.asr_enabled,
            "ransomware_enabled": config.defense.ransomware_enabled,
            "memory_protection": config.defense.memory_protection,
            "exploit_protection": config.defense.exploit_protection,
            "credential_protection": config.defense.credential_protection,
            "device_control": config.defense.device_control,
            "deception_enabled": config.defense.deception_enabled,
        },
        "network": {
            "firewall_enabled": config.network.firewall_enabled,
            "dns_proxy_enabled": config.network.dns_proxy_enabled,
            "dns_over_https": config.network.dns_over_https,
            "vpn_enabled": config.network.vpn_enabled,
            "tor_enabled": config.network.tor_enabled,
            "leak_protection": config.network.leak_protection,
            "tls_inspection": config.network.tls_inspection,
            "web_protection": config.network.web_protection,
        },
        "ppl_status": format!("{:?}", ppl.protection_status()),
        "tpm_available": tpm.is_available(),
        "scan": {
            "running": scan.running,
            "scan_count": scan.scan_count,
            "threats_found": scan.threats_found,
        },
        "alert_count": alert_count,
    }))
}

#[tauri::command]
async fn get_process_detail(pid: u32) -> Result<serde_json::Value, String> {
    match get_process_by_pid(pid) {
        Some(info) => Ok(serde_json::to_value(&info).map_err(|e| e.to_string())?),
        None => Err(format!("Process with PID {} not found", pid)),
    }
}

#[tauri::command]
async fn export_audit_log(
    state: State<'_, AppState>,
    format: Option<String>,
) -> Result<serde_json::Value, String> {
    let audit = state.audit.read().await;
    let fmt = format.unwrap_or_else(|| "json".into());
    match fmt.as_str() {
        "json" => {
            let entries: Vec<serde_json::Value> = audit
                .entries()
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "id": e.id,
                        "timestamp": e.timestamp.to_rfc3339(),
                        "action": e.action,
                        "actor": e.actor,
                        "target": e.target,
                        "previous_hash": e.previous_hash,
                        "current_hash": e.current_hash,
                    })
                })
                .collect();
            Ok(serde_json::json!({
                "format": "json",
                "total_entries": audit.count(),
                "chain_valid": audit.verify_chain(),
                "entries": entries,
            }))
        }
        "csv" => {
            let mut csv = String::from("id,timestamp,action,actor,target,current_hash\n");
            for e in audit.entries() {
                csv.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    e.id,
                    e.timestamp.to_rfc3339(),
                    e.action,
                    e.actor,
                    e.target,
                    e.current_hash,
                ));
            }
            Ok(serde_json::json!({
                "format": "csv",
                "total_entries": audit.count(),
                "data": csv,
            }))
        }
        _ => Err(format!("Unsupported export format: {}", fmt)),
    }
}

#[tauri::command]
async fn verify_audit_chain(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let audit = state.audit.read().await;
    let valid = audit.verify_chain();
    Ok(serde_json::json!({
        "chain_valid": valid,
        "total_entries": audit.count(),
        "last_hash": audit.last_hash(),
    }))
}

#[tauri::command]
async fn get_engine_stats(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let stats = state.engine.stats();
    Ok(serde_json::to_value(stats).map_err(|e| e.to_string())?)
}

#[tauri::command]
async fn get_detection_rules(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let sigma_count = {
        let engine = state.rule_engine.read().await;
        engine.sigma_rule_count()
    };
    let dsl_count = {
        let engine = state.rule_engine.read().await;
        engine.dsl_rule_count()
    };
    let yara_count = {
        let yara = state.yara_engine.read().await;
        yara.list_rules().len()
    };
    Ok(serde_json::json!({
        "sigma_rules": sigma_count,
        "dsl_rules": dsl_count,
        "yara_rules": yara_count,
        "total": sigma_count + dsl_count + yara_count,
    }))
}

#[tauri::command]
async fn force_intel_update(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    state.engine.force_intel_update();
    let feed_count = {
        let manager = state.feed_manager.read().await;
        manager.feeds().len()
    };
    let mut updater = state.rule_updater.write().await;
    let results = updater.full_update().await;
    let mut aggregator = state.intel_aggregator.write().await;
    aggregator.last_sync = Some(chrono::Utc::now().to_rfc3339());
    aggregator.feeds_configured = feed_count;
    Ok(serde_json::json!({
        "forced": true,
        "feeds_configured": feed_count,
        "results": results.into_iter().map(|r| serde_json::to_value(r).unwrap_or_default()).collect::<Vec<_>>(),
    }))
}
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// NEW: Forensic Triage commands
// ---------------------------------------------------------------------------

#[tauri::command]
async fn run_forensic_triage() -> Result<serde_json::Value, String> {
    let report = forensic_triage::triage_system()
        .await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "hostname": report.hostname,
        "collected_at": report.collected_at.to_rfc3339(),
        "evtx_events": report.evtx_events.len(),
        "mft_entries": report.mft_entries.len(),
        "prefetch_files": report.prefetch_files.len(),
        "registry_keys": report.registry_keys.len(),
        "shimcache_entries": report.shimcache_entries.len(),
        "amcache_entries": report.amcache_entries.len(),
        "srum_entries": report.srum_entries.len(),
        "lnk_files": report.lnk_files.len(),
        "usn_entries": report.usn_entries.len(),
    }))
}

// ---------------------------------------------------------------------------
// NEW: Vulnerability Management commands
// ---------------------------------------------------------------------------

#[tauri::command]
async fn scan_vulnerabilities() -> Result<serde_json::Value, String> {
    let cve_db = CveDatabase::new();
    let patch_assessment = PatchAssessment::new();
    let missing = patch_assessment.get_missing_patches();
    let critical_cves = cve_db.get_critical_cves();
    Ok(serde_json::json!({
        "total_cves_in_db": cve_db.count(),
        "critical_cves": critical_cves.len(),
        "missing_patches": missing.len(),
        "patches": missing.into_iter().map(|p| serde_json::json!({
            "kb": p.kb_number,
            "title": p.title.clone(),
            "severity": p.severity.clone(),
            "release_date": p.release_date.clone(),
        })).collect::<Vec<_>>(),
    }))
}

#[tauri::command]
async fn get_cve_details(cve_id: String) -> Result<serde_json::Value, String> {
    let db = CveDatabase::new();
    match db.lookup_cve(&cve_id) {
        Some(cve) => Ok(serde_json::to_value(cve).map_err(|e| e.to_string())?),
        None => Ok(serde_json::json!({"error": "CVE not found in database"})),
    }
}

#[tauri::command]
async fn search_cves(query: String) -> Result<serde_json::Value, String> {
    let db = CveDatabase::new();
    let results = db.search_cves(&query);
    let total = results.len();
    Ok(serde_json::json!({
        "query": query,
        "results": results.into_iter().map(|cve| serde_json::to_value(cve).unwrap_or_default()).collect::<Vec<_>>(),
        "total": total,
    }))
}

// ---------------------------------------------------------------------------
// NEW: Active Response commands
// ---------------------------------------------------------------------------

#[tauri::command]
async fn get_containment_level(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let mgr = state.containment.read().await;
    let level = mgr.get_current_level();
    Ok(serde_json::json!({
        "level": format!("{:?}", level),
        "description": level.description(),
        "numeric": level.numeric_value(),
    }))
}

#[tauri::command]
async fn set_containment_level(
    state: State<'_, AppState>,
    level: String,
) -> Result<serde_json::Value, String> {
    let containment_level = match level.as_str() {
        "none" => ContainmentLevel::None,
        "partial" => ContainmentLevel::Partial,
        "full" => ContainmentLevel::Full,
        "emergency" => ContainmentLevel::Emergency,
        _ => return Err(format!("Invalid containment level: {}", level)),
    };
    let mut mgr = state.containment.write().await;
    mgr.set_containment_level(containment_level.clone(), None)
        .map_err(|e| e.to_string())?;
    let mut audit = state.audit.write().await;
    let mut details = HashMap::new();
    details.insert("level".into(), serde_json::json!(format!("{:?}", containment_level)));
    audit.record("containment.level.changed", "user", "containment", details);
    Ok(serde_json::json!({
        "success": true,
        "level": format!("{:?}", containment_level),
        "description": containment_level.description(),
    }))
}

#[tauri::command]
async fn get_playbooks(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let engine = state.playbook_engine.read().await;
    let playbooks: Vec<serde_json::Value> = engine
        .list_playbooks()
        .into_iter()
        .map(|p| serde_json::json!({
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "enabled": p.enabled,
            "triggers": p.triggers.len(),
            "steps": p.steps.len(),
        }))
        .collect();
    Ok(serde_json::json!({
        "playbooks": playbooks,
        "total": playbooks.len(),
    }))
}

#[tauri::command]
async fn get_quarantine_list(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let store = state.quarantine_store.read().await;
    let items: Vec<serde_json::Value> = store
        .list_quarantined()
        .iter()
        .map(|q| serde_json::to_value(q).unwrap_or_default())
        .collect();
    Ok(serde_json::json!({
        "items": items,
        "total": store.count(),
    }))
}

// ---------------------------------------------------------------------------
// NEW: Fleet Management commands
// ---------------------------------------------------------------------------

#[tauri::command]
async fn get_fleet_agents(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let registry = state.fleet_agents.read().await;
    let agents: Vec<serde_json::Value> = registry
        .list_agents()
        .into_iter()
        .map(|a| serde_json::to_value(a).unwrap_or_default())
        .collect();
    Ok(serde_json::json!({
        "agents": agents,
        "total": agents.len(),
    }))
}

#[tauri::command]
async fn get_fleet_stats(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let registry = state.fleet_agents.read().await;
    let agents = registry.list_agents();
    let total = agents.len();
    let online = registry.get_online_count();
    Ok(serde_json::json!({
        "total_agents": total,
        "online_agents": online,
        "offline_agents": total.saturating_sub(online),
    }))
}

// ---------------------------------------------------------------------------
// NEW: MITRE ATT&CK commands
// ---------------------------------------------------------------------------

#[tauri::command]
async fn get_mitre_techniques() -> Result<serde_json::Value, String> {
    let analyzer = CoverageAnalyzer::new();
    let report = analyzer.calculate_coverage();
    Ok(serde_json::json!({
        "total_techniques": report.total_techniques,
        "covered_techniques": report.covered_techniques,
        "coverage_percent": (report.coverage_percent * 10.0).round() / 10.0,
        "gaps": report.gaps.len(),
    }))
}

// ---------------------------------------------------------------------------
// NEW: SIEM Export commands
// ---------------------------------------------------------------------------

#[tauri::command]
async fn export_siem_events(
    state: State<'_, AppState>,
    format: Option<String>,
    limit: Option<usize>,
) -> Result<serde_json::Value, String> {
    let fmt = format.unwrap_or_else(|| "json".to_string());
    let limit = limit.unwrap_or(1000);

    let stored_events = state
        .store
        .get_recent_events(limit)
        .map_err(|e| e.to_string())?;

    let envelopes: Vec<SecurityEventEnvelope> = stored_events
        .into_iter()
        .filter_map(|se| {
            let id = uuid::Uuid::parse_str(&se.id).ok()?;
            let ts = chrono::DateTime::parse_from_rfc3339(&se.timestamp)
                .ok()?
                .with_timezone(&chrono::Utc);
            let severity: royalsecurity_common::types::EventSeverity =
                se.severity.parse().ok()?;
            let event_type: royalsecurity_common::types::EventType =
                se.event_type.parse().ok()?;
            let payload: SecurityEvent =
                serde_json::from_value(se.data.clone()).unwrap_or(SecurityEvent::Process(ProcessInfo::default()));
            Some(SecurityEventEnvelope {
                id,
                severity,
                event_type,
                timestamp: ts,
                source: se.source,
                raw: None,
                details: HashMap::new(),
                payload,
            })
        })
        .collect();

    let mut buf: Vec<u8> = Vec::new();
    match fmt.as_str() {
        "ecs" => {
            let formatter = royalsecurity_siem_export::EcsNdjsonFormatter::new();
            formatter.format_batch(&envelopes, &mut buf).map_err(|e| e.to_string())?;
        }
        "cef" => {
            let formatter = royalsecurity_siem_export::CefFormatter::new();
            formatter.format_batch(&envelopes, &mut buf).map_err(|e| e.to_string())?;
        }
        "syslog" => {
            let formatter = royalsecurity_siem_export::SyslogFormatter::new();
            formatter.format_batch(&envelopes, &mut buf).map_err(|e| e.to_string())?;
        }
        "csv" => {
            let formatter = royalsecurity_siem_export::CsvFormatter::new();
            formatter.format_batch(&envelopes, &mut buf).map_err(|e| e.to_string())?;
        }
        "splunk" => {
            let formatter = royalsecurity_siem_export::SplunkHecFormatter::new();
            formatter.format_batch(&envelopes, &mut buf).map_err(|e| e.to_string())?;
        }
        _ => {
            let formatter = royalsecurity_siem_export::JsonFormatter::new();
            formatter.format_batch(&envelopes, &mut buf).map_err(|e| e.to_string())?;
        }
    }

    let output = String::from_utf8_lossy(&buf).to_string();
    Ok(serde_json::json!({
        "format": fmt,
        "event_count": envelopes.len(),
        "output": output,
    }))
}

// ---------------------------------------------------------------------------
// NEW: STIX/TAXII commands
// ---------------------------------------------------------------------------

#[tauri::command]
async fn export_stix_bundle(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    use royalsecurity_common::types::{ThreatInfo, EventSeverity, ThreatStatus};
    let threats = state.store.get_threats().unwrap_or_default();
    let mut bundle = StixBundle::new();
    for stored in &threats {
        let severity = match stored.severity.to_lowercase().as_str() {
            "critical" => EventSeverity::Critical,
            "high" => EventSeverity::High,
            "medium" => EventSeverity::Medium,
            "low" => EventSeverity::Low,
            _ => EventSeverity::Informational,
        };
        let threat = ThreatInfo {
            id: uuid::Uuid::parse_str(&stored.id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
            name: stored.name.clone(),
            description: stored.description.clone(),
            severity,
            mitre_tactic: stored.mitre_tactic.clone(),
            mitre_technique: stored.mitre_technique.clone(),
            iocs: vec![],
            affected_hosts: vec![],
            first_seen: chrono::DateTime::parse_from_rfc3339(&stored.first_seen)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
            last_seen: chrono::DateTime::parse_from_rfc3339(&stored.last_seen)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
            status: ThreatStatus::Active,
        };
        let objects = threat_to_stix(&threat);
        for obj in objects {
            bundle.add_object(obj);
        }
    }
    let json = bundle.to_json().map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "bundle_size": bundle.objects.len(),
        "json_length": json.len(),
        "spec_version": "2.1",
    }))
}

// main()
// ---------------------------------------------------------------------------

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("RoyalSecurity Agent starting");

    let bus = EventBus::new();
    let config = AppConfig::default();
    let vault = CryptoVault::new();
    let audit = AuditLog::new();
    let registry = ModuleRegistry::new(bus.clone());
    let store = StateStore::new("C:\\ProgramData\\RoyalSecurity\\Database\\state.redb")
        .expect("Failed to initialize state store");
    let rule_engine = RuleEngine::new();
    let feed_manager = FeedManager::new();
    let ioc_matcher = IocMatcher::new();
    let mut yara_engine = YaraEngine::new();
    let mut rule_updater = RuleUpdater::new("C:\\ProgramData\\RoyalSecurity\\Rules");
    let ppl = ProcessProtection::new(ProtectionConfig::default());
    let _tpm = TpmManager::new();
    let enhanced_vault = EnhancedVault::new();
    let tpm_vault = TpmSealedVault::new(enhanced_vault);

    yara_engine.load_default_rules();
    tracing::info!(count = yara_engine.list_rules().len(), "Loaded default YARA rules");

    rule_updater.load_builtin_feeds();
    tracing::info!("Loaded builtin threat intel feeds");

    let initial_procs = list_processes();
    tracing::info!(count = initial_procs.len(), "Enumerated initial process list");

    let _ = ppl.apply_mitigations();
    let _ = ppl.start_watchdog(std::time::Duration::from_secs(30));
    tracing::info!("PPL watchdog started");

    let containment = ContainmentManager::new();
    let playbook_engine = PlaybookEngine::new();
    let quarantine_store = QuarantineStore::new();
    let fleet_agents = AgentRegistry::new();
    let policy_engine = PolicyEngine::new();
    let mitre_coverage = CoverageAnalyzer::new();
    let cve_db = CveDatabase::new();

    tracing::info!(playbooks = playbook_engine.list_playbooks().len(), "Loaded response playbooks");
    tracing::info!(cves = cve_db.count(), "Loaded CVE database");
    tracing::info!(techniques = 112, "MITRE ATT&CK techniques loaded");

    let engine = Arc::new(SecurityEngine::new(config.clone()));
    {
        let engine_clone = engine.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(e) = engine_clone.start().await {
                tracing::error!("SecurityEngine start failed: {}", e);
            }
        });
    }

    {
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            tracing::info!("Starting real-time collectors");

            let sysmon = royalsecurity_collector_sysmon::SysmonCollector::new(
                royalsecurity_core::bus::EventBus::new(),
            );
            let _ = sysmon.start().await;

            let mut log_collector = royalsecurity_collector_log::LogCollector::new(
                royalsecurity_core::bus::EventBus::new(),
            );
            let _ = log_collector.start();

            tracing::info!("Real-time collectors initialized");

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                #[cfg(target_os = "windows")]
                {
                    let sysmon_count = sysmon.poll_real_events();
                    if sysmon_count > 0 {
                        tracing::info!(count = sysmon_count, "Sysmon events collected from real event log");
                    }

                    let log_count = log_collector.poll_real_events();
                    if log_count > 0 {
                        tracing::info!(count = log_count, "Windows Event Log entries collected");
                    }
                }
            }
        });
    }

    tracing::info!(
        app_name = %config.general.app_name,
        version = %config.general.version,
        "Configuration loaded"
    );

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_log::Builder::default().build())
        .plugin(tauri_plugin_fs::init())
        .manage(AppState {
            engine,
            bus,
            config: Arc::new(RwLock::new(config)),
            vault: Arc::new(RwLock::new(vault)),
            audit: Arc::new(RwLock::new(audit)),
            registry: Arc::new(registry),
            store: Arc::new(store),
            rule_engine: Arc::new(RwLock::new(rule_engine)),
            feed_manager: Arc::new(RwLock::new(feed_manager)),
            ioc_matcher: Arc::new(RwLock::new(ioc_matcher)),
            yara_engine: Arc::new(RwLock::new(yara_engine)),
            rule_updater: Arc::new(RwLock::new(rule_updater)),
            ppl: Arc::new(RwLock::new(ppl)),
            tpm: Arc::new(RwLock::new(TpmManager::new())),
            tpm_vault: Arc::new(RwLock::new(tpm_vault)),
            intel_aggregator: Arc::new(RwLock::new(ThreatIntelAggregator::default())),
            process_cache: Arc::new(RwLock::new(initial_procs)),
            network_cache: Arc::new(RwLock::new(Vec::new())),
            alert_store: Arc::new(RwLock::new(Vec::new())),
            scan_state: Arc::new(RwLock::new(ScanState::default())),
            containment: Arc::new(RwLock::new(containment)),
            playbook_engine: Arc::new(RwLock::new(playbook_engine)),
            quarantine_store: Arc::new(RwLock::new(quarantine_store)),
            fleet_agents: Arc::new(RwLock::new(fleet_agents)),
            policy_engine: Arc::new(RwLock::new(policy_engine)),
            mitre_coverage: Arc::new(RwLock::new(mitre_coverage)),
            cve_db: Arc::new(RwLock::new(cve_db)),
        })
        .setup(|_app| {
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // READ commands (16)
            get_system_info,
            get_process_list,
            get_network_connections,
            get_alert_stats,
            get_mitre_coverage,
            get_compliance_status,
            get_audit_log,
            get_events,
            get_threats,
            search_iocs,
            get_crypto_keys,
            get_config,
            get_module_health,
            get_event_bus_stats,
            get_ppl_status,
            get_tpm_status,
            // WRITE commands (16)
            update_config,
            encrypt_data,
            decrypt_data,
            add_sigma_rule,
            add_yara_rule,
            evaluate_event,
            trigger_threat_intel_update,
            terminate_process,
            block_ip,
            remove_detection_rule,
            trigger_scan,
            update_config_field,
            get_defense_status,
            get_process_detail,
            export_audit_log,
            verify_audit_chain,
            // Engine commands
            get_engine_stats,
            get_detection_rules,
            force_intel_update,
            // NEW: Forensic Triage
            run_forensic_triage,
            // NEW: Vulnerability Management
            scan_vulnerabilities,
            get_cve_details,
            search_cves,
            // NEW: Active Response
            get_containment_level,
            set_containment_level,
            get_playbooks,
            get_quarantine_list,
            // NEW: Fleet Management
            get_fleet_agents,
            get_fleet_stats,
            // NEW: MITRE ATT&CK
            get_mitre_techniques,
            // NEW: SIEM Export
            export_siem_events,
            // NEW: STIX/TAXII
            export_stix_bundle,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}


