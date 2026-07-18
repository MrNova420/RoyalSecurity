import { invoke } from '@tauri-apps/api/core';

export async function invokeCommand<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(command, args);
}

// ── Interfaces ──

export interface SystemInfo {
  hostname: string;
  os: string;
  arch: string;
  version: string;
  agent_name: string;
}

export interface ModuleHealth {
  [key: string]: string;
}

export interface AlertStats {
  total_alerts: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface MitreCoverage {
  tactics_covered: number;
  techniques_covered: number;
  coverage_percent: number;
}

export interface ComplianceStatus {
  cis_score: number;
  stig_score: number;
  total_checks: number;
  passed: number;
  failed: number;
  warnings: number;
}

export interface AuditInfo {
  total_entries: number;
  chain_valid: boolean;
  last_hash: string;
}

export interface Threat {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  title: string;
  source: string;
  mitre: string;
  host: string;
  time: string;
  status: 'active' | 'investigating' | 'resolved' | 'false_positive';
  description: string;
}

export interface ProcessInfo {
  pid: number;
  name: string;
  path: string;
  command_line: string;
  cpu: number;
  memory: number;
  status: string;
  user: string;
  parent_pid: number;
  parent_name: string;
  created: string;
}

export interface NetworkConnection {
  id: string;
  local_addr: string;
  local_port: number;
  remote_addr: string;
  remote_port: number;
  protocol: string;
  state: string;
  process: string;
  pid: number;
  direction: 'inbound' | 'outbound';
  country: string;
  flagged: boolean;
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  action: string;
  user: string;
  target: string;
  details: string;
  hash: string;
  prev_hash: string;
  integrity: string;
}

export interface EventBusStats {
  total_events: number;
  events_per_second: number;
  subscribers: number;
  queue_depth: number;
}

export interface PplStatus {
  enabled: boolean;
  level: string;
  protected_processes: number;
}

export interface TpmStatus {
  available: boolean;
  version: string;
  keys_stored: number;
  pcr_values: Record<string, string>;
}

export interface DefenseStatus {
  defender_enabled: boolean;
  real_time_protection: boolean;
  last_scan: string;
  threats_found: number;
}

export interface Config {
  hostname?: string;
  server_url?: string;
  log_level?: string;
  scan_interval?: number;
  alert_threshold?: string;
  auto_isolate?: boolean;
  telemetry_enabled?: boolean;
  max_cpu_percent?: number;
  first_run?: boolean;
  [key: string]: unknown;
}

// ── READ commands ──

export async function getSystemInfo() {
  return invokeCommand<SystemInfo>('get_system_info');
}

export async function getModuleHealth() {
  return invokeCommand<ModuleHealth>('get_module_health');
}

export async function getAlertStats() {
  return invokeCommand<AlertStats>('get_alert_stats');
}

export async function getMitreCoverage() {
  return invokeCommand<MitreCoverage>('get_mitre_coverage');
}

export async function getComplianceStatus() {
  return invokeCommand<ComplianceStatus>('get_compliance_status');
}

export async function getAuditInfo() {
  return invokeCommand<AuditInfo>('get_audit_log');
}

export async function getConfig() {
  return invokeCommand<Config>('get_config');
}

export async function getProcessList() {
  return invokeCommand<ProcessInfo[]>('get_process_list');
}

export async function getNetworkConnections() {
  return invokeCommand<NetworkConnection[]>('get_network_connections');
}

export async function getEvents(limit?: number) {
  return invokeCommand<AlertStats[]>('get_events', limit !== undefined ? { limit } : undefined);
}

export async function getThreats() {
  return invokeCommand<Threat[]>('get_threats');
}

export async function searchIocs(value: string) {
  return invokeCommand<unknown>('search_iocs', { value });
}

export async function getCryptoKeys() {
  return invokeCommand<unknown[]>('get_crypto_keys');
}

export async function getEventBusStats() {
  return invokeCommand<EventBusStats>('get_event_bus_stats');
}

export async function getPplStatus() {
  return invokeCommand<PplStatus>('get_ppl_status');
}

export async function getTpmStatus() {
  return invokeCommand<TpmStatus>('get_tpm_status');
}

export async function getDefenseStatus() {
  return invokeCommand<DefenseStatus>('get_defense_status');
}

export async function getProcessDetail(pid: number) {
  return invokeCommand<ProcessInfo>('get_process_detail', { pid });
}

export async function verifyAuditChain() {
  return invokeCommand<{ valid: boolean; broken_at?: number }>('verify_audit_chain');
}

// ── WRITE commands ──

export async function updateConfig(config: Partial<Config>) {
  return invokeCommand<void>('update_config', { config });
}

export async function addSigmaRule(yaml: string) {
  return invokeCommand<{ success: boolean; rule_id?: string; message: string }>('add_sigma_rule', { yaml });
}

export async function addYaraRule(yaml: string) {
  return invokeCommand<{ success: boolean; rule_id?: string; message: string }>('add_yara_rule', { yaml });
}

export async function evaluateEvent(event: string) {
  return invokeCommand<unknown>('evaluate_event', { event });
}

export async function triggerThreatIntelUpdate() {
  return invokeCommand<void>('trigger_threat_intel_update');
}

export async function terminateProcess(pid: number) {
  return invokeCommand<{ success: boolean; message: string }>('terminate_process', { pid });
}

export async function blockIp(ip: string) {
  return invokeCommand<{ success: boolean; message: string }>('block_ip', { ip });
}

export async function removeDetectionRule(ruleId: string) {
  return invokeCommand<{ success: boolean; message: string }>('remove_detection_rule', { ruleId });
}

export async function triggerScan(scanType: string) {
  return invokeCommand<{ success: boolean; message: string }>('trigger_scan', { scanType });
}

export async function updateConfigField(key: string, value: unknown) {
  return invokeCommand<void>('update_config_field', { key, value });
}

export async function exportAuditLog(format: string) {
  return invokeCommand<{ success: boolean; path?: string; message: string }>('export_audit_log', { format });
}

export async function encryptData(data: string, keyId: string) {
  return invokeCommand<{ encrypted: string }>('encrypt_data', { data, keyId });
}

export async function decryptData(data: string, keyId: string) {
  return invokeCommand<{ decrypted: string }>('decrypt_data', { data, keyId });
}

// --- NEW: Forensic Triage ---
export async function runForensicTriage() {
  return invokeCommand<unknown>('run_forensic_triage');
}

// --- NEW: Vulnerability Management ---
export async function scanVulnerabilities() {
  return invokeCommand<unknown>('scan_vulnerabilities');
}
export async function getCveDetails(cveId: string) {
  return invokeCommand<unknown>('get_cve_details', { cveId });
}
export async function searchCves(query: string) {
  return invokeCommand<unknown>('search_cves', { query });
}

// --- NEW: Active Response ---
export async function getContainmentLevel() {
  return invokeCommand<string>('get_containment_level');
}
export async function setContainmentLevel(level: string) {
  return invokeCommand<void>('set_containment_level', { level });
}
export async function getPlaybooks() {
  return invokeCommand<unknown[]>('get_playbooks');
}
export async function getQuarantineList() {
  return invokeCommand<unknown[]>('get_quarantine_list');
}

// --- NEW: Fleet Management ---
export async function getFleetAgents() {
  return invokeCommand<unknown[]>('get_fleet_agents');
}
export async function getFleetStats() {
  return invokeCommand<unknown>('get_fleet_stats');
}

// --- NEW: MITRE ATT&CK ---
export async function getMitreTechniques() {
  return invokeCommand<unknown[]>('get_mitre_techniques');
}

// --- NEW: SIEM Export ---
export async function exportSiemEvents(format?: string, limit?: number) {
  return invokeCommand<unknown>('export_siem_events', { format, limit });
}

// --- NEW: STIX/TAXII ---
export async function exportStixBundle() {
  return invokeCommand<unknown>('export_stix_bundle');
}
