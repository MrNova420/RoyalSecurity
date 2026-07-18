import { invoke } from '@tauri-apps/api/core';

export async function invokeCommand<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(command, args);
}

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
  return invokeCommand<unknown>('get_config');
}
