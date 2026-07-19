import { useState, useEffect, useCallback } from 'react';
import {
  Settings, Save, Shield, Server, Activity, Network,
  Database, FileSearch, Cpu, CheckCircle, AlertTriangle, RefreshCw
} from 'lucide-react';
import { getConfig, updateConfig, triggerScan, updateConfigField } from '../lib/tauri-bridge';
import type { Config } from '../lib/tauri-bridge';

interface ModuleConfig {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  icon: any;
  status: 'running' | 'stopped' | 'error';
}

const defaultModules: ModuleConfig[] = [
  { id: 'edr', name: 'EDR Engine', description: 'Endpoint Detection and Response - monitors processes, registry, and file system', enabled: true, icon: Shield, status: 'running' },
  { id: 'hids', name: 'HIDS Monitor', description: 'Host-based Intrusion Detection - file integrity and system monitoring', enabled: true, icon: Database, status: 'running' },
  { id: 'sigma', name: 'Sigma Rules Engine', description: 'Sigma rule matching against Windows Event Logs', enabled: true, icon: FileSearch, status: 'running' },
  { id: 'yara', name: 'YARA Scanner', description: 'Memory and file scanning with YARA rules', enabled: true, icon: FileSearch, status: 'running' },
  { id: 'network', name: 'Network Monitor', description: 'Network traffic analysis and C2 detection', enabled: true, icon: Network, status: 'running' },
  { id: 'compliance', name: 'Compliance Scanner', description: 'CIS/STIG/NIST compliance checking', enabled: true, icon: Settings, status: 'running' },
  { id: 'audit', name: 'Audit Logger', description: 'Tamper-proof audit trail with hash chain', enabled: true, icon: Database, status: 'running' },
  { id: 'mitre', name: 'MITRE Mapper', description: 'Maps detections to MITRE ATT&CK framework', enabled: true, icon: Activity, status: 'running' },
  { id: 'dlp', name: 'DLP Monitor', description: 'Data Loss Prevention - monitors file transfers and USB', enabled: false, icon: Shield, status: 'stopped' },
  { id: 'sandbox', name: 'Sandbox Analyzer', description: 'Automated malware analysis in isolated environment', enabled: false, icon: Server, status: 'stopped' },
];

const statusColors: Record<string, string> = {
  running: 'var(--low)',
  stopped: 'var(--text-secondary)',
  error: 'var(--critical)',
};

export default function SettingsPage() {
  const [modules, setModules] = useState<ModuleConfig[]>(defaultModules);
  const [config, setConfig] = useState<Config>({
    hostname: '',
    server_url: '',
    log_level: 'info',
    scan_interval: 300,
    alert_threshold: 'medium',
    auto_isolate: true,
    telemetry_enabled: true,
    max_cpu_percent: 25,
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message });
    setTimeout(() => setFeedback(null), 5000);
  };

  const load = useCallback(async () => {
    try {
      const data = await getConfig();
      if (data) {
        setConfig((prev) => ({ ...prev, ...data }));
        if ((data as any).modules && Array.isArray((data as any).modules)) {
          setModules((data as any).modules);
        }
      }
    } catch {
      // Use defaults
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const toggleModule = async (id: string) => {
    const target = modules.find(m => m.id === id);
    if (!target) return;
    const newEnabled = !target.enabled;
    setModules((prev) =>
      prev.map((m) =>
        m.id === id
          ? { ...m, enabled: newEnabled, status: newEnabled ? 'running' : 'stopped' }
          : m
      )
    );
    try {
      await updateConfigField(`defense.${id}_enabled`, newEnabled);
    } catch {
      setModules((prev) =>
        prev.map((m) =>
          m.id === id
            ? { ...m, enabled: target.enabled, status: target.status }
            : m
        )
      );
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateConfig(config);
      showFeedback('success', 'Configuration saved successfully');
    } catch (err: any) {
      showFeedback('error', err?.toString() || 'Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleScan = async (scanType: string) => {
    try {
      const result = await triggerScan(scanType);
      showFeedback('success', result.message || `Started ${scanType} scan`);
    } catch (err: any) {
      showFeedback('error', err?.toString() || 'Failed to trigger scan');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-3">
          <Cpu className="w-5 h-5 animate-spin" style={{ color: 'var(--accent)' }} />
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Loading settings...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>SYSTEM CONFIGURATION</h1>
          <p className="text-[10px] uppercase mt-1" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Agent Settings & Module Management</p>
        </div>
        <div className="flex items-center gap-2">
          {feedback && (
            <span className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg" style={{
              backgroundColor: feedback.type === 'success' ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
              color: feedback.type === 'success' ? 'var(--low)' : 'var(--critical)',
              border: `1px solid ${feedback.type === 'success' ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)'}`,
            }}>
              {feedback.type === 'success' ? <CheckCircle className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
              {feedback.message}
            </span>
          )}
          <button onClick={load} className="flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-medium transition-all"
            style={{ border: '1px solid var(--accent)', color: 'var(--accent)', backgroundColor: 'transparent' }}
            onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--accent-muted)'; }}
            onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-medium transition-all disabled:opacity-50"
            style={{
              backgroundColor: 'var(--accent)',
              color: 'var(--bg-primary)',
            }}
            onMouseEnter={(e) => { if (!e.currentTarget.disabled) e.currentTarget.style.opacity = '0.9'; }}
            onMouseLeave={(e) => { e.currentTarget.style.opacity = '1'; }}
          >
            <Save className="w-3.5 h-3.5" />
            {saving ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-6">
          <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderLeft: '4px solid var(--accent)' }}>
            <span className="text-[10px] font-medium uppercase block mb-4" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Agent Configuration</span>
            <div className="space-y-4">
              <div>
                <label className="text-[10px] font-medium uppercase block mb-2" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Hostname</label>
                <input
                  type="text"
                  value={config.hostname || ''}
                  onChange={(e) => setConfig({ ...config, hostname: e.target.value })}
                  className="w-full px-4 py-2.5 rounded-xl text-sm border outline-none transition-all focus:border-[var(--border-active)]"
                  style={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
                />
              </div>
              <div>
                <label className="text-[10px] font-medium uppercase block mb-2" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Server URL</label>
                <input
                  type="text"
                  value={config.server_url || ''}
                  onChange={(e) => setConfig({ ...config, server_url: e.target.value })}
                  className="w-full px-4 py-2.5 rounded-xl text-sm border outline-none transition-all focus:border-[var(--border-active)]"
                  style={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] font-medium uppercase block mb-2" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Log Level</label>
                  <select
                    value={config.log_level || 'info'}
                    onChange={(e) => setConfig({ ...config, log_level: e.target.value })}
                    className="w-full px-4 py-2.5 rounded-xl text-sm border outline-none transition-all focus:border-[var(--border-active)]"
                    style={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
                  >
                    <option value="debug">Debug</option>
                    <option value="info">Info</option>
                    <option value="warn">Warning</option>
                    <option value="error">Error</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] font-medium uppercase block mb-2" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Alert Threshold</label>
                  <select
                    value={config.alert_threshold || 'medium'}
                    onChange={(e) => setConfig({ ...config, alert_threshold: e.target.value })}
                    className="w-full px-4 py-2.5 rounded-xl text-sm border outline-none transition-all focus:border-[var(--border-active)]"
                    style={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
                  >
                    <option value="critical">Critical Only</option>
                    <option value="high">High+</option>
                    <option value="medium">Medium+</option>
                    <option value="low">Low+</option>
                    <option value="info">All</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="text-[10px] font-medium uppercase block mb-2" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>
                  Scan Interval: {config.scan_interval || 300}s
                </label>
                <input
                  type="range"
                  min="30"
                  max="3600"
                  step="30"
                  value={config.scan_interval || 300}
                  onChange={(e) => setConfig({ ...config, scan_interval: parseInt(e.target.value) })}
                  className="w-full"
                  style={{ accentColor: 'var(--accent)' }}
                />
                <div className="flex justify-between text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
                  <span>30s</span>
                  <span>1hr</span>
                </div>
              </div>
              <div>
                <label className="text-[10px] font-medium uppercase block mb-2" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>
                  Max CPU Usage: {config.max_cpu_percent || 25}%
                </label>
                <input
                  type="range"
                  min="5"
                  max="100"
                  step="5"
                  value={config.max_cpu_percent || 25}
                  onChange={(e) => setConfig({ ...config, max_cpu_percent: parseInt(e.target.value) })}
                  className="w-full"
                  style={{ accentColor: 'var(--accent)' }}
                />
              </div>
            </div>
          </div>

          <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderLeft: '4px solid var(--accent)' }}>
            <span className="text-[10px] font-medium uppercase block mb-4" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Behavior</span>
            <div className="space-y-3">
              {[
                { key: 'auto_isolate' as const, label: 'Auto-Isolate on Critical', desc: 'Automatically isolate hosts when critical threats are detected' },
                { key: 'telemetry_enabled' as const, label: 'Telemetry Collection', desc: 'Send anonymous usage data to improve detection accuracy' },
              ].map((item) => (
                <div key={item.key} className="flex items-center justify-between p-3 rounded-xl border transition-all" style={{
                  backgroundColor: 'var(--bg-elevated)',
                  borderColor: 'var(--border-color)',
                }}>
                  <div>
                    <div className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>{item.label}</div>
                    <div className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{item.desc}</div>
                  </div>
                  <button
                    onClick={() => setConfig({ ...config, [item.key]: !config[item.key] })}
                    className="relative w-10 h-5 rounded-full transition-colors shrink-0"
                    style={{
                      backgroundColor: config[item.key] ? 'var(--accent)' : 'var(--bg-card)',
                      border: `1px solid ${config[item.key] ? 'var(--accent)' : 'var(--border-color)'}`,
                    }}
                  >
                    <div
                      className="absolute top-0.5 w-4 h-4 rounded-full transition-all"
                      style={{
                        left: config[item.key] ? '22px' : '2px',
                        backgroundColor: config[item.key] ? 'var(--bg-primary)' : 'var(--text-tertiary)',
                      }}
                    />
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderLeft: '4px solid var(--accent)' }}>
            <span className="text-[10px] font-medium uppercase block mb-4" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Scan Triggers</span>
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'Quick Scan', type: 'quick' },
                { label: 'Full System Scan', type: 'full' },
                { label: 'Memory Scan', type: 'memory' },
                { label: 'Network Scan', type: 'network' },
              ].map((scan) => (
                <button
                  key={scan.type}
                  onClick={() => handleScan(scan.type)}
                  className="flex items-center justify-center gap-2 px-3 py-3 rounded-xl text-xs font-medium border transition-all hover:shadow-md"
                  style={{
                    backgroundColor: 'var(--bg-card)',
                    borderColor: 'var(--border-color)',
                    color: 'var(--text-primary)',
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.boxShadow = '0 0 15px rgba(201,168,76,0.1)'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; e.currentTarget.style.boxShadow = 'none'; }}
                >
                  {scan.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderLeft: '4px solid var(--accent)' }}>
          <div className="flex items-center justify-between mb-4">
            <span className="text-[10px] font-medium uppercase" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Modules</span>
            <span className="text-[10px] px-2 py-0.5 rounded-full" style={{ backgroundColor: 'var(--accent-muted)', color: 'var(--accent)' }}>
              {modules.filter(m => m.enabled).length}/{modules.length} active
            </span>
          </div>
          <div className="space-y-2">
            {modules.map((mod) => {
              const Icon = mod.icon;
              return (
                <div
                  key={mod.id}
                  className="flex items-center gap-3 p-4 rounded-xl border transition-all hover:shadow-md"
                  style={{
                    backgroundColor: 'var(--bg-elevated)',
                    borderColor: 'var(--border-color)',
                    borderLeft: `4px solid ${mod.enabled ? 'var(--accent)' : 'var(--border-color)'}`,
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--border-active)'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; }}
                >
                  <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'var(--bg-card)' }}>
                    <Icon className="w-4 h-4" style={{ color: mod.enabled ? 'var(--accent)' : 'var(--text-tertiary)' }} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>{mod.name}</span>
                      <div className="w-1.5 h-1.5 rounded-full" style={{
                        backgroundColor: statusColors[mod.status],
                        boxShadow: mod.status === 'running' ? '0 0 6px var(--low)' : 'none',
                      }} />
                    </div>
                    <p className="text-[10px] truncate" style={{ color: 'var(--text-tertiary)' }}>{mod.description}</p>
                  </div>
                  <button
                    onClick={() => toggleModule(mod.id)}
                    className="relative w-10 h-5 rounded-full transition-colors shrink-0"
                    style={{
                      backgroundColor: mod.enabled ? 'var(--accent)' : 'var(--bg-card)',
                      border: `1px solid ${mod.enabled ? 'var(--accent)' : 'var(--border-color)'}`,
                    }}
                  >
                    <div
                      className="absolute top-0.5 w-4 h-4 rounded-full transition-all"
                      style={{
                        left: mod.enabled ? '22px' : '2px',
                        backgroundColor: mod.enabled ? 'var(--bg-primary)' : 'var(--text-tertiary)',
                      }}
                    />
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
