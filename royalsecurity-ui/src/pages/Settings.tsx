import { useState, useEffect } from 'react';
import {
  Settings, Save, Shield, Server, Activity, Network,
  Database, FileSearch, Cpu, CheckCircle
} from 'lucide-react';
import { getConfig } from '../lib/tauri-bridge';

interface ModuleConfig {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  icon: any;
  status: 'running' | 'stopped' | 'error';
}

interface AgentConfig {
  hostname: string;
  server_url: string;
  log_level: string;
  scan_interval: number;
  alert_threshold: string;
  auto_isolate: boolean;
  telemetry_enabled: boolean;
  max_cpu_percent: number;
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
  const [config, setConfig] = useState<AgentConfig>({
    hostname: 'WIN-SRV-001',
    server_url: 'https://royalsecurity.local:8443',
    log_level: 'info',
    scan_interval: 300,
    alert_threshold: 'medium',
    auto_isolate: true,
    telemetry_enabled: true,
    max_cpu_percent: 25,
  });
  const [loading, setLoading] = useState(true);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const data = await getConfig() as Partial<AgentConfig>;
        if (data) {
          setConfig((prev) => ({ ...prev, ...data }));
        }
      } catch {
        // Use defaults
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const toggleModule = (id: string) => {
    setModules((prev) =>
      prev.map((m) =>
        m.id === id
          ? { ...m, enabled: !m.enabled, status: !m.enabled ? 'running' : 'stopped' }
          : m
      )
    );
  };

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-3">
          <Cpu className="w-5 h-5 text-indigo-400 animate-spin" />
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Loading settings...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Settings</h1>
        <div className="flex items-center gap-2">
          {saved && (
            <span className="flex items-center gap-1.5 text-xs text-green-400">
              <CheckCircle className="w-4 h-4" />
              Saved
            </span>
          )}
          <button
            onClick={handleSave}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500 text-white hover:bg-indigo-600 transition-colors"
          >
            <Save className="w-3.5 h-3.5" />
            Save Changes
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-6">
          <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
            <h2 className="text-sm font-semibold mb-4">Agent Configuration</h2>
            <div className="space-y-4">
              <div>
                <label className="text-xs font-medium block mb-1.5" style={{ color: 'var(--text-secondary)' }}>Hostname</label>
                <input
                  type="text"
                  value={config.hostname}
                  onChange={(e) => setConfig({ ...config, hostname: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg text-sm border outline-none focus:ring-1 focus:ring-indigo-500"
                  style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
                />
              </div>
              <div>
                <label className="text-xs font-medium block mb-1.5" style={{ color: 'var(--text-secondary)' }}>Server URL</label>
                <input
                  type="text"
                  value={config.server_url}
                  onChange={(e) => setConfig({ ...config, server_url: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg text-sm border outline-none focus:ring-1 focus:ring-indigo-500"
                  style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-medium block mb-1.5" style={{ color: 'var(--text-secondary)' }}>Log Level</label>
                  <select
                    value={config.log_level}
                    onChange={(e) => setConfig({ ...config, log_level: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg text-sm border outline-none focus:ring-1 focus:ring-indigo-500"
                    style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
                  >
                    <option value="debug">Debug</option>
                    <option value="info">Info</option>
                    <option value="warn">Warning</option>
                    <option value="error">Error</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs font-medium block mb-1.5" style={{ color: 'var(--text-secondary)' }}>Alert Threshold</label>
                  <select
                    value={config.alert_threshold}
                    onChange={(e) => setConfig({ ...config, alert_threshold: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg text-sm border outline-none focus:ring-1 focus:ring-indigo-500"
                    style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
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
                <label className="text-xs font-medium block mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                  Scan Interval (seconds): {config.scan_interval}
                </label>
                <input
                  type="range"
                  min="30"
                  max="3600"
                  step="30"
                  value={config.scan_interval}
                  onChange={(e) => setConfig({ ...config, scan_interval: parseInt(e.target.value) })}
                  className="w-full accent-indigo-500"
                />
                <div className="flex justify-between text-[10px]" style={{ color: 'var(--text-secondary)' }}>
                  <span>30s</span>
                  <span>1hr</span>
                </div>
              </div>
              <div>
                <label className="text-xs font-medium block mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                  Max CPU Usage: {config.max_cpu_percent}%
                </label>
                <input
                  type="range"
                  min="5"
                  max="100"
                  step="5"
                  value={config.max_cpu_percent}
                  onChange={(e) => setConfig({ ...config, max_cpu_percent: parseInt(e.target.value) })}
                  className="w-full accent-indigo-500"
                />
              </div>
            </div>
          </div>

          <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
            <h2 className="text-sm font-semibold mb-4">Behavior</h2>
            <div className="space-y-3">
              {[
                { key: 'auto_isolate' as const, label: 'Auto-Isolate on Critical', desc: 'Automatically isolate hosts when critical threats are detected' },
                { key: 'telemetry_enabled' as const, label: 'Telemetry Collection', desc: 'Send anonymous usage data to improve detection accuracy' },
              ].map((item) => (
                <div key={item.key} className="flex items-center justify-between py-2">
                  <div>
                    <div className="text-xs font-medium">{item.label}</div>
                    <div className="text-[10px]" style={{ color: 'var(--text-secondary)' }}>{item.desc}</div>
                  </div>
                  <button
                    onClick={() => setConfig({ ...config, [item.key]: !config[item.key] })}
                    className={`relative w-10 h-5 rounded-full transition-colors ${config[item.key] ? 'bg-indigo-500' : 'bg-gray-600'}`}
                  >
                    <div
                      className="absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all"
                      style={{ left: config[item.key] ? '22px' : '2px' }}
                    />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold">Modules</h2>
            <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
              {modules.filter(m => m.enabled).length}/{modules.length} active
            </span>
          </div>
          <div className="space-y-2">
            {modules.map((mod) => {
              const Icon = mod.icon;
              return (
                <div
                  key={mod.id}
                  className="flex items-center gap-3 p-3 rounded-lg border transition-colors hover:bg-white/5"
                  style={{ borderColor: 'var(--border-color)' }}
                >
                  <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'var(--bg-secondary)' }}>
                    <Icon className="w-4 h-4" style={{ color: mod.enabled ? 'var(--accent)' : 'var(--text-secondary)' }} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium">{mod.name}</span>
                      <div className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: statusColors[mod.status] }} />
                    </div>
                    <p className="text-[10px] truncate" style={{ color: 'var(--text-secondary)' }}>{mod.description}</p>
                  </div>
                  <button
                    onClick={() => toggleModule(mod.id)}
                    className={`relative w-10 h-5 rounded-full transition-colors shrink-0 ${mod.enabled ? 'bg-indigo-500' : 'bg-gray-600'}`}
                  >
                    <div
                      className="absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all"
                      style={{ left: mod.enabled ? '22px' : '2px' }}
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
