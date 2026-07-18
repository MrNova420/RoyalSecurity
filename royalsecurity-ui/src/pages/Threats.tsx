import { useState, useEffect } from 'react';
import {
  AlertTriangle, Search, RefreshCw
} from 'lucide-react';
import { getAlertStats } from '../lib/tauri-bridge';

interface Threat {
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

const mockThreats: Threat[] = [
  { id: 'THR-001', severity: 'critical', title: 'Ransomware Execution Attempt', source: 'EDR', mitre: 'T1486 - Data Encrypted for Impact', host: 'WIN-SRV-001', time: '2 min ago', status: 'active', description: 'PowerShell process spawned cmd.exe which attempted to encrypt files with .locked extension. Process chain terminated.' },
  { id: 'THR-002', severity: 'critical', title: 'Credential Dumping via LSASS', source: 'EDR', mitre: 'T1003.001 - LSASS Memory', host: 'WIN-DC-003', time: '8 min ago', status: 'investigating', description: 'Suspicious access to LSASS process memory detected. Potential Mimikatz usage identified through memory scan.' },
  { id: 'THR-003', severity: 'high', title: 'Lateral Movement via PsExec', source: 'Sigma', mitre: 'T1021.002 - SMB/Windows Admin Shares', host: 'WIN-SRV-002', time: '15 min ago', status: 'active', description: 'PsExec service created on remote host from WIN-WS-047. Service binary executed in temp directory.' },
  { id: 'THR-004', severity: 'high', title: 'PowerShell Reverse Shell', source: 'YARA', mitre: 'T1059.001 - PowerShell', host: 'WIN-WS-012', time: '23 min ago', status: 'investigating', description: 'Outbound TCP connection from PowerShell process to external IP 185.220.101.34 on port 443.' },
  { id: 'THR-005', severity: 'medium', title: 'Suspicious Scheduled Task', source: 'HIDS', mitre: 'T1053.005 - Scheduled Task', host: 'WIN-SRV-001', time: '31 min ago', status: 'active', description: 'New scheduled task "WindowsUpdateService" created pointing to %TEMP%\\update.exe. Task not signed.' },
  { id: 'THR-006', severity: 'medium', title: 'DNS Tunneling Detected', source: 'Network', mitre: 'T1071.004 - DNS', host: 'WIN-WS-089', time: '42 min ago', status: 'active', description: 'Anomalous DNS query patterns detected. High-entropy subdomain queries to suspicious domain.' },
  { id: 'THR-007', severity: 'low', title: 'New Service Installation', source: 'Sysmon', mitre: 'T1543.003 - Windows Service', host: 'WIN-SRV-002', time: '1 hr ago', status: 'false_positive', description: 'Legitimate Windows service "CryptSvc Update" installed by Windows Update process.' },
  { id: 'THR-008', severity: 'high', title: 'Pass-the-Hash Attempt', source: 'Sigma', mitre: 'T1550.002 - Pass the Hash', host: 'WIN-DC-003', time: '1 hr ago', status: 'investigating', description: 'NTLM authentication using hash passed from compromised workstation WIN-WS-023 to domain controller.' },
  { id: 'THR-009', severity: 'medium', title: 'Registry Persistence Mechanism', source: 'EDR', mitre: 'T1547.001 - Registry Run Keys', host: 'WIN-WS-012', time: '2 hr ago', status: 'active', description: 'New entry added to HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run pointing to executable in AppData.' },
  { id: 'THR-010', severity: 'low', title: 'USB Device Connected', source: 'DLP', mitre: 'T1091 - Removable Media', host: 'WIN-WS-047', time: '3 hr ago', status: 'resolved', description: 'USB mass storage device connected. File scan completed - no sensitive data exfiltration detected.' },
];

const severityColors: Record<string, string> = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
  informational: 'var(--info)',
};

const statusColors: Record<string, string> = {
  active: 'var(--critical)',
  investigating: 'var(--medium)',
  resolved: 'var(--low)',
  false_positive: 'var(--text-secondary)',
};

export default function Threats() {
  const [threats] = useState<Threat[]>(mockThreats);
  const [filter, setFilter] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [stats, setStats] = useState({ critical: 3, high: 12, medium: 28, low: 47 });
  const [, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const data = await getAlertStats();
        setStats({ critical: data.critical, high: data.high, medium: data.medium, low: data.low });
      } catch {
        // Use defaults
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const filtered = threats.filter((t) => {
    if (filter !== 'all' && t.severity !== filter) return false;
    if (searchTerm && !t.title.toLowerCase().includes(searchTerm.toLowerCase()) && !t.source.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Threats</h1>
        <button className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors">
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Critical', count: stats.critical, color: 'var(--critical)' },
          { label: 'High', count: stats.high, color: 'var(--high)' },
          { label: 'Medium', count: stats.medium, color: 'var(--medium)' },
          { label: 'Low', count: stats.low, color: 'var(--low)' },
        ].map((s) => (
          <button
            key={s.label}
            onClick={() => setFilter(filter === s.label.toLowerCase() ? 'all' : s.label.toLowerCase())}
            className={`rounded-xl p-3 border text-left transition-all ${filter === s.label.toLowerCase() ? 'ring-1' : 'hover:bg-white/5'}`}
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}
          >
            <div className="flex items-center gap-2 mb-1">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: s.color }} />
              <span className="text-[10px] uppercase font-medium" style={{ color: 'var(--text-secondary)' }}>{s.label}</span>
            </div>
            <div className="text-lg font-bold">{s.count}</div>
          </button>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          <input
            type="text"
            placeholder="Search threats..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg text-sm border outline-none focus:ring-1 focus:ring-indigo-500"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
          />
        </div>
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{filtered.length} threats</span>
      </div>

      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Severity</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Title</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Source</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>MITRE</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Host</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Status</th>
              <th className="text-right py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((threat) => (
              <tr
                key={threat.id}
                className="border-b hover:bg-white/5 transition-colors cursor-pointer"
                style={{ borderColor: 'var(--border-color)' }}
                onClick={() => setSelectedThreat(selectedThreat?.id === threat.id ? null : threat)}
              >
                <td className="py-3 px-4">
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase" style={{
                    backgroundColor: `${severityColors[threat.severity]}15`,
                    color: severityColors[threat.severity],
                  }}>
                    <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: severityColors[threat.severity] }} />
                    {threat.severity}
                  </span>
                </td>
                <td className="py-3 px-4 font-medium">{threat.title}</td>
                <td className="py-3 px-4" style={{ color: 'var(--text-secondary)' }}>{threat.source}</td>
                <td className="py-3 px-4" style={{ color: 'var(--accent)' }}>{threat.mitre}</td>
                <td className="py-3 px-4">{threat.host}</td>
                <td className="py-3 px-4">
                  <span className="text-[10px] font-medium uppercase" style={{ color: statusColors[threat.status] }}>
                    {threat.status.replace('_', ' ')}
                  </span>
                </td>
                <td className="py-3 px-4 text-right" style={{ color: 'var(--text-secondary)' }}>{threat.time}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selectedThreat && (
        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: severityColors[selectedThreat.severity] }}>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5" style={{ color: severityColors[selectedThreat.severity] }} />
              <h3 className="text-sm font-semibold">{selectedThreat.title}</h3>
            </div>
            <button onClick={() => setSelectedThreat(null)} className="text-xs" style={{ color: 'var(--text-secondary)' }}>Close</button>
          </div>
          <div className="grid grid-cols-4 gap-4 mb-3 text-xs">
            <div><span style={{ color: 'var(--text-secondary)' }}>ID: </span>{selectedThreat.id}</div>
            <div><span style={{ color: 'var(--text-secondary)' }}>Host: </span>{selectedThreat.host}</div>
            <div><span style={{ color: 'var(--text-secondary)' }}>Source: </span>{selectedThreat.source}</div>
            <div><span style={{ color: 'var(--text-secondary)' }}>MITRE: </span><span style={{ color: 'var(--accent)' }}>{selectedThreat.mitre}</span></div>
          </div>
          <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{selectedThreat.description}</p>
          <div className="flex gap-2 mt-4">
            <button className="px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors">
              Block Indicator
            </button>
            <button className="px-3 py-1.5 rounded-lg text-xs font-medium bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30 transition-colors">
              Investigate
            </button>
            <button className="px-3 py-1.5 rounded-lg text-xs font-medium bg-green-500/20 text-green-400 hover:bg-green-500/30 transition-colors">
              Mark Resolved
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
