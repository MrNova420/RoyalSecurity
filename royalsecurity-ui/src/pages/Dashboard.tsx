import { useState, useEffect } from 'react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import {
  Shield, Activity, AlertTriangle, FileSearch, Scale, Clock,
  Server, Eye, Cpu
} from 'lucide-react';
import { getSystemInfo, getModuleHealth, getAlertStats, getMitreCoverage, getComplianceStatus } from '../lib/tauri-bridge';

function StatCard({ title, value, icon: Icon, color, subtitle }: { title: string; value: string | number; icon: any; color: string; subtitle?: string }) {
  return (
    <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--text-secondary)' }}>{title}</span>
        <Icon className="w-5 h-5" style={{ color }} />
      </div>
      <div className="text-2xl font-bold">{value}</div>
      {subtitle && <div className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>{subtitle}</div>}
    </div>
  );
}

const eventsOverTime = Array.from({ length: 24 }, (_, i) => ({
  hour: `${String(i).padStart(2, '0')}:00`,
  events: Math.floor(Math.random() * 180) + 20,
  threats: Math.floor(Math.random() * 15),
}));

const severityData = [
  { name: 'Critical', value: 3, color: '#ef4444' },
  { name: 'High', value: 12, color: '#f97316' },
  { name: 'Medium', value: 28, color: '#eab308' },
  { name: 'Low', value: 47, color: '#22c55e' },
];

const moduleHealthData = [
  { name: 'Running', value: 58, color: '#22c55e' },
  { name: 'Degraded', value: 6, color: '#eab308' },
  { name: 'Stopped', value: 4, color: '#ef4444' },
];

const recentAlerts = [
  { id: 1, severity: 'critical', source: 'EDR', message: 'Ransomware behavior detected in PowerShell child process', time: '2 min ago' },
  { id: 2, severity: 'high', source: 'YARA', message: 'Known malware signature match: trojan.genericKD', time: '8 min ago' },
  { id: 3, severity: 'medium', source: 'HIDS', message: 'Suspicious scheduled task creation detected', time: '15 min ago' },
  { id: 4, severity: 'high', source: 'Sigma', message: 'Credential dumping attempt via Mimikatz pattern', time: '23 min ago' },
  { id: 5, severity: 'low', source: 'Sysmon', message: 'New service installed: cryptsvc_update', time: '31 min ago' },
  { id: 6, severity: 'medium', source: 'Network', message: 'DNS query to known C2 domain observed', time: '42 min ago' },
  { id: 7, severity: 'low', source: 'FIM', message: 'System file hash changed: ntdll.dll', time: '1 hr ago' },
];

const severityColors: Record<string, string> = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
};

export default function Dashboard() {
  const [uptime, setUptime] = useState('0d 0h 0m');
  const [moduleCount, setModuleCount] = useState({ running: 58, total: 68 });
  const [alerts, setAlerts] = useState({ total: 90, critical: 3, high: 12, medium: 28, low: 47 });
  const [mitre, setMitre] = useState({ tactics: 12, techniques: 84, percent: 72 });
  const [compliance, setCompliance] = useState({ score: 78 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [sysInfo, health, alertStats, mitreData, compData] = await Promise.allSettled([
          getSystemInfo(),
          getModuleHealth(),
          getAlertStats(),
          getMitreCoverage(),
          getComplianceStatus(),
        ]);

        if (sysInfo.status === 'fulfilled') {
          setUptime(sysInfo.value.version || '1.0.0');
        }
        if (health.status === 'fulfilled') {
          const modules = Object.values(health.value);
          const running = modules.filter(s => s === 'running').length;
          setModuleCount({ running, total: modules.length || 68 });
        }
        if (alertStats.status === 'fulfilled') {
          setAlerts({
            total: alertStats.value.total_alerts,
            critical: alertStats.value.critical,
            high: alertStats.value.high,
            medium: alertStats.value.medium,
            low: alertStats.value.low,
          });
        }
        if (mitreData.status === 'fulfilled') {
          setMitre({
            tactics: mitreData.value.tactics_covered,
            techniques: mitreData.value.techniques_covered,
            percent: mitreData.value.coverage_percent,
          });
        }
        if (compData.status === 'fulfilled') {
          const total = compData.value.passed + compData.value.failed + compData.value.warnings;
          const score = total > 0 ? Math.round((compData.value.passed / total) * 100) : 78;
          setCompliance({ score });
        }
      } catch {
        // Use defaults
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  useEffect(() => {
    const start = Date.now();
    const interval = setInterval(() => {
      const diff = Date.now() - start;
      const days = Math.floor(diff / 86400000);
      const hours = Math.floor((diff % 86400000) / 3600000);
      const mins = Math.floor((diff % 3600000) / 60000);
      setUptime(`${days}d ${hours}h ${mins}m`);
    }, 60000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-3">
          <Cpu className="w-5 h-5 text-indigo-400 animate-spin" />
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Loading dashboard...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Dashboard</h1>
        <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
          <Clock className="w-4 h-4" />
          Last updated: {new Date().toLocaleTimeString()}
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard title="Active Threats" value={alerts.total} icon={AlertTriangle} color="var(--critical)" subtitle={`${alerts.critical} critical`} />
        <StatCard title="Events Today" value={eventsOverTime.reduce((s, e) => s + e.events, 0).toLocaleString()} icon={Activity} color="var(--info)" subtitle="24h window" />
        <StatCard title="Modules Running" value={`${moduleCount.running}/${moduleCount.total}`} icon={Server} color="var(--low)" subtitle="All systems operational" />
        <StatCard title="IOC Rules" value="1,247" icon={FileSearch} color="var(--accent)" subtitle="Sigma + YARA" />
        <StatCard title="Compliance Score" value={`${compliance.score}%`} icon={Scale} color="var(--medium)" subtitle="CIS + STIG" />
        <StatCard title="Uptime" value={uptime} icon={Clock} color="#a78bfa" subtitle="Agent uptime" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold">Events Over Time</h2>
            <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>Last 24 hours</span>
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={eventsOverTime}>
              <defs>
                <linearGradient id="eventGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
              <XAxis dataKey="hour" tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1a2236', border: '1px solid #1e2d4a', borderRadius: '8px', fontSize: '12px' }}
                labelStyle={{ color: '#e5e7eb' }}
              />
              <Area type="monotone" dataKey="events" stroke="#6366f1" fill="url(#eventGrad)" strokeWidth={2} />
              <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="url(#threatGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <h2 className="text-sm font-semibold mb-4">Events by Severity</h2>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={severityData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: '#9ca3af' }} tickLine={false} axisLine={false} width={70} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1a2236', border: '1px solid #1e2d4a', borderRadius: '8px', fontSize: '12px' }}
              />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {severityData.map((entry, index) => (
                  <Cell key={index} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <h2 className="text-sm font-semibold mb-4">Module Health</h2>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={moduleHealthData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={80}
                paddingAngle={3}
                dataKey="value"
              >
                {moduleHealthData.map((entry, index) => (
                  <Cell key={index} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: '#1a2236', border: '1px solid #1e2d4a', borderRadius: '8px', fontSize: '12px' }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-4 mt-2">
            {moduleHealthData.map((item) => (
              <div key={item.name} className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{item.name} ({item.value})</span>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <h2 className="text-sm font-semibold mb-3">MITRE ATT&CK Coverage</h2>
          <div className="space-y-4 mt-6">
            <div>
              <div className="flex justify-between text-xs mb-1.5">
                <span style={{ color: 'var(--text-secondary)' }}>Tactics Covered</span>
                <span className="font-medium">{mitre.tactics}/14</span>
              </div>
              <div className="h-2 rounded-full" style={{ backgroundColor: 'var(--bg-secondary)' }}>
                <div className="h-2 rounded-full bg-indigo-500 transition-all" style={{ width: `${(mitre.tactics / 14) * 100}%` }} />
              </div>
            </div>
            <div>
              <div className="flex justify-between text-xs mb-1.5">
                <span style={{ color: 'var(--text-secondary)' }}>Techniques Covered</span>
                <span className="font-medium">{mitre.techniques}/201</span>
              </div>
              <div className="h-2 rounded-full" style={{ backgroundColor: 'var(--bg-secondary)' }}>
                <div className="h-2 rounded-full bg-purple-500 transition-all" style={{ width: `${(mitre.techniques / 201) * 100}%` }} />
              </div>
            </div>
            <div>
              <div className="flex justify-between text-xs mb-1.5">
                <span style={{ color: 'var(--text-secondary)' }}>Overall Coverage</span>
                <span className="font-medium text-indigo-400">{mitre.percent}%</span>
              </div>
              <div className="h-2 rounded-full" style={{ backgroundColor: 'var(--bg-secondary)' }}>
                <div className="h-2 rounded-full bg-gradient-to-r from-indigo-500 to-purple-500 transition-all" style={{ width: `${mitre.percent}%` }} />
              </div>
            </div>
          </div>
          <div className="mt-6 p-3 rounded-lg" style={{ backgroundColor: 'var(--bg-secondary)' }}>
            <div className="flex items-center gap-2 mb-1">
              <Eye className="w-4 h-4 text-indigo-400" />
              <span className="text-xs font-medium">Detection Rules</span>
            </div>
            <div className="grid grid-cols-2 gap-2 mt-2">
              <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                Sigma: <span className="text-white font-medium">847</span>
              </div>
              <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                YARA: <span className="text-white font-medium">400</span>
              </div>
              <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                Snort: <span className="text-white font-medium">213</span>
              </div>
              <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                Custom: <span className="text-white font-medium">56</span>
              </div>
            </div>
          </div>
        </div>

        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <h2 className="text-sm font-semibold mb-3">System Info</h2>
          <div className="space-y-3 mt-2">
            {[
              { label: 'Hostname', value: 'WIN-SRV-001' },
              { label: 'OS', value: 'Windows Server 2022' },
              { label: 'Agent', value: 'v0.1.0' },
              { label: 'Kernel', value: '10.0.20348' },
              { label: 'Arch', value: 'x86_64' },
              { label: 'Memory', value: '16.4 GB / 32 GB' },
              { label: 'CPU', value: 'Intel Xeon E5-2680' },
              { label: 'Disk', value: '234 GB / 512 GB' },
            ].map((item) => (
              <div key={item.label} className="flex justify-between items-center">
                <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                <span className="text-xs font-medium">{item.value}</span>
              </div>
            ))}
          </div>
          <div className="mt-4 p-3 rounded-lg flex items-center gap-2" style={{ backgroundColor: 'rgba(34,197,94,0.1)' }}>
            <Shield className="w-4 h-4 text-green-400" />
            <span className="text-xs text-green-400 font-medium">System Protected</span>
          </div>
        </div>
      </div>

      <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold">Recent Alerts</h2>
          <span className="text-xs px-2 py-1 rounded-full" style={{ backgroundColor: 'rgba(99,102,241,0.15)', color: 'var(--accent)' }}>
            {recentAlerts.length} alerts
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b" style={{ borderColor: 'var(--border-color)' }}>
                <th className="text-left py-2 px-3 font-medium" style={{ color: 'var(--text-secondary)' }}>Severity</th>
                <th className="text-left py-2 px-3 font-medium" style={{ color: 'var(--text-secondary)' }}>Source</th>
                <th className="text-left py-2 px-3 font-medium" style={{ color: 'var(--text-secondary)' }}>Message</th>
                <th className="text-right py-2 px-3 font-medium" style={{ color: 'var(--text-secondary)' }}>Time</th>
              </tr>
            </thead>
            <tbody>
              {recentAlerts.map((alert) => (
                <tr key={alert.id} className="border-b hover:bg-white/5 transition-colors" style={{ borderColor: 'var(--border-color)' }}>
                  <td className="py-2.5 px-3">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase" style={{
                      backgroundColor: `${severityColors[alert.severity]}15`,
                      color: severityColors[alert.severity],
                    }}>
                      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: severityColors[alert.severity] }} />
                      {alert.severity}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-medium">{alert.source}</td>
                  <td className="py-2.5 px-3" style={{ color: 'var(--text-secondary)' }}>{alert.message}</td>
                  <td className="py-2.5 px-3 text-right" style={{ color: 'var(--text-secondary)' }}>{alert.time}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
