import { useState, useEffect, useCallback } from 'react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import {
  Shield, Activity, AlertTriangle, FileSearch, Scale, Clock,
  Server, Eye, Cpu, RefreshCw
} from 'lucide-react';
import {
  getSystemInfo, getModuleHealth, getAlertStats, getMitreCoverage,
  getComplianceStatus, getEvents, getDetectionRules
} from '../lib/tauri-bridge';

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

const severityColors: Record<string, string> = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
};

export default function Dashboard() {
  const [uptime, setUptime] = useState('0d 0h 0m');
  const [moduleName, setModuleName] = useState('RoyalSecurity');
  const [moduleCount, setModuleCount] = useState({ running: 0, total: 0 });
  const [alerts, setAlerts] = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0 });
  const [mitre, setMitre] = useState({ tactics: 0, techniques: 0, percent: 0 });
  const [compliance, setCompliance] = useState({ score: 0 });
  const [systemInfo, setSystemInfo] = useState({ hostname: '-', os: '-', version: '-', arch: '-', agent_name: '-' });
  const [eventsOverTime, setEventsOverTime] = useState<Array<{ hour: string; events: number; threats: number }>>([]);
  const [recentAlerts, setRecentAlerts] = useState<Array<{ id: number; severity: string; source: string; message: string; time: string }>>([]);
  const [moduleHealthData, setModuleHealthData] = useState<Array<{ name: string; value: number; color: string }>>([]);
  const [severityData, setSeverityData] = useState<Array<{ name: string; value: number; color: string }>>([]);
  const [ruleCounts, setRuleCounts] = useState({ sigma: 0, yara: 0, snort: 0, custom: 0 });
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState('');

  const load = useCallback(async () => {
    try {
      const [sysInfo, health, alertStats, mitreData, compData, events, detectionRules] = await Promise.allSettled([
        getSystemInfo(),
        getModuleHealth(),
        getAlertStats(),
        getMitreCoverage(),
        getComplianceStatus(),
        getEvents(50),
        getDetectionRules(),
      ]);

      if (sysInfo.status === 'fulfilled') {
        const s = sysInfo.value;
        setSystemInfo(s);
        setModuleName(s.agent_name || 'RoyalSecurity');
      }

      if (health.status === 'fulfilled') {
        const modules = Object.entries(health.value);
        const running = modules.filter(([, s]) => s === 'running').length;
        setModuleCount({ running, total: modules.length });
        const runningCount = modules.filter(([, s]) => s === 'running').length;
        const degradedCount = modules.filter(([, s]) => s === 'degraded').length;
        const stoppedCount = modules.filter(([, s]) => s !== 'running' && s !== 'degraded').length;
        setModuleHealthData([
          { name: 'Running', value: runningCount, color: '#22c55e' },
          { name: 'Degraded', value: degradedCount, color: '#eab308' },
          { name: 'Stopped', value: stoppedCount, color: '#ef4444' },
        ].filter(d => d.value > 0));
      }

      if (alertStats.status === 'fulfilled') {
        const a = alertStats.value;
        setAlerts({ total: a.total_alerts, critical: a.critical, high: a.high, medium: a.medium, low: a.low });
        setSeverityData([
          { name: 'Critical', value: a.critical, color: '#ef4444' },
          { name: 'High', value: a.high, color: '#f97316' },
          { name: 'Medium', value: a.medium, color: '#eab308' },
          { name: 'Low', value: a.low, color: '#22c55e' },
        ]);
      }

      if (mitreData.status === 'fulfilled') {
        const m = mitreData.value;
        setMitre({ tactics: m.tactics_covered, techniques: m.techniques_covered, percent: m.coverage_percent });
      }

      if (compData.status === 'fulfilled') {
        const c = compData.value;
        const total = c.passed + c.failed + c.warnings;
        setCompliance({ score: total > 0 ? Math.round((c.passed / total) * 100) : 0 });
      }

      if (events.status === 'fulfilled' && Array.isArray(events.value)) {
        const bucketed: Record<string, { events: number; threats: number }> = {};
        for (let i = 0; i < 24; i++) {
          bucketed[`${String(i).padStart(2, '0')}:00`] = { events: 0, threats: 0 };
        }
        const recentList: Array<{ id: number; severity: string; source: string; message: string; time: string }> = [];
        events.value.forEach((evt: any, idx: number) => {
          const d = new Date(evt.timestamp || Date.now());
          const hour = `${String(d.getHours()).padStart(2, '0')}:00`;
          if (bucketed[hour]) bucketed[hour].events++;
          if (evt.severity === 'critical' || evt.severity === 'high') bucketed[hour].threats++;
          if (idx < 7) {
            recentList.push({
              id: idx + 1,
              severity: evt.severity || 'low',
              source: evt.source || 'System',
              message: evt.message || evt.details || 'Event recorded',
              time: evt.time || d.toLocaleTimeString(),
            });
          }
        });
        setEventsOverTime(Object.entries(bucketed).map(([hour, data]) => ({ hour, ...data })));
        if (recentList.length > 0) setRecentAlerts(recentList);
      }

      if (detectionRules.status === 'fulfilled') {
        const r = detectionRules.value;
        setRuleCounts({ sigma: r.sigma_rules, yara: r.yara_rules, snort: r.dsl_rules, custom: 0 });
      }
    } catch {
      // Use defaults
    } finally {
      setLoading(false);
      setLastUpdated(new Date().toLocaleTimeString());
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

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
        <div className="flex items-center gap-3">
          <button onClick={load} className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors">
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
          <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
            <Clock className="w-4 h-4" />
            Last updated: {lastUpdated}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard title="Active Threats" value={alerts.total} icon={AlertTriangle} color="var(--critical)" subtitle={`${alerts.critical} critical`} />
        <StatCard title="Modules Running" value={`${moduleCount.running}/${moduleCount.total}`} icon={Server} color="var(--low)" subtitle="All systems operational" />
        <StatCard title="Compliance Score" value={`${compliance.score}%`} icon={Scale} color="var(--medium)" subtitle="CIS + STIG" />
        <StatCard title="MITRE Coverage" value={`${mitre.percent}%`} icon={Eye} color="var(--accent)" subtitle={`${mitre.tactics} tactics`} />
        <StatCard title="IOC Rules" value={`${ruleCounts.sigma + ruleCounts.yara + ruleCounts.snort + ruleCounts.custom || '—'}`} icon={FileSearch} color="var(--info)" subtitle="Sigma + YARA" />
        <StatCard title="Uptime" value={uptime} icon={Clock} color="#a78bfa" subtitle="Agent uptime" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold">Events Over Time</h2>
            <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>Last 24 hours</span>
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={eventsOverTime.length > 0 ? eventsOverTime : Array.from({ length: 24 }, (_, i) => ({ hour: `${String(i).padStart(2, '0')}:00`, events: 0, threats: 0 }))}>
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
              <Tooltip contentStyle={{ backgroundColor: '#1a2236', border: '1px solid #1e2d4a', borderRadius: '8px', fontSize: '12px' }} labelStyle={{ color: '#e5e7eb' }} />
              <Area type="monotone" dataKey="events" stroke="#6366f1" fill="url(#eventGrad)" strokeWidth={2} />
              <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="url(#threatGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <h2 className="text-sm font-semibold mb-4">Events by Severity</h2>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={severityData.length > 0 ? severityData : [{ name: 'Critical', value: 0, color: '#ef4444' }, { name: 'High', value: 0, color: '#f97316' }, { name: 'Medium', value: 0, color: '#eab308' }, { name: 'Low', value: 0, color: '#22c55e' }]} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: '#9ca3af' }} tickLine={false} axisLine={false} width={70} />
              <Tooltip contentStyle={{ backgroundColor: '#1a2236', border: '1px solid #1e2d4a', borderRadius: '8px', fontSize: '12px' }} />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {(severityData.length > 0 ? severityData : [{ name: 'Critical', value: 0, color: '#ef4444' }, { name: 'High', value: 0, color: '#f97316' }, { name: 'Medium', value: 0, color: '#eab308' }, { name: 'Low', value: 0, color: '#22c55e' }]).map((entry, index) => (
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
              <Pie data={moduleHealthData.length > 0 ? moduleHealthData : [{ name: 'No Data', value: 1, color: '#4b5563' }]} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3} dataKey="value">
                {(moduleHealthData.length > 0 ? moduleHealthData : [{ name: 'No Data', value: 1, color: '#4b5563' }]).map((entry, index) => (
                  <Cell key={index} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: '#1a2236', border: '1px solid #1e2d4a', borderRadius: '8px', fontSize: '12px' }} />
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
                <span className="text-xs font-medium text-indigo-400">{mitre.percent}%</span>
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
              <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>Sigma: <span className="text-white font-medium">{ruleCounts.sigma || '—'}</span></div>
              <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>YARA: <span className="text-white font-medium">{ruleCounts.yara || '—'}</span></div>
              <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>Snort: <span className="text-white font-medium">{ruleCounts.snort || '—'}</span></div>
              <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>Custom: <span className="text-white font-medium">{ruleCounts.custom || '—'}</span></div>
            </div>
          </div>
        </div>

        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <h2 className="text-sm font-semibold mb-3">System Info</h2>
          <div className="space-y-3 mt-2">
            {[
              { label: 'Hostname', value: systemInfo.hostname },
              { label: 'OS', value: systemInfo.os },
              { label: 'Agent', value: systemInfo.agent_name || systemInfo.version },
              { label: 'Version', value: systemInfo.version },
              { label: 'Arch', value: systemInfo.arch },
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
            {recentAlerts.length > 0 ? `${recentAlerts.length} alerts` : 'No alerts'}
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
              {recentAlerts.length === 0 ? (
                <tr><td colSpan={4} className="py-6 text-center" style={{ color: 'var(--text-secondary)' }}>No recent alerts</td></tr>
              ) : recentAlerts.map((alert) => (
                <tr key={alert.id} className="border-b hover:bg-white/5 transition-colors" style={{ borderColor: 'var(--border-color)' }}>
                  <td className="py-2.5 px-3">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase" style={{
                      backgroundColor: `${severityColors[alert.severity] || 'var(--text-secondary)'}15`,
                      color: severityColors[alert.severity] || 'var(--text-secondary)',
                    }}>
                      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: severityColors[alert.severity] || 'var(--text-secondary)' }} />
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
