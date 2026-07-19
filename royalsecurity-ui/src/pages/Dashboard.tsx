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

  const now = new Date();
  const dateStr = now.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
  const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  const totalEvents = eventsOverTime.reduce((sum, d) => sum + d.events, 0);
  const totalThreats = eventsOverTime.reduce((sum, d) => sum + d.threats, 0);
  const peakHour = eventsOverTime.reduce((max, d) => d.events > max.events ? d : max, { hour: '--:--', events: 0, threats: 0 });
  const avgEventsPerHour = eventsOverTime.length > 0 ? (totalEvents / eventsOverTime.length).toFixed(1) : '0';
  const threatRate = totalEvents > 0 ? ((totalThreats / totalEvents) * 100).toFixed(1) : '0';
  const totalRules = ruleCounts.sigma + ruleCounts.yara + ruleCounts.snort + ruleCounts.custom;
  const hasThreats = totalThreats > 0;
  const runningTotal = moduleHealthData.reduce((s, d) => s + d.value, 0);

  const defaultData24h = Array.from({ length: 24 }, (_, i) => ({ hour: `${String(i).padStart(2, '0')}:00`, events: 0, threats: 0 }));
  const defaultSeverity = [{ name: 'Critical', value: 0, color: '#ef4444' }, { name: 'High', value: 0, color: '#f97316' }, { name: 'Medium', value: 0, color: '#eab308' }, { name: 'Low', value: 0, color: '#22c55e' }];
  const chartData = eventsOverTime.length > 0 ? eventsOverTime : defaultData24h;
  const sevData = severityData.length > 0 ? severityData : defaultSeverity;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex flex-col items-center gap-4">
          <div className="relative w-12 h-12">
            <div className="absolute inset-0 rounded-full border-2" style={{ borderColor: 'rgba(201,168,76,0.15)' }} />
            <div className="absolute inset-0 rounded-full border-2 border-t-transparent animate-spin" style={{ borderColor: 'transparent', borderTopColor: '#c9a84c' }} />
            <Cpu className="absolute inset-0 m-auto w-5 h-5" style={{ color: '#c9a84c' }} />
          </div>
          <div className="flex flex-col items-center gap-1">
            <span className="text-xs font-semibold uppercase tracking-widest" style={{ color: '#c9a84c' }}>Initializing</span>
            <span className="text-[10px] uppercase tracking-[0.2em] animate-pulse" style={{ color: 'var(--text-secondary)' }}>Scanning defenses</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* ── HEADER ROW ── */}
      <div className="flex items-end justify-between">
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-[0.15em]" style={{ color: 'var(--text-secondary)' }}>
            Command Center
          </div>
          <div className="text-2xl font-light mt-1" style={{ color: 'var(--text-primary)' }}>
            {dateStr}
            <span className="ml-3 font-mono font-semibold" style={{ color: '#c9a84c' }}>{timeStr}</span>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={load}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all hover:translate-y-[-1px]"
            style={{
              border: '1px solid #c9a84c',
              color: '#c9a84c',
              backgroundColor: 'transparent',
            }}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
          <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-tertiary)' }}>
            <Clock className="w-3.5 h-3.5" />
            Last scanned {lastUpdated}
          </div>
        </div>
      </div>

      {/* ── STAT CARDS ── */}
      <style>{`
        @keyframes staggerFadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes pulseGlow { 0%, 100% { box-shadow: 0 0 0 0 rgba(201,168,76,0); } 50% { box-shadow: 0 0 12px 2px rgba(201,168,76,0.15); } }
        @keyframes slideInRight { from { opacity: 0; transform: translateX(16px); } to { opacity: 1; transform: translateX(0); } }
        @keyframes breathe { 0%, 100% { transform: scale(1); opacity: 0.7; } 50% { transform: scale(1.3); opacity: 1; } }
      `}</style>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {[
          { title: 'Active Threats', value: alerts.total, icon: AlertTriangle, color: 'var(--critical)', subtitle: `${alerts.critical} critical`, borderColor: 'var(--critical)' },
          { title: 'Modules Running', value: `${moduleCount.running}/${moduleCount.total}`, icon: Server, color: 'var(--low)', subtitle: 'All systems operational', borderColor: 'var(--low)' },
          { title: 'Compliance Score', value: `${compliance.score}%`, icon: Scale, color: 'var(--medium)', subtitle: 'CIS + STIG', borderColor: 'var(--medium)' },
          { title: 'MITRE Coverage', value: `${mitre.percent}%`, icon: Eye, color: '#c9a84c', subtitle: `${mitre.tactics} tactics`, borderColor: '#c9a84c' },
          { title: 'IOC Rules', value: totalRules || '—', icon: FileSearch, color: 'var(--info)', subtitle: 'Sigma + YARA', borderColor: 'var(--info)' },
          { title: 'Uptime', value: uptime, icon: Clock, color: '#a78bfa', subtitle: 'Agent uptime', borderColor: '#a78bfa' },
        ].map((card, idx) => (
          <div
            key={card.title}
            className="rounded-xl p-4 transition-all duration-200 hover:translate-y-[-1px] cursor-default"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderLeft: `4px solid ${card.borderColor}`,
              border: `1px solid var(--border-color)`,
              borderLeftWidth: '4px',
              borderLeftColor: card.borderColor,
              animation: `staggerFadeIn 0.4s ease-out ${idx * 50}ms both`,
            }}
          >
            <div className="flex items-center gap-2 mb-3">
              <div
                className="w-8 h-8 rounded-full flex items-center justify-center"
                style={{ backgroundColor: `color-mix(in srgb, ${card.borderColor} 10%, transparent)` }}
              >
                <card.icon className="w-4 h-4" style={{ color: card.color }} />
              </div>
              <span className="text-[10px] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--text-secondary)' }}>
                {card.title}
              </span>
            </div>
            <div className="text-3xl font-bold font-mono" style={{ color: 'var(--text-primary)' }}>{card.value}</div>
            {card.subtitle && (
              <div className="text-xs mt-1.5" style={{ color: 'var(--text-tertiary)' }}>{card.subtitle}</div>
            )}
          </div>
        ))}
      </div>

      {/* ── MAIN CONTENT: 3:2 ASYMMETRIC ── */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* LEFT COLUMN (wider: 3/5) */}
        <div className="lg:col-span-3 space-y-4">
          {/* EVENTS TIMELINE */}
          <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', animation: 'staggerFadeIn 0.4s ease-out 300ms both' }}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2.5">
                <h2 className="text-xs font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--text-secondary)' }}>Threat Activity</h2>
                {hasThreats && (
                  <span className="relative flex h-2.5 w-2.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ backgroundColor: 'var(--critical)' }} />
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5" style={{ backgroundColor: 'var(--critical)' }} />
                  </span>
                )}
              </div>
              <span className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>Last 24 hours</span>
            </div>

            <ResponsiveContainer width="100%" height={240}>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="goldGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#c9a84c" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#c9a84c" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="crimsonGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#e83e3e" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#e83e3e" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" opacity={0.1} />
                <XAxis dataKey="hour" tick={{ fontSize: 9, fill: 'var(--text-tertiary)' }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 9, fill: 'var(--text-tertiary)' }} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'var(--bg-elevated)',
                    border: '1px solid #c9a84c',
                    borderRadius: '8px',
                    fontSize: '11px',
                    padding: '8px 12px',
                  }}
                  labelStyle={{ color: 'var(--text-secondary)', marginBottom: '4px' }}
                  itemStyle={{ padding: 0 }}
                />
                <Area type="monotone" dataKey="events" stroke="#c9a84c" fill="url(#goldGrad)" strokeWidth={2} dot={false} />
                <Area type="monotone" dataKey="threats" stroke="#e83e3e" fill="url(#crimsonGrad)" strokeWidth={2} dot={false} />
              </AreaChart>
            </ResponsiveContainer>

            {/* Mini stats row */}
            <div className="grid grid-cols-3 gap-3 mt-4 pt-3" style={{ borderTop: '1px solid var(--border-color)' }}>
              {[
                { label: 'Peak Hour', value: peakHour.hour, sub: `${peakHour.events} events` },
                { label: 'Avg Events/Hour', value: avgEventsPerHour, sub: '24h average' },
                { label: 'Threat Rate', value: `${threatRate}%`, sub: 'of total events' },
              ].map((ms) => (
                <div key={ms.label} className="text-center">
                  <div className="text-[9px] uppercase tracking-[0.1em] mb-1" style={{ color: 'var(--text-tertiary)' }}>{ms.label}</div>
                  <div className="text-lg font-bold font-mono" style={{ color: '#c9a84c' }}>{ms.value}</div>
                  <div className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{ms.sub}</div>
                </div>
              ))}
            </div>
          </div>

          {/* SIGNAL INTELLIGENCE (Recent Alerts) */}
          <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', animation: 'staggerFadeIn 0.4s ease-out 400ms both' }}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2.5">
                <h2 className="text-xs font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--text-secondary)' }}>Signal Intelligence</h2>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded" style={{ backgroundColor: 'rgba(201,168,76,0.15)', color: '#c9a84c' }}>
                  {recentAlerts.length > 0 ? `${recentAlerts.length}` : '0'}
                </span>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                    {['Severity', 'Source', 'Message', 'Time'].map((h) => (
                      <th key={h} className={`py-2 px-3 font-semibold uppercase tracking-wider text-[9px] ${h === 'Time' ? 'text-right' : 'text-left'}`} style={{ color: 'var(--text-tertiary)' }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {recentAlerts.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="py-8 text-center" style={{ color: 'var(--text-tertiary)' }}>
                        <div className="flex flex-col items-center gap-2">
                          <Shield className="w-5 h-5 opacity-30" />
                          <span className="text-[10px] uppercase tracking-wider">No signals detected</span>
                        </div>
                      </td>
                    </tr>
                  ) : recentAlerts.map((alert, idx) => (
                    <tr
                      key={alert.id}
                      className="transition-all duration-200 group"
                      style={{
                        borderBottom: '1px solid var(--border-color)',
                        animation: `slideInRight 0.3s ease-out ${idx * 50}ms both`,
                      }}
                      onMouseEnter={(e) => {
                        (e.currentTarget as HTMLElement).style.borderLeftColor = '#c9a84c';
                        (e.currentTarget as HTMLElement).style.borderLeftWidth = '2px';
                      }}
                      onMouseLeave={(e) => {
                        (e.currentTarget as HTMLElement).style.borderLeftColor = 'transparent';
                        (e.currentTarget as HTMLElement).style.borderLeftWidth = '0px';
                      }}
                    >
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-1.5">
                          <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: severityColors[alert.severity] || 'var(--text-secondary)' }} />
                          <span className="text-[10px] font-bold uppercase tracking-wider" style={{ color: severityColors[alert.severity] || 'var(--text-secondary)' }}>
                            {alert.severity}
                          </span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px]" style={{ color: 'var(--text-secondary)' }}>{alert.source}</td>
                      <td className="py-2.5 px-3 max-w-[200px] truncate" style={{ color: 'var(--text-secondary)' }}>{alert.message}</td>
                      <td className="py-2.5 px-3 text-right whitespace-nowrap" style={{ color: 'var(--text-tertiary)' }}>{alert.time}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN (narrower: 2/5) */}
        <div className="lg:col-span-2 space-y-4">
          {/* DEFENSE POSTURE */}
          <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', animation: 'staggerFadeIn 0.4s ease-out 350ms both' }}>
            <h2 className="text-xs font-semibold uppercase tracking-[0.1em] mb-5" style={{ color: 'var(--text-secondary)' }}>Defense Posture</h2>

            {/* Circular score indicator */}
            <div className="flex justify-center mb-5">
              <div className="relative w-32 h-32">
                {/* Outer ring with gold gradient border */}
                <svg className="w-full h-full -rotate-90" viewBox="0 0 128 128">
                  <defs>
                    <linearGradient id="goldRing" x1="0%" y1="0%" x2="100%" y2="100%">
                      <stop offset="0%" stopColor="#c9a84c" />
                      <stop offset="100%" stopColor="#a07d2e" />
                    </linearGradient>
                  </defs>
                  <circle cx="64" cy="64" r="56" fill="none" stroke="var(--border-color)" strokeWidth="4" />
                  <circle
                    cx="64" cy="64" r="56"
                    fill="none"
                    stroke="url(#goldRing)"
                    strokeWidth="4"
                    strokeLinecap="round"
                    strokeDasharray={`${(compliance.score / 100) * 352} 352`}
                    style={{ animation: 'staggerFadeIn 0.6s ease-out 500ms both' }}
                  />
                </svg>
                {/* Inner content */}
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-3xl font-bold font-mono" style={{ color: '#c9a84c' }}>{compliance.score}%</span>
                  <span className="text-[9px] uppercase tracking-[0.15em] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>Defense Score</span>
                </div>
              </div>
            </div>

            {/* Module health bars */}
            <div className="space-y-3">
              {[
                { label: 'Running', count: moduleHealthData.find(d => d.name === 'Running')?.value || 0, color: '#22c55e' },
                { label: 'Degraded', count: moduleHealthData.find(d => d.name === 'Degraded')?.value || 0, color: '#eab308' },
                { label: 'Stopped', count: moduleHealthData.find(d => d.name === 'Stopped')?.value || 0, color: '#ef4444' },
              ].filter(b => b.count > 0).map((bar) => (
                <div key={bar.label}>
                  <div className="flex justify-between items-center mb-1.5">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: bar.color }} />
                      <span className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-secondary)' }}>{bar.label}</span>
                    </div>
                    <span className="text-xs font-mono font-semibold">{bar.count}</span>
                  </div>
                  <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-secondary)' }}>
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: runningTotal > 0 ? `${(bar.count / runningTotal) * 100}%` : '0%',
                        backgroundColor: bar.color,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* ATT&CK COVERAGE */}
          <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', animation: 'staggerFadeIn 0.4s ease-out 450ms both' }}>
            <h2 className="text-xs font-semibold uppercase tracking-[0.1em] mb-5" style={{ color: 'var(--text-secondary)' }}>ATT&CK Coverage</h2>

            {/* CSS-only circular progress */}
            <div className="flex justify-center mb-5">
              <div className="relative w-24 h-24">
                <svg className="w-full h-full -rotate-90" viewBox="0 0 96 96">
                  <circle cx="48" cy="48" r="40" fill="none" stroke="var(--border-color)" strokeWidth="5" />
                  <circle
                    cx="48" cy="48" r="40"
                    fill="none"
                    stroke="url(#goldRing)"
                    strokeWidth="5"
                    strokeLinecap="round"
                    strokeDasharray={`${(mitre.percent / 100) * 251} 251`}
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-xl font-bold font-mono" style={{ color: '#c9a84c' }}>{mitre.percent}%</span>
                </div>
              </div>
            </div>

            {/* Tactics & Techniques progress bars */}
            <div className="space-y-3 mb-5">
              <div>
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-secondary)' }}>Tactics</span>
                  <span className="text-[11px] font-mono font-semibold">{mitre.tactics}/14</span>
                </div>
                <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-secondary)' }}>
                  <div className="h-full rounded-full transition-all duration-500" style={{ width: `${(mitre.tactics / 14) * 100}%`, background: 'linear-gradient(90deg, #c9a84c, #a07d2e)' }} />
                </div>
              </div>
              <div>
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-secondary)' }}>Techniques</span>
                  <span className="text-[11px] font-mono font-semibold">{mitre.techniques}/201</span>
                </div>
                <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-secondary)' }}>
                  <div className="h-full rounded-full transition-all duration-500" style={{ width: `${(mitre.techniques / 201) * 100}%`, background: 'linear-gradient(90deg, #c9a84c, #a07d2e)' }} />
                </div>
              </div>
            </div>

            {/* Detection rules 2x2 grid */}
            <div className="grid grid-cols-2 gap-2 p-3 rounded-lg" style={{ backgroundColor: 'var(--bg-secondary)' }}>
              {[
                { label: 'Sigma', val: ruleCounts.sigma },
                { label: 'YARA', val: ruleCounts.yara },
                { label: 'Snort', val: ruleCounts.snort },
                { label: 'Custom', val: ruleCounts.custom },
              ].map((r) => (
                <div key={r.label} className="flex justify-between items-center">
                  <span className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>{r.label}</span>
                  <span className="text-xs font-mono font-bold" style={{ color: 'var(--text-primary)' }}>{r.val || '—'}</span>
                </div>
              ))}
            </div>
          </div>

          {/* SYSTEM INTEL */}
          <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', animation: 'staggerFadeIn 0.4s ease-out 550ms both' }}>
            <h2 className="text-xs font-semibold uppercase tracking-[0.1em] mb-4" style={{ color: 'var(--text-secondary)' }}>System Intel</h2>
            <div className="space-y-0">
              {[
                { label: 'Hostname', value: systemInfo.hostname },
                { label: 'OS', value: systemInfo.os },
                { label: 'Agent', value: systemInfo.agent_name || systemInfo.version },
                { label: 'Version', value: systemInfo.version },
                { label: 'Arch', value: systemInfo.arch },
              ].map((item, idx, arr) => (
                <div
                  key={item.label}
                  className="flex justify-between items-center py-2.5"
                  style={{ borderBottom: idx < arr.length - 1 ? '1px solid var(--border-color)' : 'none' }}
                >
                  <span className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-tertiary)' }}>{item.label}</span>
                  <span className="text-xs font-mono font-medium" style={{ color: 'var(--text-primary)' }}>{item.value}</span>
                </div>
              ))}
            </div>
            {/* Sentinel badge */}
            <div
              className="mt-4 flex items-center justify-center gap-2 py-2.5 rounded-lg"
              style={{
                background: 'linear-gradient(135deg, rgba(34,197,94,0.08), rgba(34,197,94,0.02))',
                border: '1px solid rgba(34,197,94,0.2)',
                animation: 'pulseGlow 3s ease-in-out infinite',
              }}
            >
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ backgroundColor: '#22c55e' }} />
                <span className="relative inline-flex rounded-full h-2 w-2" style={{ backgroundColor: '#22c55e' }} />
              </span>
              <span className="text-[10px] font-bold uppercase tracking-[0.15em]" style={{ color: '#22c55e' }}>Sentinel Active</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
