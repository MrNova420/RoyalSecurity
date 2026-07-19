import { useState, useEffect, useCallback } from 'react';
import {
  Search, RefreshCw, AlertTriangle, ArrowUpRight, ArrowDownLeft, Wifi, Ban, CheckCircle
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import { getNetworkConnections, blockIp } from '../lib/tauri-bridge';
import type { NetworkConnection } from '../lib/tauri-bridge';

export default function NetworkPage() {
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [search, setSearch] = useState('');
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message });
    setTimeout(() => setFeedback(null), 4000);
  };

  const load = useCallback(async () => {
    try {
      const data = await getNetworkConnections();
      if (Array.isArray(data)) {
        setConnections(data);
      }
    } catch {
      // Use empty
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

  const handleBlockIp = async (ip: string) => {
    try {
      const result = await blockIp(ip);
      showFeedback('success', result.message || `Blocked IP: ${ip}`);
      load();
    } catch (err: any) {
      showFeedback('error', err?.toString() || `Failed to block IP: ${ip}`);
    }
  };

  const filtered = connections.filter((c) => {
    if (flaggedOnly && !c.flagged) return false;
    if (search) {
      const s = search.toLowerCase();
      return c.remote_addr.includes(s) || c.process.toLowerCase().includes(s) || c.local_addr.includes(s);
    }
    return true;
  });

  const flaggedCount = connections.filter((c) => c.flagged).length;
  const inboundCount = connections.filter(c => c.direction === 'inbound').length;
  const outboundCount = connections.filter(c => c.direction === 'outbound').length;

  const protocolCounts: Record<string, number> = {};
  connections.forEach(c => { protocolCounts[c.protocol] = (protocolCounts[c.protocol] || 0) + 1; });
  const protocolData = Object.entries(protocolCounts).map(([name, value], i) => ({
    name, value, color: ['#6366f1', '#3b82f6', '#a78bfa', '#f97316'][i % 4],
  }));

  const portCounts: Record<string, { service: string; count: number }> = {};
  const portMap: Record<string, string> = { '443': 'HTTPS', '53': 'DNS', '1433': 'MSSQL', '445': 'SMB', '3389': 'RDP', '80': 'HTTP', '8080': 'HTTP-Alt', '8443': 'HTTPS-Alt' };
  connections.forEach(c => {
    const port = String(c.remote_port);
    if (!portCounts[port]) portCounts[port] = { service: portMap[port] || `Port ${port}`, count: 0 };
    portCounts[port].count++;
  });
  const topPorts = Object.entries(portCounts).sort((a, b) => b[1].count - a[1].count).slice(0, 5);

  const trafficData = Array.from({ length: 24 }, (_, i) => {
    const hourLabel = `${String(i).padStart(2, '0')}:00`;
    const inbound = connections.filter(c => c.direction === 'inbound' && new Date(c.id).getHours() === i).length || (i === new Date().getHours() ? inboundCount : 0);
    const outbound = connections.filter(c => c.direction === 'outbound' && new Date(c.id).getHours() === i).length || (i === new Date().getHours() ? outboundCount : 0);
    return { hour: hourLabel, inbound, outbound };
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-3">
          <Wifi className="w-5 h-5 animate-pulse" style={{ color: 'var(--accent)' }} />
          <span className="text-sm font-mono uppercase tracking-widest" style={{ color: 'var(--text-tertiary)' }}>Establishing secure link...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-1 h-8 rounded-full" style={{ background: 'linear-gradient(to bottom, var(--accent), transparent)' }} />
          <h1 className="text-xl font-bold uppercase tracking-widest" style={{ color: 'var(--text-primary)' }}>Network Operations</h1>
          {flaggedCount > 0 && (
            <span className="flex items-center gap-1 px-2.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-widest" style={{ backgroundColor: 'rgba(220,38,38,0.15)', color: 'var(--critical)', border: '1px solid rgba(220,38,38,0.3)' }}>
              <AlertTriangle className="w-3 h-3" />
              {flaggedCount} flagged
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {feedback && (
            <span className="flex items-center gap-1.5 text-[10px] font-mono px-3 py-1.5 rounded border" style={feedback.type === 'success' ? { backgroundColor: 'rgba(34,197,94,0.1)', color: 'var(--low)', borderColor: 'rgba(34,197,94,0.3)' } : { backgroundColor: 'rgba(220,38,38,0.1)', color: 'var(--critical)', borderColor: 'rgba(220,38,38,0.3)' }}>
              {feedback.type === 'success' ? <CheckCircle className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
              {feedback.message}
            </span>
          )}
          <button onClick={load} className="flex items-center gap-2 px-3 py-1.5 rounded text-[10px] font-semibold uppercase tracking-widest transition-all" style={{ border: '1px solid var(--accent)', color: 'var(--accent)', backgroundColor: 'transparent' }} onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(212,175,55,0.1)'; e.currentTarget.style.boxShadow = '0 0 20px rgba(212,175,55,0.15)'; }} onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.boxShadow = 'none'; }}>
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Active Connections', value: connections.length, icon: Wifi, accent: 'var(--accent)' },
          { label: 'Inbound', value: inboundCount, icon: ArrowDownLeft, accent: 'var(--info)' },
          { label: 'Outbound', value: outboundCount, icon: ArrowUpRight, accent: 'var(--medium)' },
          { label: 'Flagged', value: flaggedCount, icon: AlertTriangle, accent: 'var(--critical)' },
        ].map((stat) => (
          <div key={stat.label} className="relative rounded-lg p-4 border-l-4 overflow-hidden transition-all duration-300" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderLeftColor: stat.accent }} onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--border-active)'; e.currentTarget.style.boxShadow = '0 0 24px rgba(212,175,55,0.06)'; }} onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; e.currentTarget.style.boxShadow = 'none'; }}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase tracking-widest font-semibold" style={{ color: 'var(--text-tertiary)' }}>{stat.label}</span>
              <stat.icon className="w-4 h-4" style={{ color: stat.accent }} />
            </div>
            <div className="text-xl font-bold font-mono" style={{ color: 'var(--text-primary)' }}>{stat.value}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 rounded-lg p-4 border-l-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderLeftColor: 'var(--accent)' }}>
          <h2 className="text-[10px] uppercase tracking-widest font-semibold mb-4" style={{ color: 'var(--text-tertiary)' }}>Traffic Timeline</h2>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={trafficData}>
              <defs>
                <linearGradient id="inGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#d4af37" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#d4af37" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="outGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#dc2626" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#dc2626" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
              <XAxis dataKey="hour" tick={{ fontSize: 10, fill: 'var(--text-tertiary)', fontFamily: 'monospace' }} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: 'var(--text-tertiary)', fontFamily: 'monospace' }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={{ backgroundColor: 'var(--bg-elevated)', border: '1px solid var(--border-color)', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace', color: 'var(--text-primary)' }} />
              <Area type="monotone" dataKey="inbound" stroke="var(--accent)" fill="url(#inGrad)" strokeWidth={2} name="Inbound" />
              <Area type="monotone" dataKey="outbound" stroke="#dc2626" fill="url(#outGrad)" strokeWidth={2} name="Outbound" />
            </AreaChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-6 mt-3">
            <div className="flex items-center gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: 'var(--accent)' }} />
              <span className="text-[10px] uppercase tracking-widest" style={{ color: 'var(--text-tertiary)' }}>Inbound</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: '#dc2626' }} />
              <span className="text-[10px] uppercase tracking-widest" style={{ color: 'var(--text-tertiary)' }}>Outbound</span>
            </div>
          </div>
        </div>

        <div className="rounded-lg p-4 border-l-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderLeftColor: 'var(--info)' }}>
          <h2 className="text-[10px] uppercase tracking-widest font-semibold mb-4" style={{ color: 'var(--text-tertiary)' }}>Protocol Breakdown</h2>
          <div className="space-y-3">
            {protocolData.length > 0 ? protocolData.map((p) => {
              const maxVal = Math.max(...protocolData.map(d => d.value), 1);
              const pct = (p.value / maxVal) * 100;
              return (
                <div key={p.name}>
                  <div className="flex justify-between text-[10px] mb-1">
                    <span className="font-mono uppercase tracking-wider" style={{ color: 'var(--text-secondary)' }}>{p.name}</span>
                    <span className="font-mono" style={{ color: 'var(--text-primary)' }}>{p.value}</span>
                  </div>
                  <div className="h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-elevated)' }}>
                    <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, backgroundColor: p.color }} />
                  </div>
                </div>
              );
            }) : (
              <p className="text-[10px] text-center uppercase tracking-widest" style={{ color: 'var(--text-tertiary)' }}>No protocol data</p>
            )}
          </div>
          <div className="mt-5 pt-4 border-t" style={{ borderColor: 'var(--border-color)' }}>
            <h3 className="text-[10px] uppercase tracking-widest font-semibold mb-3" style={{ color: 'var(--text-tertiary)' }}>Top Ports</h3>
            <div className="space-y-2">
              {topPorts.map(([port, data]) => (
                <div key={port} className="flex justify-between text-[11px]">
                  <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{data.service} <span style={{ color: 'var(--text-tertiary)' }}>({port})</span></span>
                  <span className="font-mono font-semibold" style={{ color: 'var(--text-primary)' }}>{data.count}</span>
                </div>
              ))}
              {topPorts.length === 0 && <p className="text-[10px] text-center uppercase tracking-widest" style={{ color: 'var(--text-tertiary)' }}>No port data</p>}
            </div>
          </div>
        </div>
      </div>

      <div className="rounded-lg p-4 border-l-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderLeftColor: 'var(--critical)' }}>
        <h2 className="text-[10px] uppercase tracking-widest font-semibold mb-3" style={{ color: 'var(--text-tertiary)' }}>Block IP Address</h2>
        <div className="flex items-center gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
            <input
              type="text"
              placeholder="Search by IP, port, or process..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 rounded text-sm font-mono border outline-none transition-all duration-200"
              style={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
              onFocus={(e) => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.boxShadow = '0 0 16px rgba(212,175,55,0.12)'; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; e.currentTarget.style.boxShadow = 'none'; }}
            />
          </div>
          <button
            onClick={() => setFlaggedOnly(!flaggedOnly)}
            className="flex items-center gap-2 px-3 py-2 rounded text-[10px] font-semibold uppercase tracking-widest border transition-all duration-200"
            style={flaggedOnly ? { backgroundColor: 'rgba(220,38,38,0.15)', color: 'var(--critical)', borderColor: 'rgba(220,38,38,0.4)' } : { backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-color)', color: 'var(--text-secondary)' }}
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            Flagged Only
          </button>
        </div>
      </div>

      <div className="rounded-lg border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <div className="px-4 py-2.5 border-b" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--bg-elevated)' }}>
          <span className="text-[10px] uppercase tracking-widest font-semibold" style={{ color: 'var(--text-tertiary)' }}>Active Connections</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b" style={{ borderColor: 'var(--border-color)' }}>
                <th className="text-left py-2.5 px-4 text-[10px] uppercase tracking-widest font-semibold" style={{ color: 'var(--text-tertiary)' }}>Dir</th>
                <th className="text-left py-2.5 px-4 text-[10px] uppercase tracking-widest font-semibold" style={{ color: 'var(--text-tertiary)' }}>Local Address</th>
                <th className="text-left py-2.5 px-4 text-[10px] uppercase tracking-widest font-semibold" style={{ color: 'var(--text-tertiary)' }}>Remote Address</th>
                <th className="text-left py-2.5 px-4 text-[10px] uppercase tracking-widest font-semibold" style={{ color: 'var(--text-tertiary)' }}>Protocol</th>
                <th className="text-left py-2.5 px-4 text-[10px] uppercase tracking-widest font-semibold" style={{ color: 'var(--text-tertiary)' }}>State</th>
                <th className="text-left py-2.5 px-4 text-[10px] uppercase tracking-widest font-semibold" style={{ color: 'var(--text-tertiary)' }}>Process</th>
                <th className="text-left py-2.5 px-4 text-[10px] uppercase tracking-widest font-semibold" style={{ color: 'var(--text-tertiary)' }}>Country</th>
                <th className="text-center py-2.5 px-4 text-[10px] uppercase tracking-widest font-semibold" style={{ color: 'var(--text-tertiary)' }}>Flag</th>
                <th className="text-right py-2.5 px-4 text-[10px] uppercase tracking-widest font-semibold" style={{ color: 'var(--text-tertiary)' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={9} className="py-10 text-center text-[10px] uppercase tracking-widest" style={{ color: 'var(--text-tertiary)' }}>No connections found</td></tr>
              ) : filtered.map((conn) => (
                <tr key={conn.id} className="border-b transition-colors" style={{ borderColor: 'var(--border-color)' }} onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--bg-elevated)'; }} onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}>
                  <td className="py-2.5 px-4">
                    {conn.direction === 'inbound' ? (
                      <ArrowDownLeft className="w-4 h-4" style={{ color: 'var(--accent)' }} />
                    ) : (
                      <ArrowUpRight className="w-4 h-4" style={{ color: 'var(--medium)' }} />
                    )}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-[11px]" style={{ color: 'var(--text-primary)' }}>{conn.local_addr}:{conn.local_port}</td>
                  <td className="py-2.5 px-4 font-mono text-[11px]" style={{ color: conn.flagged ? 'var(--critical)' : 'var(--text-primary)' }}>
                    {conn.remote_addr}:{conn.remote_port}
                  </td>
                  <td className="py-2.5 px-4">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold uppercase" style={{ backgroundColor: 'rgba(212,175,55,0.1)', color: 'var(--accent)', border: '1px solid rgba(212,175,55,0.2)' }}>
                      {conn.protocol}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-[11px] font-mono" style={{ color: 'var(--text-secondary)' }}>{conn.state}</td>
                  <td className="py-2.5 px-4 text-[11px]" style={{ color: 'var(--text-primary)' }}>{conn.process}</td>
                  <td className="py-2.5 px-4 text-[11px]" style={{ color: 'var(--text-tertiary)' }}>{conn.country || '-'}</td>
                  <td className="py-2.5 px-4 text-center">
                    {conn.flagged && (
                      <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold uppercase" style={{ backgroundColor: 'rgba(220,38,38,0.12)', color: 'var(--critical)', border: '1px solid rgba(220,38,38,0.25)' }}>
                        <AlertTriangle className="w-2.5 h-2.5" />
                        Threat
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-4 text-right">
                    {conn.flagged && (
                      <button
                        onClick={() => handleBlockIp(conn.remote_addr)}
                        className="flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono font-semibold uppercase transition-all duration-200"
                        style={{ backgroundColor: 'rgba(220,38,38,0.12)', color: 'var(--critical)', border: '1px solid rgba(220,38,38,0.25)' }}
                        onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(220,38,38,0.25)'; e.currentTarget.style.boxShadow = '0 0 12px rgba(220,38,38,0.15)'; }}
                        onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'rgba(220,38,38,0.12)'; e.currentTarget.style.boxShadow = 'none'; }}
                        title={`Block ${conn.remote_addr}`}
                      >
                        <Ban className="w-3 h-3" />
                        Block
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
