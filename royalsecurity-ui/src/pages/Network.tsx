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
          <Wifi className="w-5 h-5 text-indigo-400 animate-pulse" />
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Loading network connections...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold">Network</h1>
          {flaggedCount > 0 && (
            <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold" style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: 'var(--critical)' }}>
              <AlertTriangle className="w-3 h-3" />
              {flaggedCount} flagged
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {feedback && (
            <span className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg ${feedback.type === 'success' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
              {feedback.type === 'success' ? <CheckCircle className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
              {feedback.message}
            </span>
          )}
          <button onClick={load} className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors">
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Active Connections', value: connections.length, icon: Wifi, color: 'var(--accent)' },
          { label: 'Inbound', value: inboundCount, icon: ArrowDownLeft, color: 'var(--info)' },
          { label: 'Outbound', value: outboundCount, icon: ArrowUpRight, color: 'var(--medium)' },
          { label: 'Flagged', value: flaggedCount, icon: AlertTriangle, color: 'var(--critical)' },
        ].map((stat) => (
          <div key={stat.label} className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase font-medium" style={{ color: 'var(--text-secondary)' }}>{stat.label}</span>
              <stat.icon className="w-4 h-4" style={{ color: stat.color }} />
            </div>
            <div className="text-xl font-bold">{stat.value}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <h2 className="text-sm font-semibold mb-4">Traffic Overview</h2>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={trafficData}>
              <defs>
                <linearGradient id="inGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="outGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
              <XAxis dataKey="hour" tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={{ backgroundColor: '#1a2236', border: '1px solid #1e2d4a', borderRadius: '8px', fontSize: '12px' }} />
              <Area type="monotone" dataKey="inbound" stroke="#3b82f6" fill="url(#inGrad)" strokeWidth={2} name="Inbound (KB)" />
              <Area type="monotone" dataKey="outbound" stroke="#f97316" fill="url(#outGrad)" strokeWidth={2} name="Outbound (KB)" />
            </AreaChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-6 mt-2">
            <div className="flex items-center gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-blue-500" />
              <span className="text-[10px]" style={{ color: 'var(--text-secondary)' }}>Inbound</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-orange-500" />
              <span className="text-[10px]" style={{ color: 'var(--text-secondary)' }}>Outbound</span>
            </div>
          </div>
        </div>

        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <h2 className="text-sm font-semibold mb-4">Protocols</h2>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={protocolData.length > 0 ? protocolData : [{ name: 'No Data', value: 0, color: '#4b5563' }]}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
              <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={{ backgroundColor: '#1a2236', border: '1px solid #1e2d4a', borderRadius: '8px', fontSize: '12px' }} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {(protocolData.length > 0 ? protocolData : [{ name: 'No Data', value: 0, color: '#4b5563' }]).map((entry, index) => (
                  <Cell key={index} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div className="space-y-2 mt-3">
            {topPorts.map(([port, data]) => (
              <div key={port} className="flex justify-between text-xs">
                <span style={{ color: 'var(--text-secondary)' }}>{data.service} ({port})</span>
                <span className="font-medium">{data.count}</span>
              </div>
            ))}
            {topPorts.length === 0 && <p className="text-xs text-center" style={{ color: 'var(--text-secondary)' }}>No port data</p>}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          <input
            type="text"
            placeholder="Search by IP, port, or process..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg text-sm border outline-none focus:ring-1 focus:ring-indigo-500"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
          />
        </div>
        <button
          onClick={() => setFlaggedOnly(!flaggedOnly)}
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium border transition-colors ${flaggedOnly ? 'bg-red-500/20 text-red-400 border-red-500/30' : 'hover:bg-white/5'}`}
          style={!flaggedOnly ? { backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', color: 'var(--text-secondary)' } : {}}
        >
          <AlertTriangle className="w-3.5 h-3.5" />
          Flagged Only
        </button>
      </div>

      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Direction</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Local Address</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Remote Address</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Protocol</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>State</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Process</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Country</th>
                <th className="text-center py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Flag</th>
                <th className="text-right py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={9} className="py-8 text-center" style={{ color: 'var(--text-secondary)' }}>No connections found</td></tr>
              ) : filtered.map((conn) => (
                <tr key={conn.id} className="border-b hover:bg-white/5 transition-colors" style={{ borderColor: 'var(--border-color)' }}>
                  <td className="py-2.5 px-4">
                    {conn.direction === 'inbound' ? (
                      <ArrowDownLeft className="w-4 h-4 text-blue-400" />
                    ) : (
                      <ArrowUpRight className="w-4 h-4 text-orange-400" />
                    )}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-[11px]">{conn.local_addr}:{conn.local_port}</td>
                  <td className="py-2.5 px-4 font-mono text-[11px]" style={{ color: conn.flagged ? 'var(--critical)' : 'var(--text-primary)' }}>
                    {conn.remote_addr}:{conn.remote_port}
                  </td>
                  <td className="py-2.5 px-4">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-medium" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
                      {conn.protocol}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-[11px]" style={{ color: 'var(--text-secondary)' }}>{conn.state}</td>
                  <td className="py-2.5 px-4 text-[11px]">{conn.process}</td>
                  <td className="py-2.5 px-4 text-[11px]" style={{ color: 'var(--text-secondary)' }}>{conn.country || '-'}</td>
                  <td className="py-2.5 px-4 text-center">
                    {conn.flagged && (
                      <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-full text-[10px] font-semibold" style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: 'var(--critical)' }}>
                        <AlertTriangle className="w-2.5 h-2.5" />
                        Threat
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-4 text-right">
                    {conn.flagged && (
                      <button
                        onClick={() => handleBlockIp(conn.remote_addr)}
                        className="flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-medium bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors"
                        title={`Block ${conn.remote_addr}`}
                      >
                        <Ban className="w-3 h-3" />
                        Block IP
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
