import { useState } from 'react';
import {
  Search, RefreshCw, AlertTriangle, ArrowUpRight, ArrowDownLeft, Wifi
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';

interface Connection {
  id: string;
  localAddr: string;
  localPort: number;
  remoteAddr: string;
  remotePort: number;
  protocol: string;
  state: string;
  process: string;
  pid: number;
  direction: 'inbound' | 'outbound';
  country?: string;
  flagged: boolean;
}

const mockConnections: Connection[] = [
  { id: '1', localAddr: '10.0.1.100', localPort: 443, remoteAddr: '185.220.101.34', remotePort: 443, protocol: 'TCP', state: 'ESTABLISHED', process: 'powershell.exe', pid: 2456, direction: 'outbound', country: 'RU', flagged: true },
  { id: '2', localAddr: '10.0.1.100', localPort: 1433, remoteAddr: '10.0.1.50', remotePort: 1433, protocol: 'TCP', state: 'ESTABLISHED', process: 'sqlservr.exe', pid: 5680, direction: 'inbound', country: '', flagged: false },
  { id: '3', localAddr: '10.0.1.100', localPort: 8080, remoteAddr: '91.215.85.42', remotePort: 8080, protocol: 'TCP', state: 'TIME_WAIT', process: 'chrome.exe', pid: 4200, direction: 'outbound', country: 'DE', flagged: false },
  { id: '4', localAddr: '10.0.1.100', localPort: 53, remoteAddr: '8.8.8.8', remotePort: 53, protocol: 'UDP', state: 'NONE', process: 'svchost.exe', pid: 584, direction: 'outbound', country: 'US', flagged: false },
  { id: '5', localAddr: '10.0.1.100', localPort: 445, remoteAddr: '10.0.1.200', remotePort: 49723, protocol: 'TCP', state: 'ESTABLISHED', process: 'svchost.exe', pid: 584, direction: 'inbound', country: '', flagged: true },
  { id: '6', localAddr: '10.0.1.100', localPort: 3389, remoteAddr: '10.0.1.10', remotePort: 52341, protocol: 'TCP', state: 'ESTABLISHED', process: 'svchost.exe', pid: 584, direction: 'inbound', country: '', flagged: false },
  { id: '7', localAddr: '10.0.1.100', localPort: 12345, remoteAddr: '45.33.32.156', remotePort: 80, protocol: 'TCP', state: 'SYN_SENT', process: 'net.exe', pid: 6200, direction: 'outbound', country: 'US', flagged: true },
  { id: '8', localAddr: '10.0.1.100', localPort: 9090, remoteAddr: '10.0.1.1', remotePort: 9090, protocol: 'TCP', state: 'ESTABLISHED', process: 'royalsecurity-agent.exe', pid: 7100, direction: 'outbound', country: '', flagged: false },
  { id: '9', localAddr: '10.0.1.100', localPort: 8443, remoteAddr: '203.0.113.42', remotePort: 8443, protocol: 'TCP', state: 'ESTABLISHED', process: 'chrome.exe', pid: 4200, direction: 'outbound', country: 'JP', flagged: false },
  { id: '10', localAddr: '10.0.1.100', localPort: 6789, remoteAddr: '198.51.100.7', remotePort: 6789, protocol: 'TCP', state: 'CLOSE_WAIT', process: 'powershell.exe', pid: 2456, direction: 'outbound', country: 'NL', flagged: true },
];

const trafficData = Array.from({ length: 24 }, (_, i) => ({
  hour: `${String(i).padStart(2, '0')}:00`,
  inbound: Math.floor(Math.random() * 500) + 100,
  outbound: Math.floor(Math.random() * 300) + 50,
}));

const protocolData = [
  { name: 'TCP', value: 7, color: '#6366f1' },
  { name: 'UDP', value: 2, color: '#3b82f6' },
  { name: 'ICMP', value: 1, color: '#a78bfa' },
];

export default function NetworkPage() {
  const [connections] = useState<Connection[]>(mockConnections);
  const [search, setSearch] = useState('');
  const [flaggedOnly, setFlaggedOnly] = useState(false);

  const filtered = connections.filter((c) => {
    if (flaggedOnly && !c.flagged) return false;
    if (search) {
      const s = search.toLowerCase();
      return c.remoteAddr.includes(s) || c.process.toLowerCase().includes(s) || c.localAddr.includes(s);
    }
    return true;
  });

  const flaggedCount = connections.filter((c) => c.flagged).length;

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
        <button className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors">
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Active Connections', value: connections.length, icon: Wifi, color: 'var(--accent)' },
          { label: 'Inbound', value: connections.filter(c => c.direction === 'inbound').length, icon: ArrowDownLeft, color: 'var(--info)' },
          { label: 'Outbound', value: connections.filter(c => c.direction === 'outbound').length, icon: ArrowUpRight, color: 'var(--medium)' },
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
            <BarChart data={protocolData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
              <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={{ backgroundColor: '#1a2236', border: '1px solid #1e2d4a', borderRadius: '8px', fontSize: '12px' }} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {protocolData.map((entry, index) => (
                  <Cell key={index} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div className="space-y-2 mt-3">
            {[
              { port: '443', service: 'HTTPS', count: 3 },
              { port: '53', service: 'DNS', count: 2 },
              { port: '1433', service: 'MSSQL', count: 1 },
              { port: '445', service: 'SMB', count: 1 },
              { port: '3389', service: 'RDP', count: 1 },
            ].map((svc) => (
              <div key={svc.port} className="flex justify-between text-xs">
                <span style={{ color: 'var(--text-secondary)' }}>{svc.service} ({svc.port})</span>
                <span className="font-medium">{svc.count}</span>
              </div>
            ))}
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
              </tr>
            </thead>
            <tbody>
              {filtered.map((conn) => (
                <tr key={conn.id} className="border-b hover:bg-white/5 transition-colors" style={{ borderColor: 'var(--border-color)' }}>
                  <td className="py-2.5 px-4">
                    {conn.direction === 'inbound' ? (
                      <ArrowDownLeft className="w-4 h-4 text-blue-400" />
                    ) : (
                      <ArrowUpRight className="w-4 h-4 text-orange-400" />
                    )}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-[11px]">{conn.localAddr}:{conn.localPort}</td>
                  <td className="py-2.5 px-4 font-mono text-[11px]" style={{ color: conn.flagged ? 'var(--critical)' : 'var(--text-primary)' }}>
                    {conn.remoteAddr}:{conn.remotePort}
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
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
