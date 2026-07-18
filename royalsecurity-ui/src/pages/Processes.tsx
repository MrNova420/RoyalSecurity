import { useState } from 'react';
import {
  Search, RefreshCw, AlertTriangle, Shield,
  ArrowUpDown, Ban
} from 'lucide-react';

interface Process {
  pid: number;
  name: string;
  path: string;
  commandLine: string;
  cpu: number;
  memory: number;
  status: 'running' | 'suspicious' | 'terminated';
  user: string;
  parentPid: number;
  parentName: string;
  created: string;
  hash?: string;
}

const mockProcesses: Process[] = [
  { pid: 4, name: 'System', path: 'System', commandLine: '', cpu: 0.1, memory: 0.4, status: 'running', user: 'SYSTEM', parentPid: 0, parentName: '-', created: '2026-07-18 08:00:00' },
  { pid: 584, name: 'svchost.exe', path: 'C:\\Windows\\System32\\svchost.exe', commandLine: 'svchost.exe -k netsvcs', cpu: 1.2, memory: 2.1, status: 'running', user: 'SYSTEM', parentPid: 560, parentName: 'services.exe', created: '2026-07-18 08:01:23' },
  { pid: 1204, name: 'lsass.exe', path: 'C:\\Windows\\System32\\lsass.exe', commandLine: '', cpu: 0.3, memory: 1.8, status: 'running', user: 'SYSTEM', parentPid: 560, parentName: 'services.exe', created: '2026-07-18 08:01:15' },
  { pid: 2456, name: 'powershell.exe', path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', commandLine: 'powershell.exe -enc SQBmACAAKAAuAC4ALgApAA==', cpu: 8.4, memory: 3.2, status: 'suspicious', user: 'SYSTEM', parentPid: 2380, parentName: 'wmiprvse.exe', created: '2026-07-18 14:23:45', hash: 'a1b2c3d4e5f6...' },
  { pid: 2480, name: 'cmd.exe', path: 'C:\\Windows\\System32\\cmd.exe', commandLine: 'cmd.exe /c whoami /all', cpu: 0.5, memory: 0.8, status: 'suspicious', user: 'SYSTEM', parentPid: 2456, parentName: 'powershell.exe', created: '2026-07-18 14:23:47' },
  { pid: 3100, name: 'explorer.exe', path: 'C:\\Windows\\explorer.exe', commandLine: '', cpu: 2.1, memory: 5.4, status: 'running', user: 'ADMIN', parentPid: 2980, parentName: 'userinit.exe', created: '2026-07-18 08:15:00' },
  { pid: 4200, name: 'chrome.exe', path: 'C:\\Program Files\\Google\\Chrome\\chrome.exe', commandLine: 'chrome.exe --type=renderer', cpu: 4.7, memory: 12.3, status: 'running', user: 'ADMIN', parentPid: 6800, parentName: 'chrome.exe', created: '2026-07-18 09:30:00' },
  { pid: 5100, name: 'MsMpEng.exe', path: 'C:\\Program Files\\Windows Defender\\MsMpEng.exe', commandLine: '', cpu: 1.5, memory: 4.8, status: 'running', user: 'SYSTEM', parentPid: 560, parentName: 'services.exe', created: '2026-07-18 08:01:30' },
  { pid: 5680, name: 'sqlservr.exe', path: 'C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe', commandLine: 'sqlservr -s MSSQLSERVER', cpu: 6.3, memory: 8.7, status: 'running', user: 'NT SERVICE\\MSSQLSERVER', parentPid: 560, parentName: 'services.exe', created: '2026-07-18 08:02:00' },
  { pid: 6200, name: 'net.exe', path: 'C:\\Windows\\System32\\net.exe', commandLine: 'net user /domain', cpu: 0.2, memory: 0.3, status: 'suspicious', user: 'SYSTEM', parentPid: 2480, parentName: 'cmd.exe', created: '2026-07-18 14:23:50' },
  { pid: 7100, name: 'royalsecurity-agent.exe', path: 'C:\\Program Files\\RoyalSecurity\\royalsecurity-agent.exe', commandLine: '', cpu: 3.2, memory: 2.4, status: 'running', user: 'SYSTEM', parentPid: 560, parentName: 'services.exe', created: '2026-07-18 08:00:10' },
  { pid: 7400, name: 'taskhostw.exe', path: 'C:\\Windows\\System32\\taskhostw.exe', commandLine: 'taskhostw.exe -Embedding', cpu: 0.1, memory: 0.6, status: 'running', user: 'ADMIN', parentPid: 3100, parentName: 'explorer.exe', created: '2026-07-18 09:00:00' },
];

const statusConfig: Record<string, { color: string; bg: string }> = {
  running: { color: 'var(--low)', bg: 'rgba(34,197,94,0.1)' },
  suspicious: { color: 'var(--critical)', bg: 'rgba(239,68,68,0.1)' },
  terminated: { color: 'var(--text-secondary)', bg: 'rgba(156,163,175,0.1)' },
};

export default function Processes() {
  const [processes] = useState<Process[]>(mockProcesses);
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState<'pid' | 'name' | 'cpu' | 'memory'>('pid');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(false);

  const toggleSort = (field: typeof sortBy) => {
    if (sortBy === field) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(field);
      setSortDir('asc');
    }
  };

  const sorted = [...processes]
    .filter((p) => {
      if (showSuspiciousOnly && p.status !== 'suspicious') return false;
      if (search && !p.name.toLowerCase().includes(search.toLowerCase()) && !p.path.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    })
    .sort((a, b) => {
      const mul = sortDir === 'asc' ? 1 : -1;
      if (sortBy === 'name') return mul * a.name.localeCompare(b.name);
      return mul * ((a[sortBy] as number) - (b[sortBy] as number));
    });

  const suspiciousCount = processes.filter((p) => p.status === 'suspicious').length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold">Processes</h1>
          {suspiciousCount > 0 && (
            <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold" style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: 'var(--critical)' }}>
              <AlertTriangle className="w-3 h-3" />
              {suspiciousCount} suspicious
            </span>
          )}
        </div>
        <button className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors">
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          <input
            type="text"
            placeholder="Search by process name or path..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg text-sm border outline-none focus:ring-1 focus:ring-indigo-500"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
          />
        </div>
        <button
          onClick={() => setShowSuspiciousOnly(!showSuspiciousOnly)}
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium border transition-colors ${showSuspiciousOnly ? 'bg-red-500/20 text-red-400 border-red-500/30' : 'hover:bg-white/5'}`}
          style={!showSuspiciousOnly ? { backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', color: 'var(--text-secondary)' } : {}}
        >
          <Shield className="w-3.5 h-3.5" />
          Suspicious Only
        </button>
      </div>

      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
                {[
                  { key: 'pid' as const, label: 'PID' },
                  { key: 'name' as const, label: 'Process Name' },
                  { key: 'cpu' as const, label: 'CPU %' },
                  { key: 'memory' as const, label: 'Memory (MB)' },
                ].map((col) => (
                  <th
                    key={col.key}
                    onClick={() => toggleSort(col.key)}
                    className="text-left py-3 px-4 font-medium cursor-pointer hover:text-white transition-colors select-none"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    <div className="flex items-center gap-1">
                      {col.label}
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                ))}
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Path</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>User</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Status</th>
                <th className="text-right py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((proc) => (
                <tr key={proc.pid} className="border-b hover:bg-white/5 transition-colors" style={{ borderColor: 'var(--border-color)' }}>
                  <td className="py-2.5 px-4 font-mono text-[11px]">{proc.pid}</td>
                  <td className="py-2.5 px-4">
                    <div className="flex items-center gap-2">
                      {proc.status === 'suspicious' && <AlertTriangle className="w-3.5 h-3.5 text-red-400" />}
                      <span className="font-medium">{proc.name}</span>
                    </div>
                  </td>
                  <td className="py-2.5 px-4">
                    <div className="flex items-center gap-2">
                      <div className="w-12 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-secondary)' }}>
                        <div className="h-1.5 rounded-full" style={{
                          width: `${Math.min(proc.cpu * 3, 100)}%`,
                          backgroundColor: proc.cpu > 5 ? 'var(--high)' : proc.cpu > 2 ? 'var(--medium)' : 'var(--low)',
                        }} />
                      </div>
                      <span className="text-[11px]">{proc.cpu.toFixed(1)}</span>
                    </div>
                  </td>
                  <td className="py-2.5 px-4 text-[11px]">{proc.memory.toFixed(1)}</td>
                  <td className="py-2.5 px-4 text-[10px] max-w-[200px] truncate" style={{ color: 'var(--text-secondary)' }} title={proc.path}>
                    {proc.path}
                  </td>
                  <td className="py-2.5 px-4 text-[11px]" style={{ color: 'var(--text-secondary)' }}>{proc.user}</td>
                  <td className="py-2.5 px-4">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium" style={{
                      backgroundColor: statusConfig[proc.status].bg,
                      color: statusConfig[proc.status].color,
                    }}>
                      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: statusConfig[proc.status].color }} />
                      {proc.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-right">
                    {proc.status === 'suspicious' && (
                      <button className="p-1.5 rounded-lg hover:bg-red-500/20 text-red-400 transition-colors" title="Terminate">
                        <Ban className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="flex items-center justify-between text-xs" style={{ color: 'var(--text-secondary)' }}>
        <span>Showing {sorted.length} of {processes.length} processes</span>
        <span>Real-time monitoring active</span>
      </div>
    </div>
  );
}
