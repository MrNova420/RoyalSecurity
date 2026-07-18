import { useState, useEffect, useCallback } from 'react';
import {
  Search, RefreshCw, AlertTriangle, Shield,
  ArrowUpDown, Ban, Cpu, CheckCircle
} from 'lucide-react';
import { getProcessList, terminateProcess } from '../lib/tauri-bridge';
import type { ProcessInfo } from '../lib/tauri-bridge';

const statusConfig: Record<string, { color: string; bg: string }> = {
  running: { color: 'var(--low)', bg: 'rgba(34,197,94,0.1)' },
  suspicious: { color: 'var(--critical)', bg: 'rgba(239,68,68,0.1)' },
  terminated: { color: 'var(--text-secondary)', bg: 'rgba(156,163,175,0.1)' },
};

export default function Processes() {
  const [processes, setProcesses] = useState<ProcessInfo[]>([]);
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState<'pid' | 'name' | 'cpu' | 'memory'>('pid');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(false);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message });
    setTimeout(() => setFeedback(null), 4000);
  };

  const load = useCallback(async () => {
    try {
      const data = await getProcessList();
      if (Array.isArray(data)) {
        setProcesses(data);
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

  const handleTerminate = async (pid: number, name: string) => {
    try {
      const result = await terminateProcess(pid);
      showFeedback('success', result.message || `Terminated process ${name} (PID ${pid})`);
      setProcesses(prev => prev.map(p => p.pid === pid ? { ...p, status: 'terminated' } : p));
    } catch (err: any) {
      showFeedback('error', err?.toString() || `Failed to terminate ${name}`);
    }
  };

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

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-3">
          <Cpu className="w-5 h-5 text-indigo-400 animate-spin" />
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Loading processes...</span>
        </div>
      </div>
    );
  }

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
              {sorted.length === 0 ? (
                <tr><td colSpan={8} className="py-8 text-center" style={{ color: 'var(--text-secondary)' }}>No processes found</td></tr>
              ) : sorted.map((proc) => (
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
                      backgroundColor: (statusConfig[proc.status] || statusConfig.running).bg,
                      color: (statusConfig[proc.status] || statusConfig.running).color,
                    }}>
                      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: (statusConfig[proc.status] || statusConfig.running).color }} />
                      {proc.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-right">
                    {proc.status === 'suspicious' && (
                      <button
                        onClick={() => handleTerminate(proc.pid, proc.name)}
                        className="p-1.5 rounded-lg hover:bg-red-500/20 text-red-400 transition-colors" title="Terminate"
                      >
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
