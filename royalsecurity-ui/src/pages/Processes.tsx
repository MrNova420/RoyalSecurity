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
          <Cpu className="w-5 h-5 animate-spin" style={{ color: 'var(--accent)' }} />
          <span className="text-sm font-mono uppercase tracking-widest" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Loading processes...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Cpu className="w-5 h-5" style={{ color: 'var(--accent)' }} />
          <h1 className="text-xl font-bold uppercase tracking-wider" style={{ letterSpacing: '0.08em' }}>Process Monitor</h1>
          {suspiciousCount > 0 && (
            <span
              className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-semibold uppercase"
              style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: 'var(--critical)', letterSpacing: '0.1em' }}
            >
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
          <button
            onClick={load}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
            style={{ border: '1px solid var(--accent)', color: 'var(--accent)', backgroundColor: 'transparent' }}
            onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--accent-muted, rgba(212,175,55,0.1))'; }}
            onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
          <input
            type="text"
            placeholder="Search by process name or path..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg text-sm border outline-none transition-colors"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
            onFocus={(e) => { e.currentTarget.style.borderColor = 'var(--accent)'; }}
            onBlur={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; }}
          />
        </div>
        <button
          onClick={() => setShowSuspiciousOnly(!showSuspiciousOnly)}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium border transition-colors"
          style={{
            backgroundColor: showSuspiciousOnly ? 'rgba(239,68,68,0.1)' : 'var(--bg-card)',
            borderColor: showSuspiciousOnly ? 'var(--critical)' : 'var(--border-color)',
            color: showSuspiciousOnly ? 'var(--critical)' : 'var(--text-secondary)',
          }}
        >
          <Shield className="w-3.5 h-3.5" />
          Suspicious Only
        </button>
      </div>

      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--bg-elevated)' }}>
                {[
                  { key: 'pid' as const, label: 'PID' },
                  { key: 'name' as const, label: 'Process' },
                  { key: 'cpu' as const, label: 'CPU %' },
                  { key: 'memory' as const, label: 'MEM (MB)' },
                ].map((col) => (
                  <th
                    key={col.key}
                    onClick={() => toggleSort(col.key)}
                    className="text-left py-3 px-4 font-medium cursor-pointer select-none transition-colors"
                    style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}
                  >
                    <div className="flex items-center gap-1.5">
                      {col.label}
                      <ArrowUpDown className="w-3 h-3" style={{ opacity: 0.5 }} />
                    </div>
                  </th>
                ))}
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>PATH</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>USER</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>STATUS</th>
                <th className="text-right py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {sorted.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-16 text-center">
                    <div className="flex flex-col items-center gap-4">
                      <Cpu className="w-12 h-12" style={{ color: 'var(--text-tertiary)', opacity: 0.4 }} />
                      <div>
                        <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>No processes found</p>
                        <p className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>All processes nominal</p>
                      </div>
                    </div>
                  </td>
                </tr>
              ) : sorted.map((proc) => (
                <tr
                  key={proc.pid}
                  className="border-b transition-all group"
                  style={{
                    borderColor: 'var(--border-color)',
                    borderLeft: proc.status === 'suspicious' ? '4px solid var(--critical)' : '4px solid transparent',
                    backgroundColor: proc.status === 'suspicious' ? 'rgba(239,68,68,0.03)' : 'transparent',
                  }}
                  onMouseEnter={(e) => {
                    if (proc.status !== 'suspicious') {
                      e.currentTarget.style.borderLeftColor = 'var(--accent)';
                      e.currentTarget.style.backgroundColor = 'var(--bg-elevated)';
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (proc.status !== 'suspicious') {
                      e.currentTarget.style.borderLeftColor = 'transparent';
                      e.currentTarget.style.backgroundColor = 'transparent';
                    }
                  }}
                >
                  <td className="py-2.5 px-4 font-mono text-[11px] font-medium" style={{ color: 'var(--accent)' }}>{proc.pid}</td>
                  <td className="py-2.5 px-4">
                    <div className="flex items-center gap-2">
                      {proc.status === 'suspicious' && <AlertTriangle className="w-3.5 h-3.5" style={{ color: 'var(--critical)' }} />}
                      <span className="font-medium" style={{ color: 'var(--text-primary)' }}>{proc.name}</span>
                    </div>
                  </td>
                  <td className="py-2.5 px-4">
                    <div className="flex items-center gap-2">
                      <div className="w-14 h-1 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-elevated)' }}>
                        <div className="h-1 rounded-full transition-all" style={{
                          width: `${Math.min(proc.cpu * 3, 100)}%`,
                          backgroundColor: proc.cpu > 5 ? 'var(--high)' : proc.cpu > 2 ? 'var(--medium)' : 'var(--low)',
                        }} />
                      </div>
                      <span className="font-mono text-[11px]" style={{ color: 'var(--text-secondary)' }}>{proc.cpu.toFixed(1)}</span>
                    </div>
                  </td>
                  <td className="py-2.5 px-4">
                    <div className="flex items-center gap-2">
                      <div className="w-14 h-1 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-elevated)' }}>
                        <div className="h-1 rounded-full transition-all" style={{
                          width: `${Math.min(proc.memory / 512 * 100, 100)}%`,
                          backgroundColor: proc.memory > 256 ? 'var(--high)' : proc.memory > 128 ? 'var(--medium)' : 'var(--low)',
                        }} />
                      </div>
                      <span className="font-mono text-[11px]" style={{ color: 'var(--text-secondary)' }}>{proc.memory.toFixed(1)}</span>
                    </div>
                  </td>
                  <td className="py-2.5 px-4 text-[10px] max-w-[200px] truncate font-mono" style={{ color: 'var(--text-tertiary)' }} title={proc.path}>
                    {proc.path}
                  </td>
                  <td className="py-2.5 px-4 text-[11px]" style={{ color: 'var(--text-secondary)' }}>{proc.user}</td>
                  <td className="py-2.5 px-4">
                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase" style={{
                      backgroundColor: (statusConfig[proc.status] || statusConfig.running).bg,
                      color: (statusConfig[proc.status] || statusConfig.running).color,
                      letterSpacing: '0.05em',
                    }}>
                      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: (statusConfig[proc.status] || statusConfig.running).color }} />
                      {proc.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-right">
                    {proc.status === 'suspicious' && (
                      <button
                        onClick={() => handleTerminate(proc.pid, proc.name)}
                        className="px-2.5 py-1 rounded-lg text-[10px] font-semibold uppercase transition-colors inline-flex items-center gap-1"
                        style={{ border: '1px solid var(--critical)', color: 'var(--critical)', letterSpacing: '0.05em' }}
                        title={`Terminate ${proc.name}`}
                        onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(239,68,68,0.1)'; }}
                        onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
                      >
                        <Ban className="w-3 h-3" />
                        Terminate
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="flex items-center justify-between text-xs font-mono" style={{ color: 'var(--text-tertiary)' }}>
        <span>Showing <span style={{ color: 'var(--text-secondary)' }}>{sorted.length}</span> of <span style={{ color: 'var(--text-secondary)' }}>{processes.length}</span> processes</span>
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ backgroundColor: 'var(--low)' }} />
          Real-time monitoring active
        </span>
      </div>
    </div>
  );
}
