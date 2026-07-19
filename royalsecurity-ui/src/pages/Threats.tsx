import { useState, useEffect, useCallback } from 'react';
import {
  AlertTriangle, Search, RefreshCw, ShieldAlert, Eye, CheckCircle
} from 'lucide-react';
import { getThreats, getAlertStats, blockIp, triggerThreatIntelUpdate } from '../lib/tauri-bridge';
import type { Threat, AlertStats } from '../lib/tauri-bridge';

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
  const [threats, setThreats] = useState<Threat[]>([]);
  const [filter, setFilter] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [stats, setStats] = useState<AlertStats>({ total_alerts: 0, critical: 0, high: 0, medium: 0, low: 0, informational: 0 });
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message });
    setTimeout(() => setFeedback(null), 4000);
  };

  const load = useCallback(async () => {
    try {
      const [threatsData, statsData] = await Promise.allSettled([getThreats(), getAlertStats()]);
      if (threatsData.status === 'fulfilled' && Array.isArray(threatsData.value)) {
        setThreats(threatsData.value);
      }
      if (statsData.status === 'fulfilled') {
        setStats(statsData.value);
      }
    } catch {
      // Use defaults
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
    } catch (err: any) {
      showFeedback('error', err?.toString() || 'Failed to block IP');
    }
  };

  const handleInvestigate = async (threatId: string) => {
    try {
      await triggerThreatIntelUpdate();
      showFeedback('success', `Investigation triggered for ${threatId}. Threat intel updated.`);
    } catch (err: any) {
      showFeedback('error', err?.toString() || 'Failed to trigger investigation');
    }
  };

  const handleResolve = (threatId: string) => {
    setThreats(prev => prev.map(t => t.id === threatId ? { ...t, status: 'resolved' } : t));
    showFeedback('success', `Threat ${threatId} marked as resolved.`);
  };

  const filtered = threats.filter((t) => {
    if (filter !== 'all' && t.severity !== filter) return false;
    if (searchTerm && !t.title.toLowerCase().includes(searchTerm.toLowerCase()) && !t.source.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 animate-pulse" style={{ color: 'var(--accent)' }} />
          <span className="text-sm font-mono uppercase tracking-widest" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Loading threats...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-5 h-5" style={{ color: 'var(--accent)' }} />
          <h1 className="text-xl font-bold uppercase tracking-wider" style={{ letterSpacing: '0.08em' }}>Threat Registry</h1>
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

      <div className="flex items-center gap-2">
        {[
          { label: 'Critical', count: stats.critical, color: 'var(--critical)' },
          { label: 'High', count: stats.high, color: 'var(--high)' },
          { label: 'Medium', count: stats.medium, color: 'var(--medium)' },
          { label: 'Low', count: stats.low, color: 'var(--low)' },
        ].map((s) => (
          <button
            key={s.label}
            onClick={() => setFilter(filter === s.label.toLowerCase() ? 'all' : s.label.toLowerCase())}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all"
            style={{
              backgroundColor: filter === s.label.toLowerCase() ? 'var(--accent-muted, rgba(212,175,55,0.1))' : 'var(--bg-card)',
              borderColor: filter === s.label.toLowerCase() ? 'var(--accent)' : 'var(--border-color)',
              color: filter === s.label.toLowerCase() ? 'var(--accent)' : 'var(--text-secondary)',
            }}
          >
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: s.color }} />
            <span className="uppercase" style={{ fontSize: '10px', letterSpacing: '0.1em' }}>{s.label}</span>
            <span className="font-mono" style={{ color: 'var(--text-primary)' }}>{s.count}</span>
          </button>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
          <input
            type="text"
            placeholder="Search threats..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg text-sm border outline-none transition-colors"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
            onFocus={(e) => { e.currentTarget.style.borderColor = 'var(--accent)'; }}
            onBlur={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; }}
          />
        </div>
        <span className="font-mono text-xs" style={{ color: 'var(--text-tertiary)' }}>{filtered.length} threats</span>
      </div>

      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--bg-elevated)' }}>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>SEVERITY</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>THREAT</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>SOURCE</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>MITRE</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>HOST</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>STATUS</th>
              <th className="text-right py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>TIME</th>
              <th className="text-right py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-16 text-center">
                  <div className="flex flex-col items-center gap-4">
                    <ShieldAlert className="w-12 h-12" style={{ color: 'var(--text-tertiary)', opacity: 0.4 }} />
                    <div>
                      <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>No threats detected</p>
                      <p className="text-xs mt-1" style={{ color: 'var(--text-tertiary)' }}>All systems secure</p>
                    </div>
                  </div>
                </td>
              </tr>
            ) : filtered.map((threat) => (
              <tr
                key={threat.id}
                className="border-b transition-all cursor-pointer group"
                style={{ borderColor: 'var(--border-color)' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderLeftColor = 'var(--accent)';
                  e.currentTarget.style.borderLeftWidth = '3px';
                  e.currentTarget.style.backgroundColor = 'var(--bg-elevated)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.borderLeftColor = 'transparent';
                  e.currentTarget.style.borderLeftWidth = '3px';
                  e.currentTarget.style.backgroundColor = 'transparent';
                }}
                onClick={() => setSelectedThreat(selectedThreat?.id === threat.id ? null : threat)}
              >
                <td className="py-3 px-4" style={{ borderLeft: '3px solid transparent' }}>
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full font-semibold uppercase" style={{
                    fontSize: '10px',
                    backgroundColor: `${severityColors[threat.severity]}12`,
                    color: severityColors[threat.severity],
                    letterSpacing: '0.05em',
                  }}>
                    <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: severityColors[threat.severity] }} />
                    {threat.severity}
                  </span>
                </td>
                <td className="py-3 px-4 font-semibold" style={{ color: 'var(--text-primary)' }}>{threat.title}</td>
                <td className="py-3 px-4" style={{ color: 'var(--text-secondary)' }}>{threat.source}</td>
                <td className="py-3 px-4">
                  <span className="font-mono px-2 py-0.5 rounded text-[10px] font-medium" style={{ backgroundColor: 'var(--accent-muted, rgba(212,175,55,0.1))', color: 'var(--accent)' }}>
                    {threat.mitre}
                  </span>
                </td>
                <td className="py-3 px-4 font-mono" style={{ color: 'var(--text-secondary)' }}>{threat.host}</td>
                <td className="py-3 px-4">
                  <span className="text-[10px] font-semibold uppercase" style={{ color: statusColors[threat.status], letterSpacing: '0.1em' }}>
                    {threat.status.replace('_', ' ')}
                  </span>
                </td>
                <td className="py-3 px-4 text-right font-mono" style={{ color: 'var(--text-tertiary)' }}>{threat.time}</td>
                <td className="py-3 px-4 text-right">
                  <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      onClick={(e) => { e.stopPropagation(); handleBlockIp(threat.host); }}
                      className="px-2 py-1 rounded text-[10px] font-semibold uppercase transition-colors"
                      style={{ border: '1px solid var(--critical)', color: 'var(--critical)', letterSpacing: '0.05em' }}
                      onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(239,68,68,0.1)'; }}
                      onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
                    >
                      Block
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleInvestigate(threat.id); }}
                      className="px-2 py-1 rounded text-[10px] font-semibold uppercase transition-colors"
                      style={{ border: '1px solid var(--accent)', color: 'var(--accent)', letterSpacing: '0.05em' }}
                      onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--accent-muted, rgba(212,175,55,0.1))'; }}
                      onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
                    >
                      Investigate
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleResolve(threat.id); }}
                      className="px-2 py-1 rounded text-[10px] font-semibold uppercase transition-colors"
                      style={{ border: '1px solid var(--low)', color: 'var(--low)', letterSpacing: '0.05em' }}
                      onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(34,197,94,0.1)'; }}
                      onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
                    >
                      Resolve
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selectedThreat && (
        <div className="rounded-xl p-5 border transition-all" style={{ backgroundColor: 'var(--bg-card)', borderLeftWidth: '4px', borderLeftColor: severityColors[selectedThreat.severity] }}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5" style={{ color: severityColors[selectedThreat.severity] }} />
              <h3 className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>{selectedThreat.title}</h3>
              <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full" style={{ backgroundColor: `${severityColors[selectedThreat.severity]}15`, color: severityColors[selectedThreat.severity], letterSpacing: '0.1em' }}>
                {selectedThreat.severity}
              </span>
            </div>
            <button
              onClick={() => setSelectedThreat(null)}
              className="text-xs px-2 py-1 rounded transition-colors"
              style={{ color: 'var(--text-secondary)' }}
              onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--text-primary)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-secondary)'; }}
            >
              Close
            </button>
          </div>
          <div className="grid grid-cols-4 gap-4 mb-4 text-xs">
            <div>
              <span className="block mb-0.5 uppercase" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>ID</span>
              <span className="font-mono" style={{ color: 'var(--text-primary)' }}>{selectedThreat.id}</span>
            </div>
            <div>
              <span className="block mb-0.5 uppercase" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>Host</span>
              <span className="font-mono" style={{ color: 'var(--text-primary)' }}>{selectedThreat.host}</span>
            </div>
            <div>
              <span className="block mb-0.5 uppercase" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>Source</span>
              <span style={{ color: 'var(--text-secondary)' }}>{selectedThreat.source}</span>
            </div>
            <div>
              <span className="block mb-0.5 uppercase" style={{ color: 'var(--text-tertiary)', fontSize: '10px', letterSpacing: '0.1em' }}>MITRE</span>
              <span className="font-mono px-1.5 py-0.5 rounded text-[10px]" style={{ backgroundColor: 'var(--accent-muted, rgba(212,175,55,0.1))', color: 'var(--accent)' }}>{selectedThreat.mitre}</span>
            </div>
          </div>
          <p className="text-xs leading-relaxed mb-4" style={{ color: 'var(--text-secondary)' }}>{selectedThreat.description}</p>
          <div className="flex gap-2 pt-3" style={{ borderTop: '1px solid var(--border-color)' }}>
            <button
              onClick={(e) => { e.stopPropagation(); handleBlockIp(selectedThreat.host); }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-semibold uppercase transition-colors"
              style={{ border: '1px solid var(--critical)', color: 'var(--critical)', letterSpacing: '0.05em' }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(239,68,68,0.1)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              Block
            </button>
            <button
              onClick={(e) => { e.stopPropagation(); handleInvestigate(selectedThreat.id); }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-semibold uppercase transition-colors"
              style={{ border: '1px solid var(--accent)', color: 'var(--accent)', letterSpacing: '0.05em' }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--accent-muted, rgba(212,175,55,0.1))'; }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
            >
              <Eye className="w-3.5 h-3.5" />
              Investigate
            </button>
            <button
              onClick={(e) => { e.stopPropagation(); handleResolve(selectedThreat.id); }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-semibold uppercase transition-colors"
              style={{ border: '1px solid var(--low)', color: 'var(--low)', letterSpacing: '0.05em' }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(34,197,94,0.1)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
            >
              <CheckCircle className="w-3.5 h-3.5" />
              Resolve
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
