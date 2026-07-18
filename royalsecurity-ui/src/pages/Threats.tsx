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
          <AlertTriangle className="w-5 h-5 text-indigo-400 animate-pulse" />
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Loading threats...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Threats</h1>
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
          { label: 'Critical', count: stats.critical, color: 'var(--critical)' },
          { label: 'High', count: stats.high, color: 'var(--high)' },
          { label: 'Medium', count: stats.medium, color: 'var(--medium)' },
          { label: 'Low', count: stats.low, color: 'var(--low)' },
        ].map((s) => (
          <button
            key={s.label}
            onClick={() => setFilter(filter === s.label.toLowerCase() ? 'all' : s.label.toLowerCase())}
            className={`rounded-xl p-3 border text-left transition-all ${filter === s.label.toLowerCase() ? 'ring-1' : 'hover:bg-white/5'}`}
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}
          >
            <div className="flex items-center gap-2 mb-1">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: s.color }} />
              <span className="text-[10px] uppercase font-medium" style={{ color: 'var(--text-secondary)' }}>{s.label}</span>
            </div>
            <div className="text-lg font-bold">{s.count}</div>
          </button>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          <input
            type="text"
            placeholder="Search threats..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg text-sm border outline-none focus:ring-1 focus:ring-indigo-500"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
          />
        </div>
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{filtered.length} threats</span>
      </div>

      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Severity</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Title</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Source</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>MITRE</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Host</th>
              <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Status</th>
              <th className="text-right py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={7} className="py-8 text-center" style={{ color: 'var(--text-secondary)' }}>No threats found</td></tr>
            ) : filtered.map((threat) => (
              <tr
                key={threat.id}
                className="border-b hover:bg-white/5 transition-colors cursor-pointer"
                style={{ borderColor: 'var(--border-color)' }}
                onClick={() => setSelectedThreat(selectedThreat?.id === threat.id ? null : threat)}
              >
                <td className="py-3 px-4">
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase" style={{
                    backgroundColor: `${severityColors[threat.severity]}15`,
                    color: severityColors[threat.severity],
                  }}>
                    <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: severityColors[threat.severity] }} />
                    {threat.severity}
                  </span>
                </td>
                <td className="py-3 px-4 font-medium">{threat.title}</td>
                <td className="py-3 px-4" style={{ color: 'var(--text-secondary)' }}>{threat.source}</td>
                <td className="py-3 px-4" style={{ color: 'var(--accent)' }}>{threat.mitre}</td>
                <td className="py-3 px-4">{threat.host}</td>
                <td className="py-3 px-4">
                  <span className="text-[10px] font-medium uppercase" style={{ color: statusColors[threat.status] }}>
                    {threat.status.replace('_', ' ')}
                  </span>
                </td>
                <td className="py-3 px-4 text-right" style={{ color: 'var(--text-secondary)' }}>{threat.time}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selectedThreat && (
        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: severityColors[selectedThreat.severity] }}>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5" style={{ color: severityColors[selectedThreat.severity] }} />
              <h3 className="text-sm font-semibold">{selectedThreat.title}</h3>
            </div>
            <button onClick={() => setSelectedThreat(null)} className="text-xs" style={{ color: 'var(--text-secondary)' }}>Close</button>
          </div>
          <div className="grid grid-cols-4 gap-4 mb-3 text-xs">
            <div><span style={{ color: 'var(--text-secondary)' }}>ID: </span>{selectedThreat.id}</div>
            <div><span style={{ color: 'var(--text-secondary)' }}>Host: </span>{selectedThreat.host}</div>
            <div><span style={{ color: 'var(--text-secondary)' }}>Source: </span>{selectedThreat.source}</div>
            <div><span style={{ color: 'var(--text-secondary)' }}>MITRE: </span><span style={{ color: 'var(--accent)' }}>{selectedThreat.mitre}</span></div>
          </div>
          <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{selectedThreat.description}</p>
          <div className="flex gap-2 mt-4">
            <button
              onClick={(e) => { e.stopPropagation(); handleBlockIp(selectedThreat.host); }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              Block Indicator
            </button>
            <button
              onClick={(e) => { e.stopPropagation(); handleInvestigate(selectedThreat.id); }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30 transition-colors"
            >
              <Eye className="w-3.5 h-3.5" />
              Investigate
            </button>
            <button
              onClick={(e) => { e.stopPropagation(); handleResolve(selectedThreat.id); }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-green-500/20 text-green-400 hover:bg-green-500/30 transition-colors"
            >
              <CheckCircle className="w-3.5 h-3.5" />
              Mark Resolved
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
