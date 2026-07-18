import { useState, useEffect, useCallback } from 'react';
import {
  Shield, RefreshCw, Cpu, AlertTriangle, CheckCircle, Lock, Unlock, FileSearch
} from 'lucide-react';
import { getContainmentLevel, setContainmentLevel, getPlaybooks, getQuarantineList } from '../lib/tauri-bridge';

interface Playbook {
  id: string;
  name: string;
  status: string;
  description: string;
  [key: string]: unknown;
}

interface QuarantinedFile {
  id: string;
  path: string;
  reason: string;
  timestamp: string;
  [key: string]: unknown;
}

const levels = ['none', 'partial', 'full', 'emergency'] as const;

const levelConfig: Record<string, { color: string; bg: string; icon: any }> = {
  none: { color: 'var(--low)', bg: 'rgba(34,197,94,0.1)', icon: Unlock },
  partial: { color: 'var(--medium)', bg: 'rgba(234,179,8,0.1)', icon: Shield },
  full: { color: 'var(--high)', bg: 'rgba(249,115,22,0.1)', icon: Lock },
  emergency: { color: 'var(--critical)', bg: 'rgba(239,68,68,0.1)', icon: Lock },
};

const statusColors: Record<string, { color: string; bg: string }> = {
  active: { color: 'var(--low)', bg: 'rgba(34,197,94,0.1)' },
  inactive: { color: 'var(--text-secondary)', bg: 'rgba(156,163,175,0.1)' },
  error: { color: 'var(--critical)', bg: 'rgba(239,68,68,0.1)' },
};

export default function ActiveResponse() {
  const [level, setLevel] = useState('none');
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [quarantine, setQuarantine] = useState<QuarantinedFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [changing, setChanging] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message });
    setTimeout(() => setFeedback(null), 4000);
  };

  const load = useCallback(async () => {
    try {
      const [levelData, playbookData, quarantineData] = await Promise.allSettled([
        getContainmentLevel(),
        getPlaybooks(),
        getQuarantineList(),
      ]);
      if (levelData.status === 'fulfilled') setLevel(levelData.value as string);
      if (playbookData.status === 'fulfilled' && Array.isArray(playbookData.value)) setPlaybooks(playbookData.value as Playbook[]);
      if (quarantineData.status === 'fulfilled' && Array.isArray(quarantineData.value)) setQuarantine(quarantineData.value as QuarantinedFile[]);
    } catch {
      // Use defaults
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleLevelChange = async (newLevel: string) => {
    setChanging(true);
    try {
      await setContainmentLevel(newLevel);
      setLevel(newLevel);
      showFeedback('success', `Containment level set to "${newLevel}"`);
    } catch (err: any) {
      showFeedback('error', err?.toString() || 'Failed to change containment level');
    } finally {
      setChanging(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-3">
          <Cpu className="w-5 h-5 text-indigo-400 animate-spin" />
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Loading active response...</span>
        </div>
      </div>
    );
  }

  const cfg = levelConfig[level] || levelConfig.none;
  const LevelIcon = cfg.icon;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Active Response</h1>
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

      <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold">Containment Level</h2>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-3 px-4 py-3 rounded-lg" style={{ backgroundColor: cfg.bg }}>
            <LevelIcon className="w-5 h-5" style={{ color: cfg.color }} />
            <span className="text-sm font-medium" style={{ color: cfg.color }}>{level.toUpperCase()}</span>
          </div>
          <select
            value={level}
            onChange={(e) => handleLevelChange(e.target.value)}
            disabled={changing}
            className="px-3 py-2 rounded-lg text-sm border outline-none focus:ring-1 focus:ring-indigo-500 disabled:opacity-50"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
          >
            {levels.map((l) => (
              <option key={l} value={l}>{l.charAt(0).toUpperCase() + l.slice(1)}</option>
            ))}
          </select>
          {changing && <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>Updating...</span>}
        </div>
      </div>

      <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <h2 className="text-sm font-semibold mb-3">Playbooks</h2>
        {playbooks.length === 0 ? (
          <div className="py-6 text-center text-sm" style={{ color: 'var(--text-secondary)' }}>No playbooks available</div>
        ) : (
          <div className="space-y-2">
            {playbooks.map((pb) => {
              const sc = statusColors[pb.status] || statusColors.inactive;
              return (
                <div key={pb.id} className="flex items-center justify-between p-3 rounded-lg border" style={{ borderColor: 'var(--border-color)' }}>
                  <div className="flex items-center gap-3">
                    <FileSearch className="w-4 h-4" style={{ color: 'var(--accent)' }} />
                    <div>
                      <div className="text-sm font-medium">{pb.name}</div>
                      <div className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>{pb.description}</div>
                    </div>
                  </div>
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium" style={{ backgroundColor: sc.bg, color: sc.color }}>
                    <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: sc.color }} />
                    {pb.status}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <h2 className="text-sm font-semibold mb-3">Quarantined Files</h2>
        {quarantine.length === 0 ? (
          <div className="py-6 text-center text-sm" style={{ color: 'var(--text-secondary)' }}>No files quarantined</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b" style={{ borderColor: 'var(--border-color)' }}>
                  <th className="text-left py-2 px-3 font-medium" style={{ color: 'var(--text-secondary)' }}>Path</th>
                  <th className="text-left py-2 px-3 font-medium" style={{ color: 'var(--text-secondary)' }}>Reason</th>
                  <th className="text-right py-2 px-3 font-medium" style={{ color: 'var(--text-secondary)' }}>Time</th>
                </tr>
              </thead>
              <tbody>
                {quarantine.map((q) => (
                  <tr key={q.id} className="border-b hover:bg-white/5 transition-colors" style={{ borderColor: 'var(--border-color)' }}>
                    <td className="py-2.5 px-3 font-mono text-[11px]">{q.path}</td>
                    <td className="py-2.5 px-3" style={{ color: 'var(--text-secondary)' }}>{q.reason}</td>
                    <td className="py-2.5 px-3 text-right" style={{ color: 'var(--text-secondary)' }}>{q.timestamp}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
