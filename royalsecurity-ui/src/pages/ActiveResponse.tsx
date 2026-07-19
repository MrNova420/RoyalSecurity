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
          <Cpu className="w-5 h-5 animate-spin" style={{ color: 'var(--accent)' }} />
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Loading active response...</span>
        </div>
      </div>
    );
  }

  const cfg = levelConfig[level] || levelConfig.none;
  const LevelIcon = cfg.icon;

  const containmentCards = levels.map((l) => {
    const lc = levelConfig[l];
    const Icon = lc.icon;
    const isActive = level === l;
    return { level: l, icon: Icon, color: lc.color, bg: lc.bg, isActive };
  });

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>ACTIVE RESPONSE</h1>
          <p className="text-[10px] uppercase mt-1" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Containment & Automated Response</p>
        </div>
        <div className="flex items-center gap-2">
          {feedback && (
            <span className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg" style={{
              backgroundColor: feedback.type === 'success' ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
              color: feedback.type === 'success' ? 'var(--low)' : 'var(--critical)',
              border: `1px solid ${feedback.type === 'success' ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)'}`,
            }}>
              {feedback.type === 'success' ? <CheckCircle className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
              {feedback.message}
            </span>
          )}
          <button onClick={load} className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-medium transition-all"
            style={{ border: '1px solid var(--accent)', color: 'var(--accent)', backgroundColor: 'transparent' }}
            onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--accent-muted)'; }}
            onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <div className="flex items-center justify-between mb-4">
          <span className="text-[10px] font-medium uppercase" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Containment Level</span>
          {changing && <span className="text-[10px] animate-pulse" style={{ color: 'var(--accent)' }}>Updating...</span>}
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {containmentCards.map((c) => (
            <button
              key={c.level}
              onClick={() => handleLevelChange(c.level)}
              disabled={changing}
              className="rounded-xl p-4 border transition-all text-left disabled:opacity-50"
              style={{
                backgroundColor: c.isActive ? 'var(--bg-elevated)' : 'var(--bg-card)',
                borderColor: c.isActive ? c.color : 'var(--border-color)',
                borderLeft: `4px solid ${c.color}`,
                boxShadow: c.isActive ? `0 0 20px ${c.bg}` : 'none',
              }}
              onMouseEnter={(e) => { if (!c.isActive) e.currentTarget.style.borderColor = 'var(--border-active)'; }}
              onMouseLeave={(e) => { if (!c.isActive) e.currentTarget.style.borderColor = 'var(--border-color)'; }}
            >
              <div className="flex items-center gap-2 mb-2">
                <c.icon className="w-4 h-4" style={{ color: c.color }} />
                <span className="text-xs font-medium" style={{ color: c.color }}>{c.level.toUpperCase()}</span>
              </div>
              {c.isActive && (
                <div className="text-[10px] px-2 py-0.5 rounded-full inline-block" style={{ backgroundColor: c.bg, color: c.color }}>
                  Active
                </div>
              )}
            </button>
          ))}
        </div>
      </div>

      <div className="rounded-xl border p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <div className="flex items-center justify-between mb-4">
          <span className="text-[10px] font-medium uppercase" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Playbooks</span>
          <span className="text-[10px] px-2 py-0.5 rounded-full" style={{ backgroundColor: 'var(--accent-muted)', color: 'var(--accent)' }}>
            {playbooks.length} available
          </span>
        </div>
        {playbooks.length === 0 ? (
          <div className="py-8 text-center text-sm" style={{ color: 'var(--text-tertiary)' }}>No playbooks available</div>
        ) : (
          <div className="space-y-2">
            {playbooks.map((pb) => {
              const sc = statusColors[pb.status] || statusColors.inactive;
              return (
                <div key={pb.id} className="flex items-center justify-between p-4 rounded-xl border transition-all hover:shadow-md" style={{
                  backgroundColor: 'var(--bg-elevated)',
                  borderColor: 'var(--border-color)',
                  borderLeft: '4px solid var(--accent)',
                }}
                  onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--border-active)'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; }}
                >
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'var(--bg-card)' }}>
                      <FileSearch className="w-4 h-4" style={{ color: 'var(--accent)' }} />
                    </div>
                    <div>
                      <div className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{pb.name}</div>
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

      <div className="rounded-xl border p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <div className="flex items-center justify-between mb-4">
          <span className="text-[10px] font-medium uppercase" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Quarantined Files</span>
          {quarantine.length > 0 && (
            <span className="text-[10px] px-2 py-0.5 rounded-full" style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: 'var(--critical)' }}>
              {quarantine.length} files
            </span>
          )}
        </div>
        {quarantine.length === 0 ? (
          <div className="py-8 text-center text-sm" style={{ color: 'var(--text-tertiary)' }}>No files quarantined</div>
        ) : (
          <div className="space-y-2">
            {quarantine.map((q) => (
              <div key={q.id} className="flex items-center justify-between p-4 rounded-xl border transition-all hover:shadow-md" style={{
                backgroundColor: 'var(--bg-elevated)',
                borderColor: 'var(--border-color)',
                borderLeft: '4px solid var(--critical)',
              }}
                onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--border-active)'; }}
                onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; }}
              >
                <div className="flex-1 min-w-0">
                  <div className="font-mono text-[11px] mb-1" style={{ color: 'var(--text-primary)' }}>{q.path}</div>
                  <div className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>{q.reason}</div>
                </div>
                <div className="text-[10px] font-mono ml-4 shrink-0" style={{ color: 'var(--text-tertiary)' }}>{q.timestamp}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
