import { useState, useEffect, useCallback } from 'react';
import {
  Database, Shield, CheckCircle, Search, RefreshCw,
  Link, Hash, Cpu, ChevronDown, ChevronUp, Download, AlertTriangle
} from 'lucide-react';
import { getAuditInfo, verifyAuditChain, exportAuditLog } from '../lib/tauri-bridge';
import type { AuditInfo } from '../lib/tauri-bridge';

interface AuditEntry {
  id: number;
  timestamp: string;
  action: string;
  user: string;
  target: string;
  details: string;
  hash: string;
  prevHash: string;
  integrity: 'valid' | 'tampered';
}

export default function AuditLog() {
  const [auditInfo, setAuditInfo] = useState<AuditInfo>({ total_entries: 0, chain_valid: true, last_hash: '' });
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [expandedEntry, setExpandedEntry] = useState<number | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [exporting, setExporting] = useState(false);

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message });
    setTimeout(() => setFeedback(null), 5000);
  };

  const load = useCallback(async () => {
    try {
      const data = await getAuditInfo();
      setAuditInfo(data);
      if ((data as any).entries && Array.isArray((data as any).entries)) {
        setEntries((data as any).entries);
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

  const handleVerifyChain = async () => {
    setVerifying(true);
    try {
      const result = await verifyAuditChain();
      if (result.valid) {
        showFeedback('success', 'Audit chain integrity verified. No tampering detected.');
      } else {
        showFeedback('error', `Chain broken at entry #${result.broken_at || 'unknown'}. Tampering detected!`);
      }
      setAuditInfo(prev => ({ ...prev, chain_valid: result.valid }));
    } catch (err: any) {
      showFeedback('error', err?.toString() || 'Failed to verify audit chain');
    } finally {
      setVerifying(false);
    }
  };

  const handleExport = async (format: string) => {
    setExporting(true);
    try {
      const result = await exportAuditLog(format);
      showFeedback('success', result.message || `Audit log exported as ${format.toUpperCase()}`);
    } catch (err: any) {
      showFeedback('error', err?.toString() || 'Failed to export audit log');
    } finally {
      setExporting(false);
    }
  };

  const filtered = entries.filter((e) => {
    if (!search) return true;
    const s = search.toLowerCase();
    return e.action.includes(s) || e.user.includes(s) || e.target.includes(s) || e.details.toLowerCase().includes(s);
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-3">
          <Cpu className="w-5 h-5 animate-spin" style={{ color: 'var(--accent)' }} />
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Loading audit log...</span>
        </div>
      </div>
    );
  }

  const chainEntries = entries.slice().reverse().slice(0, 12);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <h1 className="text-lg font-bold uppercase tracking-widest" style={{ color: 'var(--accent)' }}>Audit Trail</h1>
          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
            style={{
              backgroundColor: auditInfo.chain_valid ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)',
              border: `1px solid ${auditInfo.chain_valid ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)'}`,
            }}
          >
            <span
              className="w-2 h-2 rounded-full"
              style={{
                backgroundColor: auditInfo.chain_valid ? 'var(--low)' : 'var(--critical)',
                boxShadow: auditInfo.chain_valid ? '0 0 8px var(--low)' : '0 0 8px var(--critical)',
              }}
            />
            <span
              className="text-[10px] font-bold uppercase"
              style={{
                color: auditInfo.chain_valid ? 'var(--low)' : 'var(--critical)',
                letterSpacing: '0.1em',
              }}
            >
              {auditInfo.chain_valid ? 'Chain Valid' : 'Chain Broken'}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {feedback && (
            <span
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg"
              style={{
                backgroundColor: feedback.type === 'success' ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
                color: feedback.type === 'success' ? 'var(--low)' : 'var(--critical)',
                border: `1px solid ${feedback.type === 'success' ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)'}`,
              }}
            >
              {feedback.type === 'success' ? <CheckCircle className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
              {feedback.message}
            </span>
          )}
          <button
            onClick={() => handleExport('json')}
            disabled={exporting}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold uppercase tracking-wider transition-colors disabled:opacity-50"
            style={{
              backgroundColor: 'transparent',
              color: 'var(--accent)',
              border: '1px solid var(--accent)',
              letterSpacing: '0.05em',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(212,175,55,0.1)'; }}
            onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
          >
            <Download className="w-3.5 h-3.5" />
            {exporting ? 'Exporting...' : 'Export'}
          </button>
          <button
            onClick={load}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold uppercase tracking-wider transition-colors"
            style={{
              backgroundColor: 'var(--bg-elevated)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-color)',
              letterSpacing: '0.05em',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--border-active)'; }}
            onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; }}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div
          className="rounded-xl p-5 border-l-4"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderLeftColor: auditInfo.chain_valid ? 'var(--low)' : 'var(--critical)',
            borderTop: '1px solid var(--border-color)',
            borderRight: '1px solid var(--border-color)',
            borderBottom: '1px solid var(--border-color)',
          }}
        >
          <div className="flex items-center justify-between mb-3">
            <span className="text-[10px] uppercase font-semibold" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>Chain Integrity</span>
            <Shield className="w-5 h-5" style={{ color: auditInfo.chain_valid ? 'var(--low)' : 'var(--critical)' }} />
          </div>
          <div className="flex items-center gap-3">
            <span
              className="text-2xl font-bold uppercase"
              style={{
                color: auditInfo.chain_valid ? 'var(--low)' : 'var(--critical)',
                textShadow: auditInfo.chain_valid ? '0 0 20px rgba(34,197,94,0.3)' : '0 0 20px rgba(239,68,68,0.3)',
              }}
            >
              {auditInfo.chain_valid ? 'VALID' : 'BROKEN'}
            </span>
          </div>
          <p className="text-[10px] mt-2" style={{ color: 'var(--text-tertiary)' }}>
            {auditInfo.chain_valid ? 'All hash chains verified. No tampering detected.' : 'Chain integrity compromised!'}
          </p>
        </div>

        <div
          className="rounded-xl p-5 border-l-4"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderLeftColor: 'var(--accent)',
            borderTop: '1px solid var(--border-color)',
            borderRight: '1px solid var(--border-color)',
            borderBottom: '1px solid var(--border-color)',
          }}
        >
          <div className="flex items-center justify-between mb-3">
            <span className="text-[10px] uppercase font-semibold" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>Total Entries</span>
            <Database className="w-5 h-5" style={{ color: 'var(--accent)' }} />
          </div>
          <div className="text-3xl font-bold" style={{ color: 'var(--accent)' }}>{auditInfo.total_entries}</div>
          <p className="text-[10px] mt-2" style={{ color: 'var(--text-tertiary)' }}>
            Tamper-proof audit trail records
          </p>
        </div>

        <div
          className="rounded-xl p-5 border-l-4"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderLeftColor: 'var(--info)',
            borderTop: '1px solid var(--border-color)',
            borderRight: '1px solid var(--border-color)',
            borderBottom: '1px solid var(--border-color)',
          }}
        >
          <div className="flex items-center justify-between mb-3">
            <span className="text-[10px] uppercase font-semibold" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>Last Hash</span>
            <Hash className="w-5 h-5" style={{ color: 'var(--info)' }} />
          </div>
          <div className="text-xs font-mono break-all leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
            {auditInfo.last_hash || '—'}
          </div>
          <p className="text-[10px] mt-2" style={{ color: 'var(--text-tertiary)' }}>
            SHA-256 chain tip
          </p>
        </div>
      </div>

      {chainEntries.length > 0 && (
        <div
          className="rounded-xl p-5 border"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}
        >
          <span className="text-[10px] uppercase font-semibold block mb-4" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>Hash Chain Visualization</span>
          <div className="flex items-center gap-0 overflow-x-auto pb-3">
            {chainEntries.map((entry, i) => (
              <div key={entry.id} className="flex items-center shrink-0">
                <div className="flex flex-col items-center">
                  <div
                    className="w-10 h-10 rounded-full flex items-center justify-center text-[9px] font-mono font-bold transition-all"
                    style={{
                      backgroundColor: entry.integrity === 'valid' ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)',
                      border: `2px solid ${entry.integrity === 'valid' ? 'var(--low)' : 'var(--critical)'}`,
                      color: entry.integrity === 'valid' ? 'var(--low)' : 'var(--critical)',
                      boxShadow: entry.integrity === 'valid'
                        ? '0 0 12px rgba(34,197,94,0.15)'
                        : '0 0 12px rgba(239,68,68,0.15)',
                    }}
                  >
                    {entry.hash.slice(0, 4)}
                  </div>
                  <span className="text-[8px] font-mono mt-1" style={{ color: 'var(--text-tertiary)' }}>
                    #{entry.id}
                  </span>
                </div>
                {i < chainEntries.length - 1 && (
                  <div className="flex items-center mx-1">
                    <div className="w-8 h-0.5" style={{ backgroundColor: 'var(--border-color)' }} />
                    <div
                      className="w-0 h-0"
                      style={{
                        borderTop: '4px solid transparent',
                        borderBottom: '4px solid transparent',
                        borderLeft: `6px solid var(--border-color)`,
                      }}
                    />
                  </div>
                )}
              </div>
            ))}
          </div>
          <p className="text-[10px] mt-3" style={{ color: 'var(--text-tertiary)' }}>
            Each entry references the hash of the previous entry, creating a tamper-proof chain similar to blockchain.
          </p>
        </div>
      )}

      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
          <input
            type="text"
            placeholder="Search audit entries..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg text-sm border outline-none focus:ring-1 transition-all"
            style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-color)',
              color: 'var(--text-primary)',
              focusRingColor: 'var(--accent)',
            }}
            onFocus={(e) => { e.currentTarget.style.borderColor = 'var(--accent)'; }}
            onBlur={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; }}
          />
        </div>
        <button
          onClick={handleVerifyChain}
          disabled={verifying}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition-colors disabled:opacity-50"
          style={{
            backgroundColor: 'transparent',
            color: auditInfo.chain_valid ? 'var(--low)' : 'var(--critical)',
            border: `1px solid ${auditInfo.chain_valid ? 'var(--low)' : 'var(--critical)'}`,
            letterSpacing: '0.05em',
          }}
          onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = auditInfo.chain_valid ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)'; }}
          onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
        >
          <Shield className="w-3.5 h-3.5" />
          {verifying ? 'Verifying...' : 'Verify Chain'}
        </button>
        <span className="text-[10px] uppercase font-semibold" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>
          {filtered.length} entries
        </span>
      </div>

      <div
        className="rounded-xl border overflow-hidden"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}
      >
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--bg-elevated)' }}>
                <th className="text-left py-3 px-4 font-medium w-8" style={{ color: 'var(--text-tertiary)' }}></th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>Timestamp</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>Action</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>User</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>Target</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>Details</th>
                <th className="text-center py-3 px-4 font-medium" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>Chain</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center" style={{ color: 'var(--text-tertiary)' }}>
                    No audit entries found
                  </td>
                </tr>
              ) : filtered.map((entry) => (
                <>
                  <tr
                    key={entry.id}
                    className="border-b transition-colors cursor-pointer"
                    style={{ borderColor: 'var(--border-color)' }}
                    onClick={() => setExpandedEntry(expandedEntry === entry.id ? null : entry.id)}
                    onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(212,175,55,0.03)'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
                  >
                    <td className="py-3 px-4">
                      {expandedEntry === entry.id ? (
                        <ChevronUp className="w-3.5 h-3.5" style={{ color: 'var(--text-tertiary)' }} />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5" style={{ color: 'var(--text-tertiary)' }} />
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-[10px]" style={{ color: 'var(--accent)' }}>
                      {new Date(entry.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className="px-2 py-0.5 rounded text-[10px] font-bold uppercase"
                        style={{
                          backgroundColor: 'rgba(212,175,55,0.1)',
                          color: 'var(--accent)',
                          letterSpacing: '0.05em',
                          border: '1px solid rgba(212,175,55,0.15)',
                        }}
                      >
                        {entry.action}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-medium" style={{ color: 'var(--text-primary)' }}>{entry.user}</td>
                    <td className="py-3 px-4 font-mono text-[11px]" style={{ color: 'var(--text-secondary)' }}>{entry.target}</td>
                    <td className="py-3 px-4" style={{ color: 'var(--text-secondary)' }}>{entry.details}</td>
                    <td className="py-3 px-4 text-center">
                      {entry.integrity === 'valid' ? (
                        <span className="inline-flex items-center gap-1">
                          <CheckCircle className="w-3.5 h-3.5" style={{ color: 'var(--low)' }} />
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1">
                          <AlertTriangle className="w-3.5 h-3.5" style={{ color: 'var(--critical)' }} />
                        </span>
                      )}
                    </td>
                  </tr>
                  {expandedEntry === entry.id && (
                    <tr key={`${entry.id}-expanded`} className="border-b" style={{ borderColor: 'var(--border-color)' }}>
                      <td colSpan={7} className="py-3 px-8">
                        <div
                          className="grid grid-cols-2 gap-4 p-4 rounded-lg"
                          style={{ backgroundColor: 'var(--bg-elevated)', border: '1px solid var(--border-color)' }}
                        >
                          <div>
                            <span className="text-[10px] uppercase block mb-1 font-semibold" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>Entry Hash</span>
                            <code className="text-[10px] font-mono block break-all leading-relaxed" style={{ color: 'var(--accent)' }}>{entry.hash}</code>
                          </div>
                          <div>
                            <span className="text-[10px] uppercase block mb-1 font-semibold" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>Previous Hash</span>
                            <code className="text-[10px] font-mono block break-all leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{entry.prevHash}</code>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
