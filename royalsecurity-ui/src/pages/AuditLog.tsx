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
          <Cpu className="w-5 h-5 text-indigo-400 animate-spin" />
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Loading audit log...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Audit Log</h1>
        <div className="flex items-center gap-2">
          {feedback && (
            <span className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg ${feedback.type === 'success' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
              {feedback.type === 'success' ? <CheckCircle className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
              {feedback.message}
            </span>
          )}
          <button
            onClick={() => handleExport('json')}
            disabled={exporting}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            {exporting ? 'Exporting...' : 'Export'}
          </button>
          <button onClick={load} className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors">
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <div className="flex items-center justify-between mb-3">
            <span className="text-[10px] uppercase font-medium" style={{ color: 'var(--text-secondary)' }}>Chain Integrity</span>
            <Shield className="w-5 h-5" style={{ color: auditInfo.chain_valid ? 'var(--low)' : 'var(--critical)' }} />
          </div>
          <div className="flex items-center gap-2">
            {auditInfo.chain_valid ? (
              <CheckCircle className="w-5 h-5 text-green-400" />
            ) : (
              <span className="w-5 h-5 text-red-400 flex items-center justify-center font-bold">!</span>
            )}
            <span className="text-lg font-bold" style={{ color: auditInfo.chain_valid ? 'var(--low)' : 'var(--critical)' }}>
              {auditInfo.chain_valid ? 'Valid' : 'Tampered'}
            </span>
          </div>
          <p className="text-[10px] mt-2" style={{ color: 'var(--text-secondary)' }}>
            {auditInfo.chain_valid ? 'All hash chains verified. No tampering detected.' : 'Chain integrity compromised!'}
          </p>
        </div>

        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <div className="flex items-center justify-between mb-3">
            <span className="text-[10px] uppercase font-medium" style={{ color: 'var(--text-secondary)' }}>Total Entries</span>
            <Database className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold">{auditInfo.total_entries}</div>
          <p className="text-[10px] mt-2" style={{ color: 'var(--text-secondary)' }}>
            Tamper-proof audit trail entries
          </p>
        </div>

        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <div className="flex items-center justify-between mb-3">
            <span className="text-[10px] uppercase font-medium" style={{ color: 'var(--text-secondary)' }}>Last Hash</span>
            <Hash className="w-5 h-5 text-purple-400" />
          </div>
          <div className="text-xs font-mono break-all" style={{ color: 'var(--text-secondary)' }}>
            {auditInfo.last_hash || '—'}
          </div>
          <p className="text-[10px] mt-2" style={{ color: 'var(--text-secondary)' }}>
            SHA-256 chain tip
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          <input
            type="text"
            placeholder="Search audit entries..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg text-sm border outline-none focus:ring-1 focus:ring-indigo-500"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
          />
        </div>
        <button
          onClick={handleVerifyChain}
          disabled={verifying}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium bg-green-500/20 text-green-400 hover:bg-green-500/30 transition-colors disabled:opacity-50"
        >
          <Shield className="w-3.5 h-3.5" />
          {verifying ? 'Verifying...' : 'Verify Chain'}
        </button>
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{filtered.length} entries</span>
      </div>

      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
                <th className="text-left py-3 px-4 font-medium w-8" style={{ color: 'var(--text-secondary)' }}></th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Timestamp</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Action</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>User</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Target</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Details</th>
                <th className="text-center py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Chain</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={7} className="py-8 text-center" style={{ color: 'var(--text-secondary)' }}>No audit entries found</td></tr>
              ) : filtered.map((entry) => (
                <>
                  <tr
                    key={entry.id}
                    className="border-b hover:bg-white/5 transition-colors cursor-pointer"
                    style={{ borderColor: 'var(--border-color)' }}
                    onClick={() => setExpandedEntry(expandedEntry === entry.id ? null : entry.id)}
                  >
                    <td className="py-3 px-4">
                      {expandedEntry === entry.id ? (
                        <ChevronUp className="w-3.5 h-3.5 text-gray-400" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5 text-gray-400" />
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-[10px]" style={{ color: 'var(--text-secondary)' }}>
                      {new Date(entry.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium" style={{ backgroundColor: 'rgba(99,102,241,0.1)', color: 'var(--accent)' }}>
                        {entry.action}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-medium">{entry.user}</td>
                    <td className="py-3 px-4 font-mono text-[11px]" style={{ color: 'var(--text-secondary)' }}>{entry.target}</td>
                    <td className="py-3 px-4" style={{ color: 'var(--text-secondary)' }}>{entry.details}</td>
                    <td className="py-3 px-4 text-center">
                      {entry.integrity === 'valid' ? (
                        <CheckCircle className="w-4 h-4 text-green-400 inline" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-red-400 inline" />
                      )}
                    </td>
                  </tr>
                  {expandedEntry === entry.id && (
                    <tr key={`${entry.id}-expanded`} className="border-b" style={{ borderColor: 'var(--border-color)' }}>
                      <td colSpan={7} className="py-3 px-8">
                        <div className="grid grid-cols-2 gap-4 p-3 rounded-lg" style={{ backgroundColor: 'var(--bg-secondary)' }}>
                          <div>
                            <span className="text-[10px] block mb-1" style={{ color: 'var(--text-secondary)' }}>Entry Hash</span>
                            <code className="text-[10px] font-mono">{entry.hash}</code>
                          </div>
                          <div>
                            <span className="text-[10px] block mb-1" style={{ color: 'var(--text-secondary)' }}>Previous Hash</span>
                            <code className="text-[10px] font-mono">{entry.prevHash}</code>
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

      <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <div className="flex items-center gap-2 mb-3">
          <Link className="w-4 h-4 text-indigo-400" />
          <h2 className="text-xs font-semibold">Hash Chain Verification</h2>
        </div>
        <div className="flex items-center gap-2 overflow-x-auto pb-2">
          {entries.slice().reverse().map((entry, i) => (
            <div key={entry.id} className="flex items-center gap-1 shrink-0">
              <div className="px-2 py-1 rounded text-[9px] font-mono" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
                {entry.hash.slice(0, 8)}
              </div>
              {i < entries.length - 1 && <span className="text-gray-600">&rarr;</span>}
            </div>
          ))}
          {entries.length === 0 && <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>No chain data</span>}
        </div>
        <p className="text-[10px] mt-2" style={{ color: 'var(--text-secondary)' }}>
          Each entry references the hash of the previous entry, creating a tamper-proof chain similar to blockchain.
        </p>
      </div>
    </div>
  );
}
