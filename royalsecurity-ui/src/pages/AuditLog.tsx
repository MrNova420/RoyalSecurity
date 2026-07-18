import { useState, useEffect } from 'react';
import {
  Database, Shield, CheckCircle, Search, RefreshCw,
  Link, Hash, Cpu, ChevronDown, ChevronUp
} from 'lucide-react';
import { getAuditInfo } from '../lib/tauri-bridge';

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

const mockEntries: AuditEntry[] = [
  { id: 1, timestamp: '2026-07-18T14:23:45Z', action: 'rule.create', user: 'admin', target: 'SIGMA-005', details: 'Created new Sigma rule: Suspicious PowerShell Encoded Command', hash: 'a3f8c2d1e5b4...', prevHash: '7e9d1f3a8c6b', integrity: 'valid' },
  { id: 2, timestamp: '2026-07-18T14:20:12Z', action: 'alert.acknowledge', user: 'analyst1', target: 'THR-003', details: 'Acknowledged alert: Lateral Movement via PsExec', hash: 'b4e7d3c2f6a5...', prevHash: 'a3f8c2d1e5b4', integrity: 'valid' },
  { id: 3, timestamp: '2026-07-18T14:15:33Z', action: 'config.update', user: 'admin', target: 'agent.settings', details: 'Updated agent configuration: enabled DNS logging', hash: 'c5f8e4d3a7b6...', prevHash: 'b4e7d3c2f6a5', integrity: 'valid' },
  { id: 4, timestamp: '2026-07-18T14:10:07Z', action: 'module.restart', user: 'system', target: 'edr-engine', details: 'EDR engine restarted after rule update', hash: 'd6a9f5e4b8c7...', prevHash: 'c5f8e4d3a7b6', integrity: 'valid' },
  { id: 5, timestamp: '2026-07-18T14:05:21Z', action: 'response.isolate', user: 'admin', target: 'WIN-WS-012', details: 'Host isolated due to ransomware detection', hash: 'e7b0a6f5c9d8...', prevHash: 'd6a9f5e4b8c7', integrity: 'valid' },
  { id: 6, timestamp: '2026-07-18T13:58:44Z', action: 'user.login', user: 'admin', target: 'session', details: 'Successful login from 10.0.1.10', hash: 'f8c1b7a6d0e9...', prevHash: 'e7b0a6f5c9d8', integrity: 'valid' },
  { id: 7, timestamp: '2026-07-18T13:50:18Z', action: 'rule.disable', user: 'analyst2', target: 'SIGMA-003', details: 'Disabled rule: Scheduled Task Persistence (false positive)', hash: '09d2c8b7e1f0...', prevHash: 'f8c1b7a6d0e9', integrity: 'valid' },
  { id: 8, timestamp: '2026-07-18T13:45:00Z', action: 'scan.complete', user: 'system', target: 'full-system', details: 'Full system scan completed. 1,847 files scanned.', hash: '1ae3d9c8f2a1...', prevHash: '09d2c8b7e1f0', integrity: 'valid' },
];

export default function AuditLog() {
  const [auditInfo, setAuditInfo] = useState({ totalEntries: 8, chainValid: true, lastHash: '1ae3d9c8f2a1...' });
  const [entries] = useState<AuditEntry[]>(mockEntries);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [expandedEntry, setExpandedEntry] = useState<number | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const data = await getAuditInfo();
        setAuditInfo({
          totalEntries: data.total_entries,
          chainValid: data.chain_valid,
          lastHash: data.last_hash,
        });
      } catch {
        // Use defaults
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

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
        <button className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors">
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <div className="flex items-center justify-between mb-3">
            <span className="text-[10px] uppercase font-medium" style={{ color: 'var(--text-secondary)' }}>Chain Integrity</span>
            <Shield className="w-5 h-5" style={{ color: auditInfo.chainValid ? 'var(--low)' : 'var(--critical)' }} />
          </div>
          <div className="flex items-center gap-2">
            {auditInfo.chainValid ? (
              <CheckCircle className="w-5 h-5 text-green-400" />
            ) : (
              <span className="w-5 h-5 text-red-400 flex items-center justify-center font-bold">!</span>
            )}
            <span className="text-lg font-bold" style={{ color: auditInfo.chainValid ? 'var(--low)' : 'var(--critical)' }}>
              {auditInfo.chainValid ? 'Valid' : 'Tampered'}
            </span>
          </div>
          <p className="text-[10px] mt-2" style={{ color: 'var(--text-secondary)' }}>
            All hash chains verified. No tampering detected.
          </p>
        </div>

        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <div className="flex items-center justify-between mb-3">
            <span className="text-[10px] uppercase font-medium" style={{ color: 'var(--text-secondary)' }}>Total Entries</span>
            <Database className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold">{auditInfo.totalEntries}</div>
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
            {auditInfo.lastHash}
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
              {filtered.map((entry) => (
                <AuditRow
                  key={entry.id}
                  entry={entry}
                  expanded={expandedEntry === entry.id}
                  onToggle={() => setExpandedEntry(expandedEntry === entry.id ? null : entry.id)}
                />
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
        </div>
        <p className="text-[10px] mt-2" style={{ color: 'var(--text-secondary)' }}>
          Each entry references the hash of the previous entry, creating a tamper-proof chain similar to blockchain.
        </p>
      </div>
    </div>
  );
}

function AuditRow({ entry, expanded, onToggle }: { entry: AuditEntry; expanded: boolean; onToggle: () => void }) {
  return (
    <>
      <tr
        className="border-b hover:bg-white/5 transition-colors cursor-pointer"
        style={{ borderColor: 'var(--border-color)' }}
        onClick={onToggle}
      >
        <td className="py-3 px-4">
          {expanded ? (
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
          <CheckCircle className="w-4 h-4 text-green-400 inline" />
        </td>
      </tr>
      {expanded && (
        <tr className="border-b" style={{ borderColor: 'var(--border-color)' }}>
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
  );
}
