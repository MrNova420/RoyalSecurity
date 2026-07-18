import { useState, useEffect, useCallback } from 'react';
import {
  Search, RefreshCw, Cpu, FileSearch, Clock, CheckCircle
} from 'lucide-react';
import { runForensicTriage } from '../lib/tauri-bridge';

interface ForensicResults {
  hostname: string;
  timestamp: string;
  evtx_events: number;
  mft_entries: number;
  prefetch_files: number;
  registry_hives: number;
  shimcache_entries: number;
  amcache_entries: number;
  srum_records: number;
  lnk_files: number;
  usn_entries: number;
  [key: string]: unknown;
}

function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
      <span className="text-[10px] font-medium uppercase tracking-wide block mb-1" style={{ color: 'var(--text-secondary)' }}>{label}</span>
      <span className="text-lg font-bold">{value}</span>
    </div>
  );
}

export default function Forensics() {
  const [results, setResults] = useState<ForensicResults | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await runForensicTriage();
      setResults(data as ForensicResults);
    } catch (err: any) {
      setError(err?.toString() || 'Failed to run forensic triage');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    run();
  }, [run]);

  const counters = results ? [
    { label: 'EVTX Events', value: results.evtx_events ?? 0 },
    { label: 'MFT Entries', value: results.mft_entries ?? 0 },
    { label: 'Prefetch Files', value: results.prefetch_files ?? 0 },
    { label: 'Registry Hives', value: results.registry_hives ?? 0 },
    { label: 'Shimcache Entries', value: results.shimcache_entries ?? 0 },
    { label: 'Amcache Entries', value: results.amcache_entries ?? 0 },
    { label: 'SRUM Records', value: results.srum_records ?? 0 },
    { label: 'LNK Files', value: results.lnk_files ?? 0 },
    { label: 'USN Entries', value: results.usn_entries ?? 0 },
  ] : [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Forensic Triage</h1>
        <div className="flex items-center gap-3">
          {results && (
            <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
              <Clock className="w-4 h-4" />
              {results.timestamp || 'N/A'}
            </div>
          )}
          <button
            onClick={run}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Run Triage
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl p-4 border bg-red-500/10 border-red-500/20 text-red-400 text-sm">
          {error}
        </div>
      )}

      {loading && !results && (
        <div className="flex items-center justify-center h-64">
          <div className="flex items-center gap-3">
            <Cpu className="w-5 h-5 text-indigo-400 animate-spin" />
            <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Running forensic triage...</span>
          </div>
        </div>
      )}

      {results && (
        <>
          <div className="rounded-xl p-4 border flex items-center gap-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
            <FileSearch className="w-5 h-5 text-indigo-400" />
            <div>
              <span className="text-sm font-medium">{results.hostname || 'Unknown Host'}</span>
              <span className="text-xs ml-3" style={{ color: 'var(--text-secondary)' }}>Triage completed successfully</span>
            </div>
            <div className="ml-auto flex items-center gap-1.5 text-green-400 text-xs">
              <CheckCircle className="w-3.5 h-3.5" />
              Complete
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-3 gap-4">
            {counters.map((item) => (
              <StatCard key={item.label} label={item.label} value={item.value} />
            ))}
          </div>
        </>
      )}

      {!loading && !results && !error && (
        <div className="flex items-center justify-center h-64">
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>No results yet. Click "Run Triage" to begin.</span>
        </div>
      )}
    </div>
  );
}
