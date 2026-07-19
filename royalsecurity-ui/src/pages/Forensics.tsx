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

  const evtxCounters = results ? counters.filter(c => ['EVTX Events'].includes(c.label)) : [];
  const mftCounters = results ? counters.filter(c => ['MFT Entries', 'USN Entries'].includes(c.label)) : [];
  const prefetchCounters = results ? counters.filter(c => ['Prefetch Files', 'LNK Files'].includes(c.label)) : [];
  const registryCounters = results ? counters.filter(c => ['Registry Hives', 'Shimcache Entries', 'Amcache Entries', 'SRUM Records'].includes(c.label)) : [];

  const sections = [
    { title: 'EVTX Logs', items: evtxCounters },
    { title: 'MFT & USN Journal', items: mftCounters },
    { title: 'Prefetch & LNK', items: prefetchCounters },
    { title: 'Registry & Cache', items: registryCounters },
  ].filter(s => s.items.length > 0);

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>DIGITAL FORENSICS</h1>
          <p className="text-[10px] uppercase mt-1" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Triage & Artifact Collection</p>
        </div>
        <div className="flex items-center gap-3">
          {results && (
            <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
              <Clock className="w-4 h-4" />
              <span className="font-mono text-[11px]">{results.timestamp || 'N/A'}</span>
            </div>
          )}
          <button
            onClick={run}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-medium transition-all disabled:opacity-50"
            style={{
              border: '1px solid var(--accent)',
              color: 'var(--accent)',
              backgroundColor: 'transparent',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--accent-muted)'; }}
            onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Run Triage
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl p-4 border text-sm" style={{ backgroundColor: 'rgba(239,68,68,0.1)', borderColor: 'rgba(239,68,68,0.2)', color: 'var(--critical)' }}>
          {error}
        </div>
      )}

      {loading && !results && (
        <div className="flex items-center justify-center h-64">
          <div className="flex items-center gap-3">
            <Cpu className="w-5 h-5 animate-spin" style={{ color: 'var(--accent)' }} />
            <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Running forensic triage...</span>
          </div>
        </div>
      )}

      {results && (
        <>
          <div className="rounded-xl p-4 border flex items-center gap-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'var(--bg-elevated)' }}>
              <FileSearch className="w-5 h-5" style={{ color: 'var(--accent)' }} />
            </div>
            <div className="flex-1">
              <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{results.hostname || 'Unknown Host'}</span>
              <span className="text-xs ml-3" style={{ color: 'var(--text-secondary)' }}>Triage completed successfully</span>
            </div>
            <div className="flex items-center gap-1.5 text-xs font-medium" style={{ color: 'var(--low)' }}>
              <CheckCircle className="w-3.5 h-3.5" />
              Complete
            </div>
          </div>

          <div className="space-y-4">
            {sections.map((section) => (
              <div key={section.title} className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderLeft: '4px solid var(--accent)' }}>
                <div className="px-4 py-3 flex items-center justify-between" style={{ backgroundColor: 'var(--bg-elevated)' }}>
                  <div>
                    <span className="text-[10px] font-medium uppercase" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>{section.title}</span>
                    <span className="ml-2 text-[10px] px-2 py-0.5 rounded-full" style={{ backgroundColor: 'var(--accent-muted)', color: 'var(--accent)' }}>
                      {section.items.reduce((sum, item) => sum + (item.value as number), 0)} entries
                    </span>
                  </div>
                  <FileSearch className="w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-0 divide-y md:divide-y-0 md:divide-x" style={{ borderColor: 'var(--border-color)' }}>
                  {section.items.map((item) => (
                    <div key={item.label} className="p-4">
                      <span className="text-[10px] font-medium uppercase block mb-1" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>{item.label}</span>
                      <span className="text-lg font-bold font-mono" style={{ color: 'var(--text-primary)' }}>{item.value.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {!loading && !results && !error && (
        <div className="flex flex-col items-center justify-center h-64 gap-3">
          <FileSearch className="w-8 h-8" style={{ color: 'var(--text-tertiary)' }} />
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>No results yet. Click "Run Triage" to begin.</span>
        </div>
      )}
    </div>
  );
}
