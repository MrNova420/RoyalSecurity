import { useState, useEffect, useCallback } from 'react';
import {
  Search, RefreshCw, Cpu, AlertTriangle, Shield, CheckCircle
} from 'lucide-react';
import { scanVulnerabilities, searchCves, getCveDetails } from '../lib/tauri-bridge';

interface ScanResults {
  total_cves_in_db: number;
  critical_cves: number;
  missing_patches: Array<{ id: string; severity: string; description: string; kb: string }>;
  [key: string]: unknown;
}

export default function VulnScan() {
  const [query, setQuery] = useState('');
  const [scanData, setScanData] = useState<ScanResults | null>(null);
  const [searchResults, setSearchResults] = useState<unknown[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message });
    setTimeout(() => setFeedback(null), 4000);
  };

  const runScan = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await scanVulnerabilities();
      setScanData(data as ScanResults);
      showFeedback('success', 'Vulnerability scan completed');
    } catch (err: any) {
      setError(err?.toString() || 'Scan failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    runScan();
  }, [runScan]);

  const handleSearch = async () => {
    if (!query.trim()) return;
    setSearching(true);
    setError(null);
    try {
      const data = await searchCves(query);
      setSearchResults(Array.isArray(data) ? data : [data]);
    } catch (err: any) {
      setError(err?.toString() || 'Search failed');
    } finally {
      setSearching(false);
    }
  };

  const handleCveLookup = async (cveId: string) => {
    try {
      const data = await getCveDetails(cveId);
      setSearchResults([data]);
    } catch (err: any) {
      showFeedback('error', err?.toString() || 'CVE lookup failed');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Vulnerability Management</h1>
        <div className="flex items-center gap-2">
          {feedback && (
            <span className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg ${feedback.type === 'success' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
              {feedback.type === 'success' ? <CheckCircle className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
              {feedback.message}
            </span>
          )}
          <button
            onClick={runScan}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Run Scan
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl p-4 border bg-red-500/10 border-red-500/20 text-red-400 text-sm">
          {error}
        </div>
      )}

      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          <input
            type="text"
            placeholder="Search CVEs (e.g. CVE-2024-12345)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            className="w-full pl-9 pr-4 py-2 rounded-lg text-sm border outline-none focus:ring-1 focus:ring-indigo-500"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
          />
        </div>
        <button
          onClick={handleSearch}
          disabled={searching || !query.trim()}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors disabled:opacity-50"
        >
          <Search className="w-3.5 h-3.5" />
          {searching ? 'Searching...' : 'Search'}
        </button>
      </div>

      {loading && !scanData && (
        <div className="flex items-center justify-center h-64">
          <div className="flex items-center gap-3">
            <Cpu className="w-5 h-5 text-indigo-400 animate-spin" />
            <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Scanning for vulnerabilities...</span>
          </div>
        </div>
      )}

      {scanData && (
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          {[
            { label: 'CVEs in Database', value: scanData.total_cves_in_db ?? 0, icon: Shield, color: 'var(--info)' },
            { label: 'Critical CVEs', value: scanData.critical_cves ?? 0, icon: AlertTriangle, color: 'var(--critical)' },
            { label: 'Missing Patches', value: scanData.missing_patches?.length ?? 0, icon: AlertTriangle, color: 'var(--medium)' },
          ].map((item) => (
            <div key={item.label} className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-medium uppercase tracking-wide" style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                <item.icon className="w-4 h-4" style={{ color: item.color }} />
              </div>
              <div className="text-2xl font-bold">{item.value}</div>
            </div>
          ))}
        </div>
      )}

      {scanData?.missing_patches && scanData.missing_patches.length > 0 && (
        <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
                  <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>ID</th>
                  <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Severity</th>
                  <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Description</th>
                  <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>KB</th>
                </tr>
              </thead>
              <tbody>
                {scanData.missing_patches.map((patch, idx) => (
                  <tr key={idx} className="border-b hover:bg-white/5 transition-colors" style={{ borderColor: 'var(--border-color)' }}>
                    <td className="py-2.5 px-4 font-mono text-[11px]">{patch.id}</td>
                    <td className="py-2.5 px-4">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase" style={{
                        backgroundColor: patch.severity === 'critical' ? 'rgba(239,68,68,0.15)' : patch.severity === 'high' ? 'rgba(249,115,22,0.15)' : 'rgba(234,179,8,0.15)',
                        color: patch.severity === 'critical' ? 'var(--critical)' : patch.severity === 'high' ? 'var(--high)' : 'var(--medium)',
                      }}>
                        {patch.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-4" style={{ color: 'var(--text-secondary)' }}>{patch.description}</td>
                    <td className="py-2.5 px-4 font-mono text-[11px]">{patch.kb}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {searchResults && searchResults.length > 0 && (
        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <h2 className="text-sm font-semibold mb-3">Search Results</h2>
          <pre className="text-xs overflow-auto max-h-80 p-3 rounded-lg" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
            {JSON.stringify(searchResults, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
