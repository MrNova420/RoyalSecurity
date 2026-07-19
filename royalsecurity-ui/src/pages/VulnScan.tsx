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
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>VULNERABILITY ASSESSMENT</h1>
          <p className="text-[10px] uppercase mt-1" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>CVE Database & Patch Management</p>
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
          <button
            onClick={runScan}
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
            Run Scan
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl p-4 border text-sm" style={{ backgroundColor: 'rgba(239,68,68,0.1)', borderColor: 'rgba(239,68,68,0.2)', color: 'var(--critical)' }}>
          {error}
        </div>
      )}

      <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <label className="text-[10px] font-medium uppercase block mb-2" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Search CVE Database</label>
        <div className="flex items-center gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
            <input
              type="text"
              placeholder="Search CVEs (e.g. CVE-2024-12345)..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              className="w-full pl-9 pr-4 py-2.5 rounded-xl text-sm border outline-none transition-all focus:border-[var(--border-active)]"
              style={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
            />
          </div>
          <button
            onClick={handleSearch}
            disabled={searching || !query.trim()}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-medium transition-all disabled:opacity-50"
            style={{
              border: '1px solid var(--accent)',
              color: 'var(--accent)',
              backgroundColor: 'transparent',
            }}
            onMouseEnter={(e) => { if (!e.currentTarget.disabled) e.currentTarget.style.backgroundColor = 'var(--accent-muted)'; }}
            onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
          >
            <Search className="w-3.5 h-3.5" />
            {searching ? 'Searching...' : 'Search'}
          </button>
        </div>
      </div>

      {loading && !scanData && (
        <div className="flex items-center justify-center h-64">
          <div className="flex items-center gap-3">
            <Cpu className="w-5 h-5 animate-spin" style={{ color: 'var(--accent)' }} />
            <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Scanning for vulnerabilities...</span>
          </div>
        </div>
      )}

      {scanData && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { label: 'CVEs in Database', value: scanData.total_cves_in_db ?? 0, icon: Shield, color: 'var(--accent)' },
            { label: 'Critical CVEs', value: scanData.critical_cves ?? 0, icon: AlertTriangle, color: 'var(--critical)' },
            { label: 'Missing Patches', value: scanData.missing_patches?.length ?? 0, icon: AlertTriangle, color: 'var(--medium)' },
          ].map((item) => (
            <div key={item.label} className="rounded-xl p-4 border transition-all hover:shadow-lg" style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-color)',
              borderLeft: '4px solid ' + item.color,
              boxShadow: '0 0 15px rgba(201,168,76,0.05)',
            }}
              onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--border-active)'; e.currentTarget.style.boxShadow = '0 0 20px rgba(201,168,76,0.1)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; e.currentTarget.style.boxShadow = '0 0 15px rgba(201,168,76,0.05)'; }}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-medium uppercase" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>{item.label}</span>
                <item.icon className="w-4 h-4" style={{ color: item.color }} />
              </div>
              <div className="text-2xl font-bold font-mono" style={{ color: 'var(--text-primary)' }}>{item.value.toLocaleString()}</div>
            </div>
          ))}
        </div>
      )}

      {scanData?.missing_patches && scanData.missing_patches.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-medium uppercase" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Missing Patches</span>
            <span className="text-[10px] px-2 py-0.5 rounded-full" style={{ backgroundColor: 'var(--accent-muted)', color: 'var(--accent)' }}>
              {scanData.missing_patches.length} found
            </span>
          </div>
          <div className="space-y-2">
            {scanData.missing_patches.map((patch, idx) => (
              <div key={idx} className="rounded-xl border p-4 transition-all hover:shadow-md" style={{
                backgroundColor: 'var(--bg-card)',
                borderColor: 'var(--border-color)',
                borderLeft: `4px solid ${patch.severity === 'critical' ? 'var(--critical)' : patch.severity === 'high' ? 'var(--high)' : 'var(--medium)'}`,
              }}
                onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--border-active)'; }}
                onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; }}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-sm font-medium" style={{ color: 'var(--accent)' }}>{patch.id}</span>
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase" style={{
                    backgroundColor: patch.severity === 'critical' ? 'rgba(239,68,68,0.15)' : patch.severity === 'high' ? 'rgba(249,115,22,0.15)' : 'rgba(234,179,8,0.15)',
                    color: patch.severity === 'critical' ? 'var(--critical)' : patch.severity === 'high' ? 'var(--high)' : 'var(--medium)',
                  }}>
                    {patch.severity}
                  </span>
                </div>
                <p className="text-xs mb-2" style={{ color: 'var(--text-secondary)' }}>{patch.description}</p>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] px-2 py-0.5 rounded font-mono" style={{ backgroundColor: 'var(--bg-elevated)', color: 'var(--text-tertiary)' }}>
                    {patch.kb}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {searchResults && searchResults.length > 0 && (
        <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderLeft: '4px solid var(--accent)' }}>
          <div className="flex items-center justify-between mb-3">
            <span className="text-[10px] font-medium uppercase" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Search Results</span>
            <span className="text-[10px] px-2 py-0.5 rounded-full" style={{ backgroundColor: 'var(--accent-muted)', color: 'var(--accent)' }}>
              {searchResults.length} result{searchResults.length > 1 ? 's' : ''}
            </span>
          </div>
          <pre className="text-xs overflow-auto max-h-80 p-3 rounded-xl font-mono" style={{ backgroundColor: 'var(--bg-elevated)', color: 'var(--text-secondary)' }}>
            {JSON.stringify(searchResults, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
