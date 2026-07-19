import { useState, useCallback } from 'react';
import {
  Download, RefreshCw, Cpu, AlertTriangle, CheckCircle, FileText, Package
} from 'lucide-react';
import { exportSiemEvents, exportStixBundle } from '../lib/tauri-bridge';

const formats = ['JSON', 'ECS', 'CEF', 'Syslog', 'CSV', 'Splunk'] as const;

export default function SiemExport() {
  const [format, setFormat] = useState<string>('JSON');
  const [limit, setLimit] = useState<number>(1000);
  const [exporting, setExporting] = useState(false);
  const [exportingStix, setExportingStix] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message });
    setTimeout(() => setFeedback(null), 4000);
  };

  const handleExport = async () => {
    setExporting(true);
    try {
      const result = await exportSiemEvents(format, limit);
      showFeedback('success', `Exported events as ${format}${(result as any)?.path ? ` to ${(result as any).path}` : ''}`);
    } catch (err: any) {
      showFeedback('error', err?.toString() || 'Export failed');
    } finally {
      setExporting(false);
    }
  };

  const handleStixExport = async () => {
    setExportingStix(true);
    try {
      const result = await exportStixBundle();
      showFeedback('success', `STIX bundle exported${(result as any)?.path ? ` to ${(result as any).path}` : ''}`);
    } catch (err: any) {
      showFeedback('error', err?.toString() || 'STIX export failed');
    } finally {
      setExportingStix(false);
    }
  };

  const formatCards = formats.map((f) => ({
    id: f,
    name: f,
    description: f === 'JSON' ? 'Standard JSON format'
      : f === 'ECS' ? 'Elastic Common Schema'
      : f === 'CEF' ? 'Common Event Format'
      : f === 'Syslog' ? 'Syslog message format'
      : f === 'CSV' ? 'Comma-separated values'
      : 'Splunk HEC format',
    isActive: format === f,
  }));

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>SIEM INTEGRATION</h1>
          <p className="text-[10px] uppercase mt-1" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Event Export & Threat Intelligence Sharing</p>
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
        </div>
      </div>

      <div className="rounded-xl border p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <span className="text-[10px] font-medium uppercase block mb-4" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Export Format</span>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
          {formatCards.map((fc) => (
            <button
              key={fc.id}
              onClick={() => setFormat(fc.id)}
              className="rounded-xl p-4 border transition-all text-left"
              style={{
                backgroundColor: fc.isActive ? 'var(--bg-elevated)' : 'var(--bg-card)',
                borderColor: fc.isActive ? 'var(--accent)' : 'var(--border-color)',
                borderLeft: `4px solid ${fc.isActive ? 'var(--accent)' : 'transparent'}`,
                boxShadow: fc.isActive ? '0 0 20px rgba(201,168,76,0.1)' : 'none',
              }}
              onMouseEnter={(e) => { if (!fc.isActive) e.currentTarget.style.borderColor = 'var(--border-active)'; }}
              onMouseLeave={(e) => { if (!fc.isActive) e.currentTarget.style.borderColor = 'var(--border-color)'; }}
            >
              <div className="text-sm font-medium mb-1" style={{ color: fc.isActive ? 'var(--accent)' : 'var(--text-primary)' }}>{fc.name}</div>
              <div className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{fc.description}</div>
            </button>
          ))}
        </div>

        <div className="flex items-end gap-4">
          <div className="flex-1">
            <label className="text-[10px] font-medium uppercase block mb-2" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Record Limit</label>
            <input
              type="number"
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
              min={1}
              max={100000}
              className="w-full px-4 py-2.5 rounded-xl text-sm border outline-none transition-all focus:border-[var(--border-active)]"
              style={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
            />
          </div>
          <button
            onClick={handleExport}
            disabled={exporting}
            className="flex items-center gap-2 px-6 py-2.5 rounded-xl text-xs font-medium transition-all disabled:opacity-50"
            style={{
              border: '1px solid var(--accent)',
              color: 'var(--accent)',
              backgroundColor: 'transparent',
            }}
            onMouseEnter={(e) => { if (!e.currentTarget.disabled) e.currentTarget.style.backgroundColor = 'var(--accent-muted)'; }}
            onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
          >
            {exporting ? <Cpu className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            {exporting ? 'Exporting...' : 'Export Events'}
          </button>
        </div>
      </div>

      <div className="rounded-xl border p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderLeft: '4px solid var(--accent)' }}>
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'var(--bg-elevated)' }}>
            <Package className="w-5 h-5" style={{ color: 'var(--accent)' }} />
          </div>
          <div>
            <span className="text-[10px] font-medium uppercase" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>STIX / TAXII Export</span>
            <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              Share threat intelligence as STIX 2.1 bundles
            </p>
          </div>
        </div>
        <p className="text-xs mb-4" style={{ color: 'var(--text-secondary)' }}>
          Export threat intelligence data as a STIX 2.1 bundle for sharing with other security tools and platforms.
        </p>
        <button
          onClick={handleStixExport}
          disabled={exportingStix}
          className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-medium transition-all disabled:opacity-50"
          style={{
            border: '1px solid var(--accent)',
            color: 'var(--accent)',
            backgroundColor: 'transparent',
          }}
          onMouseEnter={(e) => { if (!e.currentTarget.disabled) e.currentTarget.style.backgroundColor = 'var(--accent-muted)'; }}
          onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
        >
          {exportingStix ? <Cpu className="w-3.5 h-3.5 animate-spin" /> : <Package className="w-3.5 h-3.5" />}
          {exportingStix ? 'Exporting...' : 'Export STIX Bundle'}
        </button>
      </div>
    </div>
  );
}
