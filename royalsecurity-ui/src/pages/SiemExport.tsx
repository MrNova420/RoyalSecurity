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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">SIEM Export</h1>
        <div className="flex items-center gap-2">
          {feedback && (
            <span className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg ${feedback.type === 'success' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
              {feedback.type === 'success' ? <CheckCircle className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
              {feedback.message}
            </span>
          )}
        </div>
      </div>

      <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <h2 className="text-sm font-semibold mb-4">Export Events</h2>
        <div className="flex items-end gap-4">
          <div className="flex-1">
            <label className="text-[10px] font-medium uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-secondary)' }}>Format</label>
            <select
              value={format}
              onChange={(e) => setFormat(e.target.value)}
              className="w-full px-3 py-2 rounded-lg text-sm border outline-none focus:ring-1 focus:ring-indigo-500"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
            >
              {formats.map((f) => (
                <option key={f} value={f}>{f}</option>
              ))}
            </select>
          </div>
          <div className="flex-1">
            <label className="text-[10px] font-medium uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-secondary)' }}>Limit</label>
            <input
              type="number"
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
              min={1}
              max={100000}
              className="w-full px-3 py-2 rounded-lg text-sm border outline-none focus:ring-1 focus:ring-indigo-500"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
            />
          </div>
          <button
            onClick={handleExport}
            disabled={exporting}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors disabled:opacity-50"
          >
            {exporting ? <Cpu className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            {exporting ? 'Exporting...' : 'Export'}
          </button>
        </div>
      </div>

      <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <h2 className="text-sm font-semibold mb-4">STIX/TAXII Export</h2>
        <p className="text-xs mb-4" style={{ color: 'var(--text-secondary)' }}>
          Export threat intelligence data as a STIX 2.1 bundle for sharing with other security tools and platforms.
        </p>
        <button
          onClick={handleStixExport}
          disabled={exportingStix}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 transition-colors disabled:opacity-50"
        >
          {exportingStix ? <Cpu className="w-3.5 h-3.5 animate-spin" /> : <Package className="w-3.5 h-3.5" />}
          {exportingStix ? 'Exporting...' : 'Export STIX Bundle'}
        </button>
      </div>
    </div>
  );
}
