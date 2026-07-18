import { useState, useEffect } from 'react';
import {
  Shield, CheckCircle, XCircle, AlertTriangle, Download, Cpu
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar
} from 'recharts';
import { getComplianceStatus } from '../lib/tauri-bridge';

interface ComplianceFramework {
  name: string;
  score: number;
  passed: number;
  failed: number;
  warnings: number;
  total: number;
  color: string;
}

const radarData = [
  { category: 'Access Control', score: 85 },
  { category: 'Audit Logging', score: 92 },
  { category: 'Configuration', score: 71 },
  { category: 'Encryption', score: 88 },
  { category: 'Network Security', score: 79 },
  { category: 'Endpoint Protection', score: 94 },
  { category: 'Patch Management', score: 68 },
  { category: 'Incident Response', score: 82 },
];

const findings = [
  { id: 'F-001', framework: 'CIS', severity: 'high', control: '1.1.1', title: 'Disable unnecessary SMBv1', status: 'failed', description: 'SMBv1 protocol is enabled on this system. This protocol has known vulnerabilities.' },
  { id: 'F-002', framework: 'CIS', severity: 'medium', control: '2.2.1', title: 'Audit PowerShell script block logging', status: 'failed', description: 'PowerShell script block logging is not enabled. Required for attack visibility.' },
  { id: 'F-003', framework: 'STIG', severity: 'high', control: 'V-254287', title: 'Windows Defender real-time protection', status: 'passed', description: 'Real-time protection is enabled and up to date.' },
  { id: 'F-004', framework: 'CIS', severity: 'critical', control: '5.1', title: 'BitLocker full disk encryption', status: 'failed', description: 'System drive is not encrypted with BitLocker.' },
  { id: 'F-005', framework: 'STIG', severity: 'low', control: 'V-254293', title: 'Screen saver timeout', status: 'passed', description: 'Screen saver timeout is set to 900 seconds or less.' },
  { id: 'F-006', framework: 'NIST', severity: 'medium', control: 'AC-7', title: 'Account lockout threshold', status: 'warning', description: 'Account lockout threshold is set to 0 (disabled).' },
  { id: 'F-007', framework: 'CIS', severity: 'high', control: '9.1', title: 'Windows Firewall domain profile', status: 'passed', description: 'Domain profile firewall is enabled.' },
  { id: 'F-008', framework: 'STIG', severity: 'medium', control: 'V-254301', title: 'NTLMv1 authentication disabled', status: 'failed', description: 'NTLMv1 is still allowed. Should be disabled in favor of NTLMv2 or Kerberos.' },
];

const frameworkColors: Record<string, string> = {
  CIS: 'var(--accent)',
  STIG: 'var(--info)',
  NIST: 'var(--medium)',
};

const statusColors: Record<string, { color: string; icon: any; bg: string }> = {
  passed: { color: 'var(--low)', icon: CheckCircle, bg: 'rgba(34,197,94,0.1)' },
  failed: { color: 'var(--critical)', icon: XCircle, bg: 'rgba(239,68,68,0.1)' },
  warning: { color: 'var(--medium)', icon: AlertTriangle, bg: 'rgba(234,179,8,0.1)' },
};

const severityColors: Record<string, string> = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
};

export default function Compliance() {
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([
    { name: 'CIS Benchmark', score: 72, passed: 186, failed: 48, warnings: 21, total: 255, color: '#6366f1' },
    { name: 'STIG Benchmark', score: 81, passed: 204, failed: 34, warnings: 17, total: 255, color: '#3b82f6' },
    { name: 'NIST 800-53', score: 78, passed: 156, failed: 31, warnings: 13, total: 200, color: '#eab308' },
  ]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const data = await getComplianceStatus();
        const total = data.passed + data.failed + data.warnings;
        setFrameworks((prev) => prev.map((f) => ({
          ...f,
          score: total > 0 ? Math.round((data.passed / total) * 100) : f.score,
          passed: data.passed,
          failed: data.failed,
          warnings: data.warnings,
          total,
        })));
      } catch {
        // Use defaults
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-3">
          <Cpu className="w-5 h-5 text-indigo-400 animate-spin" />
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Loading compliance data...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Compliance</h1>
        <button className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors">
          <Download className="w-3.5 h-3.5" />
          Export Report
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {frameworks.map((fw) => (
          <div key={fw.name} className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5" style={{ color: fw.color }} />
                <span className="text-sm font-semibold">{fw.name}</span>
              </div>
              <span className="text-2xl font-bold" style={{ color: fw.color }}>{fw.score}%</span>
            </div>
            <div className="h-2.5 rounded-full mb-4" style={{ backgroundColor: 'var(--bg-secondary)' }}>
              <div className="h-2.5 rounded-full transition-all" style={{ width: `${fw.score}%`, backgroundColor: fw.color }} />
            </div>
            <div className="grid grid-cols-3 gap-2 text-center">
              <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(34,197,94,0.1)' }}>
                <div className="text-sm font-bold text-green-400">{fw.passed}</div>
                <div className="text-[10px]" style={{ color: 'var(--text-secondary)' }}>Passed</div>
              </div>
              <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(239,68,68,0.1)' }}>
                <div className="text-sm font-bold text-red-400">{fw.failed}</div>
                <div className="text-[10px]" style={{ color: 'var(--text-secondary)' }}>Failed</div>
              </div>
              <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(234,179,8,0.1)' }}>
                <div className="text-sm font-bold text-yellow-400">{fw.warnings}</div>
                <div className="text-[10px]" style={{ color: 'var(--text-secondary)' }}>Warnings</div>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <h2 className="text-sm font-semibold mb-4">Category Coverage</h2>
          <ResponsiveContainer width="100%" height={280}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#1e2d4a" />
              <PolarAngleAxis dataKey="category" tick={{ fontSize: 9, fill: '#9ca3af' }} />
              <PolarRadiusAxis angle={90} domain={[0, 100]} tick={{ fontSize: 8, fill: '#9ca3af' }} />
              <Radar name="Score" dataKey="score" stroke="#6366f1" fill="#6366f1" fillOpacity={0.2} strokeWidth={2} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <h2 className="text-sm font-semibold mb-4">Results by Framework</h2>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={frameworks}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
              <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={{ backgroundColor: '#1a2236', border: '1px solid #1e2d4a', borderRadius: '8px', fontSize: '12px' }} />
              <Bar dataKey="passed" stackId="a" fill="#22c55e" />
              <Bar dataKey="warnings" stackId="a" fill="#eab308" />
              <Bar dataKey="failed" stackId="a" fill="#ef4444" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-4 mt-2">
            {[
              { label: 'Passed', color: '#22c55e' },
              { label: 'Warnings', color: '#eab308' },
              { label: 'Failed', color: '#ef4444' },
            ].map((item) => (
              <div key={item.label} className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded" style={{ backgroundColor: item.color }} />
                <span className="text-[10px]" style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <div className="px-4 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
          <span className="text-xs font-semibold">Compliance Findings</span>
          <span className="text-xs px-2 py-0.5 rounded-full" style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: 'var(--critical)' }}>
            {findings.filter(f => f.status === 'failed').length} failures
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b" style={{ borderColor: 'var(--border-color)' }}>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Status</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Framework</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Control</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Severity</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Title</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Description</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => {
                const st = statusColors[finding.status];
                const StatusIcon = st.icon;
                return (
                  <tr key={finding.id} className="border-b hover:bg-white/5 transition-colors" style={{ borderColor: 'var(--border-color)' }}>
                    <td className="py-3 px-4">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium" style={{ backgroundColor: st.bg, color: st.color }}>
                        <StatusIcon className="w-3 h-3" />
                        {finding.status}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-[10px] px-1.5 py-0.5 rounded font-medium" style={{ backgroundColor: `${frameworkColors[finding.framework]}20`, color: frameworkColors[finding.framework] }}>
                        {finding.framework}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px]" style={{ color: 'var(--text-secondary)' }}>{finding.control}</td>
                    <td className="py-3 px-4">
                      <span className="text-[10px] font-semibold uppercase" style={{ color: severityColors[finding.severity] }}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-medium">{finding.title}</td>
                    <td className="py-3 px-4" style={{ color: 'var(--text-secondary)' }}>{finding.description}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
