import { useState } from 'react';
import {
  Play, Save, AlertTriangle, CheckCircle, XCircle,
  Code, Search, Copy, Trash2, Plus
} from 'lucide-react';

interface Rule {
  id: string;
  name: string;
  source: 'sigma' | 'yara' | 'snort';
  status: 'active' | 'disabled' | 'error';
  severity: string;
  description: string;
}

const sampleSigmaRule = `title: Suspicious PowerShell Encoded Command
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects suspicious encoded PowerShell commands often used in attacks
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: RoyalSecurity SOC
date: 2026/07/18
modified: 2026/07/18
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
      - '-e '
  filter_legit:
    ParentImage|endswith:
      - '\\sccm.exe'
      - '\\configmgr.exe'
  condition: selection and not filter_legit
falsepositives:
  - Legitimate SCCM deployments
  - Automated deployment scripts
level: high
actions:
  - isolate_host
  - collect_forensics`;

const defaultRules: Rule[] = [
  { id: 'SIGMA-001', name: 'Suspicious PowerShell Encoded Command', source: 'sigma', status: 'active', severity: 'high', description: 'Encoded PowerShell execution' },
  { id: 'SIGMA-002', name: 'Credential Dumping via LSASS', source: 'sigma', status: 'active', severity: 'critical', description: 'LSASS memory access' },
  { id: 'YARA-001', name: 'Ransomware Behavior Pattern', source: 'yara', status: 'active', severity: 'critical', description: 'Bulk file encryption detection' },
  { id: 'YARA-002', name: 'Mimikatz Memory Scan', source: 'yara', status: 'active', severity: 'critical', description: 'Mimikatz signature in memory' },
  { id: 'SNORT-001', name: 'C2 Beacon Detection', source: 'snort', status: 'active', severity: 'high', description: 'Regular beaconing to external IP' },
  { id: 'SIGMA-003', name: 'Scheduled Task Persistence', source: 'sigma', status: 'disabled', severity: 'medium', description: 'New scheduled task creation' },
  { id: 'YARA-003', name: 'Webshell Detection', source: 'yara', status: 'error', severity: 'high', description: 'JSP/PHP webshell signatures' },
  { id: 'SIGMA-004', name: 'DNS Tunneling Pattern', source: 'sigma', status: 'active', severity: 'medium', description: 'High-entropy DNS queries' },
];

const sourceColors: Record<string, string> = {
  sigma: 'var(--accent)',
  yara: 'var(--high)',
  snort: 'var(--info)',
};

const statusConfig: Record<string, { color: string; icon: any }> = {
  active: { color: 'var(--low)', icon: CheckCircle },
  disabled: { color: 'var(--text-secondary)', icon: XCircle },
  error: { color: 'var(--critical)', icon: AlertTriangle },
};

const severityColors: Record<string, string> = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
};

export default function Rules() {
  const [rules] = useState<Rule[]>(defaultRules);
  const [editorContent, setEditorContent] = useState(sampleSigmaRule);
  const [compileResult, setCompileResult] = useState<{ success: boolean; message: string } | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [sourceFilter, setSourceFilter] = useState<string>('all');

  const handleCompile = () => {
    const hasTitle = editorContent.includes('title:');
    const hasDetection = editorContent.includes('detection:');
    const hasCondition = editorContent.includes('condition:');

    if (!hasTitle || !hasDetection || !hasCondition) {
      setCompileResult({
        success: false,
        message: 'Compilation failed: Missing required fields (title, detection, condition).',
      });
    } else {
      setCompileResult({
        success: true,
        message: `Rule compiled successfully. ${editorContent.split('\n').length} lines processed. Ready for deployment.`,
      });
    }
  };

  const filtered = rules.filter((r) => {
    if (sourceFilter !== 'all' && r.source !== sourceFilter) return false;
    if (searchTerm && !r.name.toLowerCase().includes(searchTerm.toLowerCase()) && !r.id.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Rules</h1>
        <div className="flex items-center gap-2">
          <span className="text-xs px-2 py-1 rounded-full" style={{ backgroundColor: 'rgba(99,102,241,0.15)', color: 'var(--accent)' }}>
            {rules.filter(r => r.status === 'active').length} active
          </span>
          <span className="text-xs px-2 py-1 rounded-full" style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: 'var(--critical)' }}>
            {rules.filter(r => r.status === 'error').length} errors
          </span>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          <input
            type="text"
            placeholder="Search rules..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg text-sm border outline-none focus:ring-1 focus:ring-indigo-500"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
          />
        </div>
        {['all', 'sigma', 'yara', 'snort'].map((src) => (
          <button
            key={src}
            onClick={() => setSourceFilter(src)}
            className={`px-3 py-2 rounded-lg text-xs font-medium transition-colors ${sourceFilter === src ? 'text-white' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'}`}
            style={sourceFilter === src ? { backgroundColor: 'rgba(99,102,241,0.2)', color: 'var(--accent)' } : {}}
          >
            {src.charAt(0).toUpperCase() + src.slice(1)}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <div className="px-4 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
            <span className="text-xs font-semibold">Rule Library</span>
            <button className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors">
              <Plus className="w-3 h-3" />
              New Rule
            </button>
          </div>
          <div className="max-h-[500px] overflow-y-auto">
            {filtered.map((rule) => {
              const StatusIcon = statusConfig[rule.status].icon;
              return (
                <div key={rule.id} className="px-4 py-3 border-b hover:bg-white/5 transition-colors cursor-pointer" style={{ borderColor: 'var(--border-color)' }}>
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <StatusIcon className="w-3.5 h-3.5" style={{ color: statusConfig[rule.status].color }} />
                      <span className="text-xs font-medium">{rule.name}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 mt-1.5">
                    <span className="text-[10px] font-mono" style={{ color: 'var(--text-secondary)' }}>{rule.id}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ backgroundColor: `${sourceColors[rule.source]}20`, color: sourceColors[rule.source] }}>
                      {rule.source.toUpperCase()}
                    </span>
                    <span className="text-[10px] font-medium" style={{ color: severityColors[rule.severity] }}>
                      {rule.severity}
                    </span>
                  </div>
                  <p className="text-[10px] mt-1" style={{ color: 'var(--text-secondary)' }}>{rule.description}</p>
                </div>
              );
            })}
          </div>
        </div>

        <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <div className="px-4 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
            <div className="flex items-center gap-2">
              <Code className="w-4 h-4 text-indigo-400" />
              <span className="text-xs font-semibold">Rule Editor</span>
            </div>
            <div className="flex items-center gap-1.5">
              <button className="p-1.5 rounded hover:bg-white/10 transition-colors" title="Copy">
                <Copy className="w-3.5 h-3.5 text-gray-400" />
              </button>
              <button className="p-1.5 rounded hover:bg-white/10 transition-colors" title="Clear">
                <Trash2 className="w-3.5 h-3.5 text-gray-400" />
              </button>
            </div>
          </div>
          <textarea
            value={editorContent}
            onChange={(e) => {
              setEditorContent(e.target.value);
              setCompileResult(null);
            }}
            className="w-full h-[320px] p-4 text-[11px] font-mono leading-relaxed border-none outline-none resize-none"
            style={{ backgroundColor: 'var(--bg-card)', color: 'var(--text-primary)' }}
            spellCheck={false}
          />
          <div className="px-4 py-3 border-t flex items-center justify-between" style={{ borderColor: 'var(--border-color)' }}>
            <div className="flex items-center gap-2">
              <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-green-500/20 text-green-400 hover:bg-green-500/30 transition-colors">
                <Save className="w-3.5 h-3.5" />
                Save
              </button>
              <button
                onClick={handleCompile}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500 text-white hover:bg-indigo-600 transition-colors"
              >
                <Play className="w-3.5 h-3.5" />
                Compile & Test
              </button>
            </div>
            {compileResult && (
              <div className={`flex items-center gap-2 text-xs ${compileResult.success ? 'text-green-400' : 'text-red-400'}`}>
                {compileResult.success ? <CheckCircle className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
                {compileResult.message}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
