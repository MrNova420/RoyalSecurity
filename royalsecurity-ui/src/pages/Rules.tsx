import { useState, useEffect, useCallback } from 'react';
import {
  Play, Save, AlertTriangle, CheckCircle, XCircle,
  Code, Search, Trash2, Plus, Cpu
} from 'lucide-react';
import { addSigmaRule, addYaraRule, removeDetectionRule, getConfig } from '../lib/tauri-bridge';

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
      - '\\\\powershell.exe'
      - '\\\\pwsh.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
      - '-e '
  filter_legit:
    ParentImage|endswith:
      - '\\\\sccm.exe'
      - '\\\\configmgr.exe'
  condition: selection and not filter_legit
falsepositives:
  - Legitimate SCCM deployments
  - Automated deployment scripts
level: high
actions:
  - isolate_host
  - collect_forensics`;

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
  const [rules, setRules] = useState<Rule[]>([]);
  const [editorContent, setEditorContent] = useState(sampleSigmaRule);
  const [compileResult, setCompileResult] = useState<{ success: boolean; message: string } | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const showFeedback = (type: 'success' | 'error', message: string) => {
    setFeedback({ type, message });
    setTimeout(() => setFeedback(null), 5000);
  };

  const load = useCallback(async () => {
    try {
      const cfg = await getConfig() as any;
      if (cfg?.rules && Array.isArray(cfg.rules)) {
        setRules(cfg.rules);
      }
    } catch {
      // Use empty
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const isYara = editorContent.includes('rule ') && editorContent.includes('{') && editorContent.includes('strings:');

  const handleSave = async () => {
    setSaving(true);
    setCompileResult(null);
    try {
      let result;
      if (isYara) {
        result = await addYaraRule(editorContent);
      } else {
        result = await addSigmaRule(editorContent);
      }
      if (result.success) {
        setCompileResult({ success: true, message: result.message || `Rule saved as ${result.rule_id || 'new rule'}. Ready for deployment.` });
        showFeedback('success', result.message || 'Rule saved successfully');
        load();
      } else {
        setCompileResult({ success: false, message: result.message || 'Failed to save rule.' });
        showFeedback('error', result.message || 'Failed to save rule');
      }
    } catch (err: any) {
      setCompileResult({ success: false, message: err?.toString() || 'Failed to save rule.' });
      showFeedback('error', err?.toString() || 'Failed to save rule');
    } finally {
      setSaving(false);
    }
  };

  const handleCompile = () => {
    const hasTitle = editorContent.includes('title:');
    const hasDetection = editorContent.includes('detection:');
    const hasCondition = editorContent.includes('condition:');

    if (!hasTitle || !hasDetection || !hasCondition) {
      setCompileResult({
        success: false,
        message: 'Preview validation failed: Missing required fields (title, detection, condition). Full compilation happens when saving.',
      });
    } else {
      setCompileResult({
        success: true,
        message: `Preview validation passed. ${editorContent.split('\n').length} lines. Full compilation happens when saving.`,
      });
    }
  };

  const handleRemove = async (ruleId: string) => {
    try {
      const result = await removeDetectionRule(ruleId);
      showFeedback('success', result.message || `Removed rule ${ruleId}`);
      setRules(prev => prev.filter(r => r.id !== ruleId));
    } catch (err: any) {
      showFeedback('error', err?.toString() || `Failed to remove rule ${ruleId}`);
    }
  };

  const filtered = rules.filter((r) => {
    if (sourceFilter !== 'all' && r.source !== sourceFilter) return false;
    if (searchTerm && !r.name.toLowerCase().includes(searchTerm.toLowerCase()) && !r.id.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-3">
          <Cpu className="w-5 h-5 animate-spin" style={{ color: 'var(--accent)' }} />
          <span className="text-sm font-mono uppercase tracking-widest" style={{ color: 'var(--text-tertiary)' }}>Loading detection rules...</span>
        </div>
      </div>
    );
  }

  const sourceBadgeColors: Record<string, { bg: string; border: string; text: string }> = {
    sigma: { bg: 'rgba(59,130,246,0.12)', border: 'rgba(59,130,246,0.3)', text: '#3b82f6' },
    yara: { bg: 'rgba(220,38,38,0.12)', border: 'rgba(220,38,38,0.3)', text: '#dc2626' },
    snort: { bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.3)', text: '#f97316' },
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-1 h-8 rounded-full" style={{ background: 'linear-gradient(to bottom, var(--accent), transparent)' }} />
          <h1 className="text-xl font-bold uppercase tracking-widest" style={{ color: 'var(--text-primary)' }}>Detection Rules</h1>
        </div>
        <div className="flex items-center gap-3">
          {feedback && (
            <span className="flex items-center gap-1.5 text-[10px] font-mono px-3 py-1.5 rounded border" style={feedback.type === 'success' ? { backgroundColor: 'rgba(34,197,94,0.1)', color: 'var(--low)', borderColor: 'rgba(34,197,94,0.3)' } : { backgroundColor: 'rgba(220,38,38,0.1)', color: 'var(--critical)', borderColor: 'rgba(220,38,38,0.3)' }}>
              {feedback.type === 'success' ? <CheckCircle className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
              {feedback.message}
            </span>
          )}
          <span className="text-[10px] font-mono px-2.5 py-1 rounded" style={{ backgroundColor: 'rgba(212,175,55,0.1)', color: 'var(--accent)', border: '1px solid rgba(212,175,55,0.2)' }}>
            {rules.filter(r => r.status === 'active').length} active
          </span>
          <span className="text-[10px] font-mono px-2.5 py-1 rounded" style={{ backgroundColor: 'rgba(220,38,38,0.1)', color: 'var(--critical)', border: '1px solid rgba(220,38,38,0.2)' }}>
            {rules.filter(r => r.status === 'error').length} errors
          </span>
        </div>
      </div>

      <div className="rounded-lg p-4 border-l-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderLeftColor: 'var(--accent)' }}>
        <div className="flex items-center gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
            <input
              type="text"
              placeholder="Search rules..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-2 rounded text-sm font-mono border outline-none transition-all duration-200"
              style={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
              onFocus={(e) => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.boxShadow = '0 0 16px rgba(212,175,55,0.12)'; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; e.currentTarget.style.boxShadow = 'none'; }}
            />
          </div>
          <div className="flex items-center gap-1.5 p-1 rounded" style={{ backgroundColor: 'var(--bg-elevated)' }}>
            {['all', 'sigma', 'yara', 'snort'].map((src) => (
              <button
                key={src}
                onClick={() => setSourceFilter(src)}
                className="px-3 py-1.5 rounded text-[10px] font-semibold uppercase tracking-widest transition-all duration-200"
                style={sourceFilter === src ? { backgroundColor: 'rgba(212,175,55,0.15)', color: 'var(--accent)', border: '1px solid rgba(212,175,55,0.3)' } : { color: 'var(--text-tertiary)', border: '1px solid transparent' }}
              >
                {src}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-lg border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <div className="px-4 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--border-color)' }}>
            <span className="text-[10px] uppercase tracking-widest font-semibold" style={{ color: 'var(--text-tertiary)' }}>Rule Library</span>
            <button
              onClick={() => { setEditorContent(isYara ? 'rule NewYaraRule {\n  strings:\n    $s1 = "malware_string"\n  condition:\n    $s1\n}' : sampleSigmaRule); setCompileResult(null); }}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] font-semibold uppercase tracking-widest transition-all duration-200"
              style={{ border: '1px solid var(--accent)', color: 'var(--accent)', backgroundColor: 'transparent' }}
              onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(212,175,55,0.1)'; e.currentTarget.style.boxShadow = '0 0 20px rgba(212,175,55,0.15)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.boxShadow = 'none'; }}
            >
              <Plus className="w-3 h-3" />
              New Rule
            </button>
          </div>
          <div className="max-h-[500px] overflow-y-auto">
            {filtered.length === 0 ? (
              <div className="py-10 text-center text-[10px] uppercase tracking-widest" style={{ color: 'var(--text-tertiary)' }}>No rules found</div>
            ) : filtered.map((rule) => {
              const StatusIcon = statusConfig[rule.status].icon;
              const badge = sourceBadgeColors[rule.source] || sourceBadgeColors.sigma;
              return (
                <div key={rule.id} className="px-4 py-3 border-b transition-colors cursor-pointer group" style={{ borderColor: 'var(--border-color)' }} onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--bg-elevated)'; }} onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}>
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center gap-2.5">
                      <StatusIcon className="w-3.5 h-3.5" style={{ color: statusConfig[rule.status].color }} />
                      <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>{rule.name}</span>
                    </div>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleRemove(rule.id); }}
                      className="opacity-0 group-hover:opacity-100 p-1 rounded transition-all duration-200"
                      style={{ color: 'var(--critical)' }}
                      onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(220,38,38,0.15)'; }}
                      onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
                      title="Remove rule"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                  <div className="flex items-center gap-2.5 mt-1.5 flex-wrap">
                    <span className="text-[10px] font-mono" style={{ color: 'var(--text-tertiary)' }}>{rule.id}</span>
                    <span className="text-[10px] font-mono font-semibold uppercase px-1.5 py-0.5 rounded" style={{ backgroundColor: badge.bg, color: badge.text, border: `1px solid ${badge.border}` }}>
                      {rule.source}
                    </span>
                    <span className="text-[10px] font-mono font-semibold uppercase px-1.5 py-0.5 rounded" style={{ backgroundColor: `${severityColors[rule.severity]}18`, color: severityColors[rule.severity], border: `1px solid ${severityColors[rule.severity]}30` }}>
                      {rule.severity}
                    </span>
                  </div>
                  <p className="text-[10px] mt-1.5 leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{rule.description}</p>
                </div>
              );
            })}
          </div>
        </div>

        <div className="rounded-lg border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          <div className="px-4 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--border-color)' }}>
            <div className="flex items-center gap-2.5">
              <Code className="w-4 h-4" style={{ color: 'var(--accent)' }} />
              <span className="text-[10px] uppercase tracking-widest font-semibold" style={{ color: 'var(--text-tertiary)' }}>Rule Editor</span>
              <span className="text-[10px] font-mono font-semibold uppercase px-1.5 py-0.5 rounded" style={isYara ? { backgroundColor: 'rgba(220,38,38,0.12)', color: '#dc2626', border: '1px solid rgba(220,38,38,0.3)' } : { backgroundColor: 'rgba(59,130,246,0.12)', color: '#3b82f6', border: '1px solid rgba(59,130,246,0.3)' }}>
                {isYara ? 'YARA' : 'Sigma'}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => navigator.clipboard.writeText(editorContent)}
                className="px-2 py-1 rounded text-[10px] font-mono transition-all duration-200"
                style={{ color: 'var(--text-tertiary)' }}
                onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--bg-elevated)'; e.currentTarget.style.color = 'var(--accent)'; }}
                onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.color = 'var(--text-tertiary)'; }}
                title="Copy"
              >
                Copy
              </button>
              <button onClick={() => { setEditorContent(''); setCompileResult(null); }} className="p-1.5 rounded transition-all duration-200" style={{ color: 'var(--text-tertiary)' }} onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(220,38,38,0.15)'; e.currentTarget.style.color = 'var(--critical)'; }} onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.color = 'var(--text-tertiary)'; }} title="Clear">
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
          <div className="relative">
            <div className="absolute top-0 left-0 w-8 h-full pointer-events-none" style={{ background: 'linear-gradient(to right, rgba(212,175,55,0.03), transparent)' }} />
            <textarea
              value={editorContent}
              onChange={(e) => { setEditorContent(e.target.value); setCompileResult(null); }}
              className="w-full h-[320px] p-4 text-[11px] font-mono leading-relaxed border-none outline-none resize-none"
              style={{ backgroundColor: 'var(--bg-elevated)', color: 'var(--text-primary)', caretColor: 'var(--accent)' }}
              spellCheck={false}
            />
          </div>
          <div className="px-4 py-3 border-t flex items-center justify-between" style={{ borderColor: 'var(--border-color)' }}>
            <div className="flex items-center gap-2">
              <button
                onClick={handleCompile}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-semibold uppercase tracking-widest transition-all duration-200"
                style={{ border: '1px solid var(--accent)', color: 'var(--accent)', backgroundColor: 'transparent' }}
                onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(212,175,55,0.15)'; e.currentTarget.style.boxShadow = '0 0 20px rgba(212,175,55,0.15)'; }}
                onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.boxShadow = 'none'; }}
              >
                <Play className="w-3.5 h-3.5" />
                Compile
              </button>
              <button
                onClick={handleCompile}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-semibold uppercase tracking-widest transition-all duration-200"
                style={{ border: '1px solid #8b5cf6', color: '#8b5cf6', backgroundColor: 'transparent' }}
                onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(139,92,246,0.12)'; }}
                onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
              >
                Test
              </button>
              <button
                onClick={handleSave}
                disabled={saving || !editorContent.trim()}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-semibold uppercase tracking-widest transition-all duration-200 disabled:opacity-40"
                style={{ border: '1px solid #22c55e', color: '#22c55e', backgroundColor: 'transparent' }}
                onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'rgba(34,197,94,0.12)'; }}
                onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
              >
                <Save className="w-3.5 h-3.5" />
                {saving ? 'Saving...' : 'Save'}
              </button>
            </div>
            {compileResult && (
              <div className="flex items-center gap-2 text-[10px] font-mono" style={{ color: compileResult.success ? 'var(--low)' : 'var(--critical)' }}>
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
