import { useState, useEffect, useCallback } from 'react';
import {
  Shield, ChevronRight, ChevronLeft, CheckCircle, AlertCircle,
  Search, Server, Activity, Network, FileSearch, Database,
  Cpu, Lock, Eye, Radio, Globe, Settings, Zap
} from 'lucide-react';
import { getSystemInfo, getConfig, updateConfig, getTpmStatus, getPplStatus } from '../lib/tauri-bridge';
import type { SystemInfo, Config } from '../lib/tauri-bridge';

interface Step {
  id: string;
  title: string;
  icon: any;
}

const steps: Step[] = [
  { id: 'welcome', title: 'Welcome', icon: Shield },
  { id: 'system', title: 'System Scan', icon: Search },
  { id: 'modules', title: 'Module Selection', icon: Server },
  { id: 'schedule', title: 'Scan Schedule', icon: Activity },
  { id: 'threat-intel', title: 'Threat Intel', icon: Globe },
  { id: 'finish', title: 'Finish', icon: CheckCircle },
];

interface Module {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  icon: any;
}

const defaultModules: Module[] = [
  { id: 'edr', name: 'EDR Engine', description: 'Endpoint Detection and Response', enabled: true, icon: Shield },
  { id: 'ransomware', name: 'Ransomware Protection', description: 'Real-time ransomware detection and prevention', enabled: true, icon: Lock },
  { id: 'network', name: 'Network Monitor', description: 'Network traffic analysis and C2 detection', enabled: true, icon: Network },
  { id: 'threat-intel', name: 'Threat Intelligence', description: 'Automated threat intel feed processing', enabled: true, icon: Globe },
  { id: 'firewall', name: 'Firewall', description: 'Application and network firewall controls', enabled: true, icon: Activity },
  { id: 'dlp', name: 'DLP Monitor', description: 'Data Loss Prevention monitoring', enabled: true, icon: Eye },
  { id: 'privacy', name: 'Privacy Guard', description: 'Anti-fingerprint and tracker blocking', enabled: true, icon: Lock },
];

const threatFeeds = [
  { id: 'virustotal', name: 'VirusTotal', description: 'Cloud-based malware scanning' },
  { id: 'abusech', name: 'Abuse.ch', description: 'Malware and botnet tracking' },
  { id: 'cisa', name: 'CISA KEV', description: 'Known Exploited Vulnerabilities' },
  { id: 'otx', name: 'AlienVault OTX', description: 'Open Threat Exchange' },
  { id: 'misp', name: 'MISP', description: 'Threat Intelligence Sharing Platform' },
];

export interface SetupWizardProps {
  onComplete: () => void;
}

export default function SetupWizard({ onComplete }: SetupWizardProps) {
  const [currentStep, setCurrentStep] = useState(0);
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [tpmAvailable, setTpmAvailable] = useState(false);
  const [pplEnabled, setPplEnabled] = useState(false);
  const [modules, setModules] = useState<Module[]>(defaultModules);
  const [quickScanDaily, setQuickScanDaily] = useState(true);
  const [fullScanWeekly, setFullScanWeekly] = useState(true);
  const [feeds, setFeeds] = useState<Record<string, boolean>>({
    virustotal: true, abusech: true, cisa: true, otx: true, misp: true,
  });
  const [scanning, setScanning] = useState(true);

  useEffect(() => {
    const fetchSystemInfo = async () => {
      try {
        const [info, tpmResult, pplResult] = await Promise.allSettled([
          getSystemInfo(),
          getTpmStatus(),
          getPplStatus(),
        ]);
        if (info.status === 'fulfilled') {
          setSystemInfo(info.value);
        } else {
          setSystemInfo({ hostname: 'Unknown', os: 'Windows', arch: 'x86_64', version: 'N/A', agent_name: 'RoyalSecurity' });
        }
        setTpmAvailable(tpmResult.status === 'fulfilled' ? tpmResult.value.available : false);
        setPplEnabled(pplResult.status === 'fulfilled' ? pplResult.value.enabled : false);
      } catch {
        setSystemInfo({ hostname: 'Unknown', os: 'Windows', arch: 'x86_64', version: 'N/A', agent_name: 'RoyalSecurity' });
      } finally {
        setScanning(false);
      }
    };
    fetchSystemInfo();
  }, []);

  const toggleModule = (id: string) => {
    setModules(prev => prev.map(m => m.id === id ? { ...m, enabled: !m.enabled } : m));
  };

  const toggleFeed = (id: string) => {
    setFeeds(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleFinish = async () => {
    try {
      const config: Partial<Config> & Record<string, unknown> = {
        first_run: false,
        modules: modules.map(m => ({ id: m.id, enabled: m.enabled })),
        scan_schedule: { quick_daily: quickScanDaily, full_weekly: fullScanWeekly },
        threat_intel_feeds: Object.entries(feeds).filter(([, v]) => v).map(([k]) => k),
      };
      await updateConfig(config);
    } catch {
      // Best effort
    }
    onComplete();
  };

  const renderProgressBar = () => (
    <div className="flex items-center gap-2 mb-8">
      {steps.map((step, i) => (
        <div key={step.id} className="flex items-center">
          <div
            className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium transition-all duration-300 ${
              i < currentStep
                ? 'bg-green-500/20 text-green-400'
                : i === currentStep
                ? 'bg-indigo-500/20 text-indigo-400 ring-2 ring-indigo-500/50'
                : 'bg-white/5 text-gray-500'
            }`}
          >
            {i < currentStep ? <CheckCircle className="w-4 h-4" /> : i + 1}
          </div>
          {i < steps.length - 1 && (
            <div className={`w-8 h-0.5 mx-1 transition-colors duration-300 ${i < currentStep ? 'bg-green-500/40' : 'bg-white/10'}`} />
          )}
        </div>
      ))}
    </div>
  );

  const renderWelcome = () => (
    <div className="text-center py-8">
      <div className="w-20 h-20 rounded-2xl bg-indigo-500/20 flex items-center justify-center mx-auto mb-6">
        <Shield className="w-10 h-10 text-indigo-400" />
      </div>
      <h1 className="text-3xl font-bold text-white mb-3">Welcome to RoyalSecurity</h1>
      <p className="text-gray-400 max-w-md mx-auto mb-8">
        Advanced endpoint protection platform. Let's configure your system for optimal security in just a few steps.
      </p>
      <button
        onClick={() => setCurrentStep(1)}
        className="px-6 py-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium transition-colors flex items-center gap-2 mx-auto"
      >
        Get Started <ChevronRight className="w-4 h-4" />
      </button>
    </div>
  );

  const renderSystemScan = () => (
    <div>
      <h2 className="text-xl font-semibold text-white mb-2">System Information</h2>
      <p className="text-gray-400 text-sm mb-6">Detecting your system configuration...</p>
      <div className="space-y-3">
        <InfoRow icon={Server} label="Hostname" value={systemInfo?.hostname || '...'} done={!scanning} />
        <InfoRow icon={Cpu} label="Operating System" value={systemInfo?.os || '...'} done={!scanning} />
        <InfoRow icon={Cpu} label="Architecture" value={systemInfo?.arch || '...'} done={!scanning} />
        <InfoRow icon={Lock} label="TPM Status" value={tpmAvailable ? 'Available' : 'Not Detected'} done={!scanning} ok={tpmAvailable} />
        <InfoRow icon={Shield} label="PPL Support" value={pplEnabled ? 'Enabled' : 'Disabled'} done={!scanning} ok={pplEnabled} />
      </div>
    </div>
  );

  const renderModules = () => (
    <div>
      <h2 className="text-xl font-semibold text-white mb-2">Defense Modules</h2>
      <p className="text-gray-400 text-sm mb-6">Select which protection modules to enable.</p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {modules.map(m => (
          <button
            key={m.id}
            onClick={() => toggleModule(m.id)}
            className={`p-4 rounded-lg border text-left transition-all duration-200 ${
              m.enabled
                ? 'border-indigo-500/50 bg-indigo-500/10'
                : 'border-white/10 bg-white/5 hover:bg-white/10'
            }`}
          >
            <div className="flex items-center gap-3 mb-1">
              <m.icon className={`w-4 h-4 ${m.enabled ? 'text-indigo-400' : 'text-gray-500'}`} />
              <span className="text-sm font-medium text-white">{m.name}</span>
              <div className={`ml-auto w-9 h-5 rounded-full transition-colors ${m.enabled ? 'bg-indigo-600' : 'bg-gray-700'}`}>
                <div className={`w-4 h-4 rounded-full bg-white shadow transition-transform mt-0.5 ${m.enabled ? 'translate-x-4.5 ml-0.5' : 'translate-x-0.5'}`} />
              </div>
            </div>
            <p className="text-xs text-gray-400 ml-7">{m.description}</p>
          </button>
        ))}
      </div>
    </div>
  );

  const renderSchedule = () => (
    <div>
      <h2 className="text-xl font-semibold text-white mb-2">Scan Schedule</h2>
      <p className="text-gray-400 text-sm mb-6">Configure automatic scanning intervals.</p>
      <div className="space-y-4">
        <div className="p-4 rounded-lg border border-white/10 bg-white/5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Zap className="w-4 h-4 text-yellow-400" />
              <div>
                <p className="text-sm font-medium text-white">Real-time Protection</p>
                <p className="text-xs text-gray-400">Always active - monitors system continuously</p>
              </div>
            </div>
            <span className="text-xs text-green-400 font-medium px-2 py-1 rounded bg-green-500/10">Always On</span>
          </div>
        </div>
        <ScheduleToggle
          label="Quick Scan"
          description="Fast scan of critical system areas"
          schedule="Daily at 2:00 AM"
          enabled={quickScanDaily}
          onToggle={() => setQuickScanDaily(!quickScanDaily)}
        />
        <ScheduleToggle
          label="Full System Scan"
          description="Comprehensive scan of all files and processes"
          schedule="Weekly on Sunday at 3:00 AM"
          enabled={fullScanWeekly}
          onToggle={() => setFullScanWeekly(!fullScanWeekly)}
        />
      </div>
    </div>
  );

  const renderThreatIntel = () => (
    <div>
      <h2 className="text-xl font-semibold text-white mb-2">Threat Intelligence Feeds</h2>
      <p className="text-gray-400 text-sm mb-6">Select which intel sources to subscribe to.</p>
      <div className="space-y-3">
        {threatFeeds.map(feed => (
          <button
            key={feed.id}
            onClick={() => toggleFeed(feed.id)}
            className={`w-full p-4 rounded-lg border text-left transition-all duration-200 flex items-center gap-3 ${
              feeds[feed.id]
                ? 'border-indigo-500/50 bg-indigo-500/10'
                : 'border-white/10 bg-white/5 hover:bg-white/10'
            }`}
          >
            <Globe className={`w-4 h-4 ${feeds[feed.id] ? 'text-indigo-400' : 'text-gray-500'}`} />
            <div className="flex-1">
              <p className="text-sm font-medium text-white">{feed.name}</p>
              <p className="text-xs text-gray-400">{feed.description}</p>
            </div>
            <div className={`w-9 h-5 rounded-full transition-colors ${feeds[feed.id] ? 'bg-indigo-600' : 'bg-gray-700'}`}>
              <div className={`w-4 h-4 rounded-full bg-white shadow transition-transform mt-0.5 ${feeds[feed.id] ? 'translate-x-4.5 ml-0.5' : 'translate-x-0.5'}`} />
            </div>
          </button>
        ))}
      </div>
    </div>
  );

  const renderFinish = () => {
    const enabledCount = modules.filter(m => m.enabled).length;
    const feedCount = Object.values(feeds).filter(Boolean).length;
    return (
      <div className="text-center py-8">
        <div className="w-20 h-20 rounded-2xl bg-green-500/20 flex items-center justify-center mx-auto mb-6">
          <CheckCircle className="w-10 h-10 text-green-400" />
        </div>
        <h2 className="text-2xl font-bold text-white mb-3">Configuration Complete</h2>
        <p className="text-gray-400 max-w-md mx-auto mb-8">
          Your system is configured and ready. RoyalSecurity will begin protecting your endpoint immediately.
        </p>
        <div className="bg-white/5 rounded-lg border border-white/10 p-4 max-w-sm mx-auto mb-8 text-left space-y-2">
          <SummaryRow label="Modules Enabled" value={`${enabledCount}/${modules.length}`} />
          <SummaryRow label="Threat Feeds" value={`${feedCount} active`} />
          <SummaryRow label="Quick Scans" value={quickScanDaily ? 'Daily' : 'Disabled'} />
          <SummaryRow label="Full Scans" value={fullScanWeekly ? 'Weekly' : 'Disabled'} />
          <SummaryRow label="System" value={systemInfo?.hostname || 'Detected'} />
        </div>
        <button
          onClick={handleFinish}
          className="px-6 py-3 bg-green-600 hover:bg-green-500 text-white rounded-lg font-medium transition-colors flex items-center gap-2 mx-auto"
        >
          <Shield className="w-4 h-4" /> Start Protection
        </button>
      </div>
    );
  };

  const renderStep = () => {
    switch (currentStep) {
      case 0: return renderWelcome();
      case 1: return renderSystemScan();
      case 2: return renderModules();
      case 3: return renderSchedule();
      case 4: return renderThreatIntel();
      case 5: return renderFinish();
      default: return null;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ backgroundColor: 'var(--bg-primary)' }}>
      <div className="w-full max-w-2xl mx-4" style={{ animation: 'fadeIn 0.3s ease-out' }}>
        <div className="rounded-xl border p-8" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
          {renderProgressBar()}
          <div style={{ animation: 'slideIn 0.3s ease-out' }} key={currentStep}>
            {renderStep()}
          </div>
          {currentStep > 0 && currentStep < steps.length - 1 && (
            <div className="flex justify-between mt-8 pt-4 border-t" style={{ borderColor: 'var(--border-color)' }}>
              <button
                onClick={() => setCurrentStep(s => s - 1)}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors flex items-center gap-2"
              >
                <ChevronLeft className="w-4 h-4" /> Back
              </button>
              <button
                onClick={() => setCurrentStep(s => s + 1)}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors flex items-center gap-2"
              >
                Next <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </div>
      <style>{`
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slideIn { from { opacity: 0; transform: translateX(20px); } to { opacity: 1; transform: translateX(0); } }
      `}</style>
    </div>
  );
}

function InfoRow({ icon: Icon, label, value, done, ok }: { icon: any; label: string; value: string; done: boolean; ok?: boolean }) {
  return (
    <div className="flex items-center gap-3 p-3 rounded-lg bg-white/5 border border-white/10">
      <Icon className="w-4 h-4 text-gray-400" />
      <span className="text-sm text-gray-300 flex-1">{label}</span>
      {done ? (
        <div className="flex items-center gap-2">
          <span className="text-sm text-white">{value}</span>
          {ok !== undefined && (
            ok ? <CheckCircle className="w-4 h-4 text-green-400" /> : <AlertCircle className="w-4 h-4 text-yellow-400" />
          )}
        </div>
      ) : (
        <div className="w-4 h-4 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
      )}
    </div>
  );
}

function ScheduleToggle({ label, description, schedule, enabled, onToggle }: {
  label: string; description: string; schedule: string; enabled: boolean; onToggle: () => void;
}) {
  return (
    <button
      onClick={onToggle}
      className={`w-full p-4 rounded-lg border text-left transition-all duration-200 flex items-center gap-3 ${
        enabled ? 'border-indigo-500/50 bg-indigo-500/10' : 'border-white/10 bg-white/5 hover:bg-white/10'
      }`}
    >
      <Activity className={`w-4 h-4 ${enabled ? 'text-indigo-400' : 'text-gray-500'}`} />
      <div className="flex-1">
        <p className="text-sm font-medium text-white">{label}</p>
        <p className="text-xs text-gray-400">{description}</p>
        <p className="text-xs text-indigo-400 mt-1">{schedule}</p>
      </div>
      <div className={`w-9 h-5 rounded-full transition-colors ${enabled ? 'bg-indigo-600' : 'bg-gray-700'}`}>
        <div className={`w-4 h-4 rounded-full bg-white shadow transition-transform mt-0.5 ${enabled ? 'translate-x-4.5 ml-0.5' : 'translate-x-0.5'}`} />
      </div>
    </button>
  );
}

function SummaryRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between text-sm">
      <span className="text-gray-400">{label}</span>
      <span className="text-white">{value}</span>
    </div>
  );
}
