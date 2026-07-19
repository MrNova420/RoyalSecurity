import { BrowserRouter, Routes, Route, NavLink, useLocation } from 'react-router-dom';
import {
  Shield, Activity, AlertTriangle, Network,
  FileSearch, Settings, BarChart3, Database,
  Scale, ChevronLeft, ChevronRight, Cpu,
  Microscope, Bug, ShieldAlert, Server, Download
} from 'lucide-react';
import { useState, useEffect, useRef } from 'react';
import Dashboard from './pages/Dashboard';
import Threats from './pages/Threats';
import Processes from './pages/Processes';
import NetworkPage from './pages/Network';
import Rules from './pages/Rules';
import Compliance from './pages/Compliance';
import AuditLog from './pages/AuditLog';
import SettingsPage from './pages/Settings';
import Forensics from './pages/Forensics';
import VulnScan from './pages/VulnScan';
import ActiveResponse from './pages/ActiveResponse';
import Fleet from './pages/Fleet';
import SiemExport from './pages/SiemExport';
import SetupWizard from './components/SetupWizard';
import NotificationToast from './components/NotificationToast';
import { useNotifications } from './hooks/useNotifications';
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts';
import { useEventStream } from './hooks/useEventStream';
import { getConfig, updateConfig } from './lib/tauri-bridge';

const navGroups = [
  {
    label: 'COMMAND',
    items: [
      { path: '/', label: 'Dashboard', icon: BarChart3 },
      { path: '/threats', label: 'Threats', icon: AlertTriangle },
      { path: '/processes', label: 'Processes', icon: Activity },
      { path: '/network', label: 'Network', icon: Network },
    ],
  },
  {
    label: 'INTELLIGENCE',
    items: [
      { path: '/rules', label: 'Rules', icon: FileSearch },
      { path: '/forensics', label: 'Forensics', icon: Microscope },
      { path: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
      { path: '/compliance', label: 'Compliance', icon: Scale },
    ],
  },
  {
    label: 'OPERATIONS',
    items: [
      { path: '/active-response', label: 'Active Response', icon: ShieldAlert },
      { path: '/fleet', label: 'Fleet', icon: Server },
      { path: '/siem-export', label: 'SIEM Export', icon: Download },
      { path: '/audit', label: 'Audit Log', icon: Database },
    ],
  },
  {
    label: 'SYSTEM',
    items: [
      { path: '/settings', label: 'Settings', icon: Settings },
    ],
  },
];

function Sidebar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  return (
    <div
      className={`drag-region h-screen ${collapsed ? 'w-16' : 'w-56'} transition-all duration-300 flex flex-col border-r shrink-0`}
      style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-color)' }}
    >
      {/* Logo */}
      <div className="flex items-center gap-2.5 px-4 h-14 border-b shrink-0" style={{ borderColor: 'var(--border-color)' }}>
        <Shield className="w-5 h-5 shrink-0" style={{ color: 'var(--accent)' }} />
        {!collapsed && (
          <div className="no-drag flex flex-col">
            <span className="text-xs font-bold" style={{ color: 'var(--text-primary)', letterSpacing: '0.15em' }}>
              ROYALSECURITY
            </span>
            <span className="text-[9px] font-medium" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.12em' }}>
              SENTINEL AGENT
            </span>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3">
        {navGroups.map((group, gi) => (
          <div key={group.label}>
            {gi > 0 && (
              <div className="mx-3 my-2" style={{ borderTop: '1px solid var(--border-color)' }} />
            )}
            {!collapsed && (
              <div
                className="px-4 pb-1 pt-1 font-medium"
                style={{ fontSize: '9px', letterSpacing: '0.2em', color: 'var(--text-tertiary)' }}
              >
                {group.label}
              </div>
            )}
            {group.items.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  `no-drag flex items-center gap-3 mx-2 py-2 transition-all duration-200 ${
                    collapsed ? 'px-3 justify-center' : 'px-3'
                  } ${
                    isActive ? '' : ''
                  }`
                }
                style={({ isActive }) => ({
                  color: isActive ? 'var(--accent)' : 'var(--text-secondary)',
                  borderLeft: isActive ? '2px solid var(--accent)' : '2px solid transparent',
                  backgroundColor: isActive ? 'var(--accent-muted)' : 'transparent',
                  boxShadow: isActive ? '0 0 12px var(--accent-muted)' : 'none',
                })}
              >
                {({ isActive }) => (
                  <>
                    <item.icon
                      className="w-4 h-4 shrink-0 transition-colors duration-200"
                      style={{ color: isActive ? 'var(--accent)' : 'var(--text-secondary)' }}
                    />
                    {!collapsed && (
                      <span
                        className="text-xs font-medium transition-colors duration-200"
                        style={{ letterSpacing: '0.02em', color: isActive ? 'var(--accent)' : 'var(--text-secondary)' }}
                      >
                        {item.label}
                      </span>
                    )}
                  </>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Collapse */}
      <button
        onClick={onToggle}
        className="no-drag flex items-center justify-center h-10 border-t transition-colors duration-200"
        style={{ borderColor: 'var(--border-color)', color: 'var(--text-tertiary)' }}
      >
        {collapsed ? (
          <ChevronRight className="w-4 h-4 transition-transform duration-200" />
        ) : (
          <ChevronLeft className="w-4 h-4 transition-transform duration-200" />
        )}
      </button>
    </div>
  );
}

function TitleBar() {
  return (
    <div
      className="drag-region h-9 flex items-center justify-between px-4 border-b shrink-0"
      style={{ backgroundColor: 'var(--bg-primary)', borderColor: 'var(--border-color)' }}
    >
      <div className="flex items-center gap-2 no-drag">
        <Shield className="w-3.5 h-3.5" style={{ color: 'var(--text-tertiary)' }} />
        <span className="text-[10px]" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.04em' }}>
          RoyalSecurity Agent v0.1.0
        </span>
      </div>
      <div className="flex items-center gap-2 no-drag">
        <div className="relative flex items-center gap-1.5">
          <span className="relative flex h-2 w-2">
            <span
              className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-75"
              style={{ backgroundColor: 'var(--status-ok)' }}
            />
            <span
              className="relative inline-flex h-2 w-2 rounded-full"
              style={{ backgroundColor: 'var(--status-ok)' }}
            />
          </span>
          <span className="text-[10px] font-medium" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.06em' }}>
            ALL SYSTEMS SECURE
          </span>
        </div>
      </div>
    </div>
  );
}

function AnimatedRoutes() {
  const location = useLocation();

  return (
    <main className="flex-1 overflow-y-auto p-6">
      <div className="animate-fade-in" key={location.pathname}>
        <Routes location={location}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/processes" element={<Processes />} />
          <Route path="/network" element={<NetworkPage />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/forensics" element={<Forensics />} />
          <Route path="/vulnerabilities" element={<VulnScan />} />
          <Route path="/active-response" element={<ActiveResponse />} />
          <Route path="/fleet" element={<Fleet />} />
          <Route path="/siem-export" element={<SiemExport />} />
          <Route path="/compliance" element={<Compliance />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </div>
    </main>
  );
}

function AppShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [showWizard, setShowWizard] = useState(true);
  const { notifications, addNotification, dismissNotification } = useNotifications();
  const { setRefreshCallback, setEscapeCallback } = useKeyboardShortcuts();
  const { events } = useEventStream();
  const prevEventCountRef = useRef(0);

  useEffect(() => {
    const checkFirstRun = async () => {
      try {
        const config = await getConfig();
        if (config && (config as any).first_run === false) {
          setShowWizard(false);
        }
      } catch {
        // Show wizard on error (first run assumption)
      }
    };
    checkFirstRun();
  }, []);

  useEffect(() => {
    setRefreshCallback(() => {
      window.dispatchEvent(new CustomEvent('royalsecurity:refresh'));
    });
    setEscapeCallback(() => {
      window.dispatchEvent(new CustomEvent('royalsecurity:escape'));
    });
    return () => {
      setRefreshCallback(null);
      setEscapeCallback(null);
    };
  }, [setRefreshCallback, setEscapeCallback]);

  useEffect(() => {
    if (events.length === 0 || events.length < prevEventCountRef.current) {
      prevEventCountRef.current = events.length;
      return;
    }
    const newEvents = events.slice(0, events.length - prevEventCountRef.current);
    prevEventCountRef.current = events.length;

    for (const evt of newEvents) {
      if (evt.severity === 'critical') {
        addNotification(`${evt.title} [CRITICAL] - ${evt.source}`, 'error');
      } else if (evt.severity === 'high') {
        addNotification(`${evt.title} - ${evt.source}`, 'warning');
      }
    }
  }, [events, addNotification]);

  const handleWizardComplete = async () => {
    setShowWizard(false);
    try {
      await updateConfig({ first_run: false } as any);
    } catch {
      // Best effort
    }
  };

  if (showWizard) {
    return <SetupWizard onComplete={handleWizardComplete} />;
  }

  return (
    <div className="flex h-screen overflow-hidden" style={{ backgroundColor: 'var(--bg-primary)' }}>
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} />
      <div className="flex-1 flex flex-col overflow-hidden min-w-0">
        <TitleBar />
        <AnimatedRoutes />
      </div>
      <NotificationToast notifications={notifications} onDismiss={dismissNotification} />
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  );
}
