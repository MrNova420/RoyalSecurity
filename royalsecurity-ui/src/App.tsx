import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import {
  Shield, Activity, AlertTriangle, Network,
  FileSearch, Settings, BarChart3, Database,
  Scale, ChevronLeft, ChevronRight, Cpu
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
import SetupWizard from './components/SetupWizard';
import NotificationToast from './components/NotificationToast';
import { useNotifications } from './hooks/useNotifications';
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts';
import { useEventStream } from './hooks/useEventStream';
import { getConfig, updateConfig } from './lib/tauri-bridge';

const navItems = [
  { path: '/', label: 'Dashboard', icon: BarChart3 },
  { path: '/threats', label: 'Threats', icon: AlertTriangle },
  { path: '/processes', label: 'Processes', icon: Activity },
  { path: '/network', label: 'Network', icon: Network },
  { path: '/rules', label: 'Rules', icon: FileSearch },
  { path: '/compliance', label: 'Compliance', icon: Scale },
  { path: '/audit', label: 'Audit Log', icon: Database },
  { path: '/settings', label: 'Settings', icon: Settings },
];

function Sidebar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  return (
    <div className={`h-screen ${collapsed ? 'w-16' : 'w-56'} transition-all duration-300 flex flex-col border-r`} style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-color)' }}>
      <div className="drag-region flex items-center gap-2 p-4 h-14 border-b" style={{ borderColor: 'var(--border-color)' }}>
        <Shield className="w-6 h-6 text-indigo-500 shrink-0" />
        {!collapsed && <span className="font-bold text-sm no-drag">RoyalSecurity</span>}
      </div>
      <nav className="flex-1 py-2 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 mx-2 rounded-lg text-sm transition-colors ${
                isActive ? 'text-white' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
              }`
            }
            style={({ isActive }) => isActive ? { backgroundColor: 'rgba(99,102,241,0.2)' } : {}}
          >
            <item.icon className="w-5 h-5 shrink-0" />
            {!collapsed && <span>{item.label}</span>}
          </NavLink>
        ))}
      </nav>
      <button onClick={onToggle} className="no-drag p-3 border-t hover:bg-white/5 transition-colors" style={{ borderColor: 'var(--border-color)' }}>
        {collapsed ? <ChevronRight className="w-4 h-4 mx-auto text-gray-400" /> : <ChevronLeft className="w-4 h-4 text-gray-400" />}
      </button>
    </div>
  );
}

function TitleBar() {
  return (
    <div className="drag-region h-10 flex items-center justify-between px-4 border-b" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-color)' }}>
      <div className="flex items-center gap-2 no-drag">
        <Cpu className="w-4 h-4 text-indigo-400" />
        <span className="text-xs text-gray-400">RoyalSecurity Agent v0.1.0</span>
      </div>
      <div className="flex items-center gap-1 no-drag">
        <div className="w-3 h-3 rounded-full bg-green-500" />
        <span className="text-xs text-gray-400 ml-1">Protected</span>
      </div>
    </div>
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
      <div className="flex-1 flex flex-col overflow-hidden">
        <TitleBar />
        <main className="flex-1 overflow-y-auto p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/threats" element={<Threats />} />
            <Route path="/processes" element={<Processes />} />
            <Route path="/network" element={<NetworkPage />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/audit" element={<AuditLog />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </main>
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
