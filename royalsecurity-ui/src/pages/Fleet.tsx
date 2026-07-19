import { useState, useEffect, useCallback } from 'react';
import {
  Server, RefreshCw, Cpu, Monitor, Wifi, WifiOff
} from 'lucide-react';
import { getFleetAgents, getFleetStats } from '../lib/tauri-bridge';

interface FleetAgent {
  id: string;
  hostname: string;
  os: string;
  status: string;
  last_seen: string;
  version: string;
  ip: string;
  [key: string]: unknown;
}

interface FleetStatsData {
  total_agents: number;
  online_agents: number;
  offline_agents: number;
  avg_uptime: string;
  [key: string]: unknown;
}

export default function Fleet() {
  const [agents, setAgents] = useState<FleetAgent[]>([]);
  const [stats, setStats] = useState<FleetStatsData | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const [agentsData, statsData] = await Promise.allSettled([
        getFleetAgents(),
        getFleetStats(),
      ]);
      if (agentsData.status === 'fulfilled' && Array.isArray(agentsData.value)) setAgents(agentsData.value as FleetAgent[]);
      if (statsData.status === 'fulfilled') setStats(statsData.value as FleetStatsData);
    } catch {
      // Use defaults
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-3">
          <Cpu className="w-5 h-5 animate-spin" style={{ color: 'var(--accent)' }} />
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Loading fleet...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>FLEET COMMAND</h1>
          <p className="text-[10px] uppercase mt-1" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Agent Management & Monitoring</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-medium transition-all"
          style={{ border: '1px solid var(--accent)', color: 'var(--accent)', backgroundColor: 'transparent' }}
          onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--accent-muted)'; }}
          onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent'; }}
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Total Agents', value: stats.total_agents ?? 0, icon: Server, color: 'var(--accent)' },
            { label: 'Online', value: stats.online_agents ?? 0, icon: Wifi, color: 'var(--low)' },
            { label: 'Offline', value: stats.offline_agents ?? 0, icon: WifiOff, color: 'var(--critical)' },
            { label: 'Avg Uptime', value: stats.avg_uptime ?? 'N/A', icon: Monitor, color: 'var(--accent)' },
          ].map((item) => (
            <div key={item.label} className="rounded-xl p-4 border transition-all hover:shadow-lg" style={{
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-color)',
              borderLeft: `4px solid ${item.color}`,
              boxShadow: '0 0 15px rgba(201,168,76,0.05)',
            }}
              onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--border-active)'; e.currentTarget.style.boxShadow = '0 0 20px rgba(201,168,76,0.1)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; e.currentTarget.style.boxShadow = '0 0 15px rgba(201,168,76,0.05)'; }}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-medium uppercase" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>{item.label}</span>
                <item.icon className="w-4 h-4" style={{ color: item.color }} />
              </div>
              <div className="text-2xl font-bold font-mono" style={{ color: 'var(--text-primary)' }}>{item.value}</div>
            </div>
          ))}
        </div>
      )}

      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-medium uppercase" style={{ color: 'var(--text-secondary)', letterSpacing: '0.1em' }}>Connected Agents</span>
          <span className="text-[10px] px-2 py-0.5 rounded-full" style={{ backgroundColor: 'var(--accent-muted)', color: 'var(--accent)' }}>
            {agents.length} agent{agents.length !== 1 ? 's' : ''}
          </span>
        </div>

        {agents.length === 0 ? (
          <div className="rounded-xl border p-12 text-center" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
            <Server className="w-8 h-8 mx-auto mb-3" style={{ color: 'var(--text-tertiary)' }} />
            <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>No agents connected</span>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {agents.map((agent) => {
              const isOnline = agent.status === 'online';
              return (
                <div key={agent.id} className="rounded-xl border p-4 transition-all hover:shadow-lg" style={{
                  backgroundColor: 'var(--bg-card)',
                  borderColor: 'var(--border-color)',
                  borderLeft: `4px solid ${isOnline ? 'var(--low)' : 'var(--critical)'}`,
                  boxShadow: '0 0 15px rgba(201,168,76,0.05)',
                }}
                  onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--border-active)'; e.currentTarget.style.boxShadow = '0 0 20px rgba(201,168,76,0.1)'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--border-color)'; e.currentTarget.style.boxShadow = '0 0 15px rgba(201,168,76,0.05)'; }}
                >
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{agent.hostname}</span>
                    <div className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full" style={{
                        backgroundColor: isOnline ? 'var(--low)' : 'var(--critical)',
                        animation: isOnline ? 'pulse 2s infinite' : 'none',
                        boxShadow: isOnline ? '0 0 6px var(--low)' : 'none',
                      }} />
                      <span className="text-[10px] font-medium uppercase" style={{ color: isOnline ? 'var(--low)' : 'var(--critical)' }}>
                        {agent.status}
                      </span>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>IP</span>
                      <span className="font-mono text-[11px]" style={{ color: 'var(--text-secondary)' }}>{agent.ip}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>OS</span>
                      <span className="text-[11px]" style={{ color: 'var(--text-secondary)' }}>{agent.os}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>Version</span>
                      <span className="font-mono text-[11px]" style={{ color: 'var(--text-secondary)' }}>{agent.version}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase" style={{ color: 'var(--text-tertiary)', letterSpacing: '0.1em' }}>Last Seen</span>
                      <span className="font-mono text-[10px]" style={{ color: 'var(--text-tertiary)' }}>{agent.last_seen}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
