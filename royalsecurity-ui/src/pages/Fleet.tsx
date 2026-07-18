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
          <Cpu className="w-5 h-5 text-indigo-400 animate-spin" />
          <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>Loading fleet...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Fleet Management</h1>
        <button onClick={load} className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 transition-colors">
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Total Agents', value: stats.total_agents ?? 0, icon: Server, color: 'var(--info)' },
            { label: 'Online', value: stats.online_agents ?? 0, icon: Wifi, color: 'var(--low)' },
            { label: 'Offline', value: stats.offline_agents ?? 0, icon: WifiOff, color: 'var(--critical)' },
            { label: 'Avg Uptime', value: stats.avg_uptime ?? 'N/A', icon: Monitor, color: 'var(--accent)' },
          ].map((item) => (
            <div key={item.label} className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-medium uppercase tracking-wide" style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                <item.icon className="w-4 h-4" style={{ color: item.color }} />
              </div>
              <div className="text-2xl font-bold">{item.value}</div>
            </div>
          ))}
        </div>
      )}

      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b" style={{ borderColor: 'var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Hostname</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>IP</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>OS</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Version</th>
                <th className="text-left py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Status</th>
                <th className="text-right py-3 px-4 font-medium" style={{ color: 'var(--text-secondary)' }}>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {agents.length === 0 ? (
                <tr><td colSpan={6} className="py-12 text-center" style={{ color: 'var(--text-secondary)' }}>
                  <Server className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  No agents connected
                </td></tr>
              ) : agents.map((agent) => {
                const isOnline = agent.status === 'online';
                return (
                  <tr key={agent.id} className="border-b hover:bg-white/5 transition-colors" style={{ borderColor: 'var(--border-color)' }}>
                    <td className="py-2.5 px-4 font-medium">{agent.hostname}</td>
                    <td className="py-2.5 px-4 font-mono text-[11px]" style={{ color: 'var(--text-secondary)' }}>{agent.ip}</td>
                    <td className="py-2.5 px-4" style={{ color: 'var(--text-secondary)' }}>{agent.os}</td>
                    <td className="py-2.5 px-4 font-mono text-[11px]" style={{ color: 'var(--text-secondary)' }}>{agent.version}</td>
                    <td className="py-2.5 px-4">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium" style={{
                        backgroundColor: isOnline ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
                        color: isOnline ? 'var(--low)' : 'var(--critical)',
                      }}>
                        <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: isOnline ? 'var(--low)' : 'var(--critical)' }} />
                        {agent.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-right" style={{ color: 'var(--text-secondary)' }}>{agent.last_seen}</td>
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
