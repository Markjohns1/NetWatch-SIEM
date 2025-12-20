import React, { useState, useEffect } from 'react';
import { Shield, LayoutDashboard, Database, AlertTriangle, Settings, Activity, Cpu, Globe, Users, Clock, ShieldAlert, ShieldCheck, MoreVertical } from 'lucide-react';
import { useDevices, useAlerts } from './hooks/useData';
import { DeviceList, AlertList } from './components/DataViews';
import { DeviceTopology } from './components/Topology';

const App = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const { data: devices, isLoading: devicesLoading } = useDevices();
  const { data: alerts, isLoading: alertsLoading } = useAlerts();

  const criticalAlerts = alerts?.filter(a => a.severity === 'critical' && !a.is_resolved);

  return (
    <div className="flex h-screen bg-background text-foreground overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className="w-64 border-r border-border bg-muted/30 backdrop-blur-xl flex flex-col z-20">
        <div className="p-6 flex items-center gap-3">
          <div className="p-2 bg-primary/20 rounded-lg shadow-[0_0_15px_rgba(0,242,255,0.1)]">
            <Shield className="text-primary w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold tracking-tighter">NETWATCH SIEM</h1>
        </div>

        <nav className="flex-1 px-4 space-y-2 mt-4">
          <NavItem
            icon={<LayoutDashboard size={20} />}
            label="Dashboard"
            active={activeTab === 'dashboard'}
            onClick={() => setActiveTab('dashboard')}
          />
          <NavItem
            icon={<Globe size={20} />}
            label="Device Map"
            active={activeTab === 'devices'}
            onClick={() => setActiveTab('devices')}
          />
          <NavItem
            icon={<AlertTriangle size={20} />}
            label="Alert Center"
            active={activeTab === 'alerts'}
            onClick={() => setActiveTab('alerts')}
            badge={criticalAlerts?.length > 0 ? criticalAlerts.length : null}
          />
          <NavItem
            icon={<Database size={20} />}
            label="Security Logs"
            active={activeTab === 'events'}
            onClick={() => setActiveTab('events')}
          />
          <div className="pt-4 pb-2 px-4">
            <span className="text-[10px] font-black uppercase text-foreground/30 tracking-[0.2em]">Configuration</span>
          </div>
          <NavItem
            icon={<Settings size={20} />}
            label="System Settings"
            active={activeTab === 'settings'}
            onClick={() => setActiveTab('settings')}
          />
        </nav>

        <div className="p-4 border-t border-border">
          <div className="flex items-center gap-3 p-3 rounded-xl bg-primary/5 border border-primary/10">
            <div className={`w-2 h-2 rounded-full ${devicesLoading ? 'bg-yellow-400' : 'bg-primary'} animate-pulse`} />
            <span className="text-[10px] font-black text-primary uppercase tracking-[0.2em]">{devicesLoading ? 'Scanning...' : 'System Active'}</span>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden relative">
        <div className="absolute inset-0 bg-neon-glow pointer-events-none opacity-30" />

        <header className="h-20 border-b border-border flex items-center justify-between px-8 bg-background/50 backdrop-blur-md z-10">
          <div className="flex items-center gap-4">
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <Activity className="text-primary w-4 h-4 animate-pulse" />
                <span className="text-sm font-bold uppercase tracking-widest text-primary">Live Monitor</span>
              </div>
              <span className="text-[10px] font-medium text-foreground/40 uppercase tracking-[0.15em]">Gateway: 192.168.1.1</span>
            </div>
          </div>
          <div className="flex items-center gap-8">
            <div className="flex flex-col items-end">
              <span className="text-[10px] text-foreground/40 uppercase font-black tracking-widest">Network Load</span>
              <span className="text-sm font-mono font-bold text-primary">0.86 MB/s</span>
            </div>
            <div className="h-10 w-[1px] bg-border" />
            <div className="flex items-center gap-3">
              <div className="text-right flex flex-col">
                <span className="text-xs font-bold">John Mark</span>
                <span className="text-[10px] text-primary/60 font-black uppercase">Administrator</span>
              </div>
              <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary group-hover:scale-110 transition-transform cursor-pointer">
                <Users size={20} />
              </div>
            </div>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-8 z-10 custom-scrollbar">
          {activeTab === 'dashboard' && <Dashboard devices={devices} alerts={alerts} loading={devicesLoading || alertsLoading} />}
          {activeTab === 'devices' && <div className="space-y-8"><h2 className="text-3xl font-black uppercase tracking-tighter">Network Map</h2><DeviceTopology devices={devices} /></div>}
          {activeTab === 'alerts' && <AlertList alerts={alerts} isLoading={alertsLoading} />}
          {(activeTab === 'events' || activeTab === 'settings') && (
            <div className="flex flex-col items-center justify-center h-full opacity-40">
              <Shield size={64} className="mb-4 text-primary animate-pulse" />
              <p className="text-xl font-bold tracking-widest uppercase">Under Maintenance</p>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

const NavItem = ({ icon, label, active, onClick, badge }) => (
  <button
    onClick={onClick}
    className={`w-full flex items-center justify-between px-4 py-3 rounded-xl transition-all duration-300 group ${active
      ? 'bg-primary/10 text-primary border border-primary/30 shadow-[0_0_20px_rgba(0,242,255,0.05)]'
      : 'text-foreground/50 hover:text-foreground hover:bg-white/5'
      }`}
  >
    <div className="flex items-center gap-3">
      <div className={`transition-transform duration-300 ${active ? 'scale-110' : 'group-hover:scale-110'}`}>
        {icon}
      </div>
      <span className="font-bold text-sm tracking-tight">{label}</span>
    </div>
    {badge && (
      <span className="px-1.5 py-0.5 rounded-md bg-accent text-[10px] font-black text-white">{badge}</span>
    )}
  </button>
);

const Dashboard = ({ devices, alerts, loading }) => {
  const recentAlerts = alerts?.slice(0, 8) || [];

  // Calculate some derived stats
  const activeAlerts = alerts?.filter(a => !a.is_resolved) || [];
  const criticalCount = activeAlerts.filter(a => a.severity === 'critical').length || 0;
  const highCount = activeAlerts.filter(a => a.severity === 'high').length || 0;
  const activeDeviceCount = devices?.length || 0;
  const untrustedCount = devices?.filter(d => !d.is_trusted).length || 0;

  // Derive a dynamic security score
  const securityScore = criticalCount > 0 ? 'CRITICAL' : highCount > 2 ? 'AT RISK' : 'STABLE';
  const scoreColor = criticalCount > 0 ? 'text-accent' : highCount > 2 ? 'text-orange-400' : 'text-green-500';

  return (
    <div className="space-y-10 max-w-7xl mx-auto">
      <div className="flex items-end justify-between">
        <div className="space-y-1">
          <h2 className="text-4xl font-black tracking-tighter uppercase">Command Center</h2>
          <p className="text-foreground/40 font-medium tracking-wide">High-precision security telemetry for {activeDeviceCount} network nodes.</p>
        </div>
        <div className="hidden lg:flex gap-4">
          <div className="px-4 py-2 rounded-xl bg-white/5 border border-border flex items-center gap-3 shadow-inner">
            <span className="text-[10px] font-black uppercase text-foreground/30">Detection Status</span>
            <div className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
              <span className="text-[10px] font-black uppercase text-green-500">Active</span>
            </div>
          </div>
        </div>
      </div>

      {/* Numerical Insights Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard title="Active Nodes" value={activeDeviceCount} icon={<Globe size={20} className="text-primary" />} trend="Network Coverage 100%" />
        <StatCard title="Critical threats" value={criticalCount} icon={<ShieldAlert size={20} className="text-accent" />} trend="Action Required" color="border-accent/40" />
        <StatCard title="Unknown Devices" value={untrustedCount} icon={<Activity size={20} className="text-yellow-400" />} trend="Identification Pending" />
        <StatCard title="Scanner Pulse" value="60s" icon={<Clock size={20} className="text-green-400" />} trend="Real-time Discovery On" />
      </div>

      {/* Secondary Metrics & Health */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="glass-card p-6 flex items-center justify-between border-l-4 border-l-primary/50 hover:bg-white/5 transition-all">
          <div>
            <p className="text-[10px] font-black uppercase text-foreground/30 mb-1">Total Signals Analysed</p>
            <p className="text-2xl font-bold font-mono tracking-tighter">14.2k</p>
          </div>
          <Activity className="text-primary/20 w-8 h-8" />
        </div>
        <div className="glass-card p-6 flex items-center justify-between border-l-4 border-l-secondary/50 hover:bg-white/5 transition-all">
          <div>
            <p className="text-[10px] font-black uppercase text-foreground/30 mb-1">High Severity Alerts</p>
            <p className="text-2xl font-bold font-mono tracking-tighter">{highCount}</p>
          </div>
          <AlertTriangle className="text-secondary/20 w-8 h-8" />
        </div>
        <div className="glass-card p-6 flex items-center justify-between border-l-4 border-l-green-500/50 hover:bg-white/5 transition-all">
          <div>
            <p className="text-[10px] font-black uppercase text-foreground/30 mb-1">Defense Posture</p>
            <p className={`text-2xl font-black font-mono tracking-tighter ${scoreColor}`}>{securityScore}</p>
          </div>
          <Shield className="text-green-500/20 w-8 h-8" />
        </div>
      </div>

      {/* Main Content: Expanded Live Log */}
      <div className="glass-card overflow-hidden border border-white/5 shadow-2xl">
        <div className="p-6 border-b border-white/5 flex items-center justify-between bg-white/2">
          <div>
            <h3 className="text-lg font-black uppercase tracking-[0.2em]">Live Security Feed</h3>
            <p className="text-[10px] text-foreground/30 font-bold uppercase tracking-widest mt-1">Real-time threat aggregation & heuristic alerts.</p>
          </div>
          <button
            onClick={() => setActiveTab('alerts')}
            className="px-4 py-2 rounded-lg bg-primary/10 border border-primary/20 text-primary text-[10px] font-black uppercase tracking-widest hover:bg-primary/20 transition-all shadow-lg"
          >
            Full Intelligence Log
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="border-b border-white/5 bg-white/3">
              <tr>
                <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Priority</th>
                <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Intelligence Description</th>
                <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Detection Vector</th>
                <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Time</th>
                <th className="px-6 py-4"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {recentAlerts.length > 0 ? (
                recentAlerts.map(alert => (
                  <tr key={alert.id} className="hover:bg-white/5 transition-all group">
                    <td className="px-6 py-4">
                      <span className={`text-[9px] font-black uppercase px-2 py-0.5 rounded border ${alert.severity === 'critical' ? 'bg-accent/10 text-accent border-accent/30' :
                          alert.severity === 'high' ? 'bg-orange-500/10 text-orange-400 border-orange-500/30' :
                            'bg-blue-500/10 text-blue-400 border-blue-500/30'
                        }`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <p className="text-sm font-bold tracking-tight text-foreground/90 group-hover:text-primary transition-colors">{alert.message}</p>
                    </td>
                    <td className="px-6 py-4">
                      <p className="text-xs font-mono text-foreground/30 group-hover:text-foreground/50">{alert.rule_id}</p>
                    </td>
                    <td className="px-6 py-4 text-xs font-mono text-foreground/30 italic">
                      {new Date(alert.timestamp).toLocaleTimeString([], { hour12: false })}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button className="p-2 rounded-lg hover:bg-white/5 text-foreground/20 hover:text-primary transition-all">
                        <MoreVertical size={16} />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="5" className="px-6 py-24 text-center">
                    <div className="flex flex-col items-center gap-4 opacity-20">
                      <Shield size={48} />
                      <p className="text-sm font-black uppercase tracking-widest">Awaiting Security Signals...</p>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const StatCard = ({ title, value, icon, trend, color }) => (
  <div className={`glass-card p-6 border-b-2 ${color || 'border-transparent'} hover:border-primary transition-all duration-300 group cursor-default shadow-[0_10px_30px_rgba(0,0,0,0.2)]`}>
    <div className="flex items-center justify-between mb-6">
      <div className="p-3 rounded-xl bg-white/5 border border-white/5 group-hover:bg-primary/10 group-hover:border-primary/20 transition-all duration-300">
        {icon}
      </div>
      <span className="text-[10px] uppercase font-black tracking-[0.2em] text-foreground/30">{title}</span>
    </div>
    <div className="space-y-1">
      <span className="text-4xl font-black tracking-tighter group-hover:text-primary transition-colors">{value}</span>
      <p className="text-[10px] text-foreground/40 font-bold uppercase tracking-widest">{trend}</p>
    </div>
  </div>
);

const AlertItem = ({ severity, message, time }) => {
  const themes = {
    critical: 'bg-accent border-accent/30 text-accent',
    high: 'bg-orange-500 border-orange-500/30 text-orange-400',
    medium: 'bg-yellow-500 border-yellow-500/30 text-yellow-400',
    low: 'bg-blue-500 border-blue-500/30 text-blue-400'
  };

  return (
    <div className="flex flex-col gap-2 p-4 rounded-xl bg-white/5 border border-white/5 hover:border-white/10 transition-all group">
      <div className="flex items-center justify-between">
        <span className={`text-[9px] font-black uppercase px-2 py-0.5 rounded border ${themes[severity]}`}>
          {severity}
        </span>
        <span className="text-[10px] text-foreground/30 font-bold group-hover:text-foreground/50 transition-colors">{time}</span>
      </div>
      <p className="text-sm font-bold tracking-tight line-clamp-2">{message}</p>
    </div>
  );
};

export default App;
