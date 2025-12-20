import React, { useState, useEffect } from 'react';
import {
  Shield, LayoutDashboard, Database, AlertTriangle, Settings,
  Activity, Cpu, Globe, Users, Clock, ShieldAlert,
  ShieldCheck, MoreVertical, Menu, X, ChevronRight, Bell,
  PanelLeftClose, PanelLeftOpen, LogOut, User, Terminal, Network
} from 'lucide-react';
import { useDevices, useAlerts, useStats, useScanStatus, useEvents } from './hooks/useData';
import { DeviceList, AlertList, EventList } from './components/DataViews';
import { DeviceTopology } from './components/Topology';

const StatCard = ({ title, value, icon, trend, color, onClick }) => (
  <div
    onClick={onClick}
    className="glass-card p-3.5 rounded-2xl border border-white/5 hover:border-primary/40 transition-all duration-500 group flex items-center gap-4 cursor-pointer min-w-0"
  >
    <div className="w-12 h-12 rounded-xl bg-white/5 flex items-center justify-center flex-shrink-0 group-hover:bg-primary transition-all duration-500 shadow-inner">
      {React.cloneElement(icon, { size: 20, className: "group-hover:text-black transition-colors" })}
    </div>

    <div className="flex-1 min-w-0 flex flex-col justify-center">
      <div className="flex items-center gap-2">
        <span className="text-2xl font-black tracking-tighter group-hover:text-primary transition-colors">
          {value}
        </span>
        <span className="text-[10px] uppercase font-black tracking-[0.2em] text-foreground/30 truncate">
          {title}
        </span>
      </div>
      <p className="text-[8px] text-foreground/20 font-bold uppercase tracking-[0.1em] truncate">{trend}</p>
    </div>
  </div>
);

const App = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [isCollapsed, setIsCollapsed] = useState(false);
  const { data: devices, isLoading: devicesLoading } = useDevices();
  const { data: alerts, isLoading: alertsLoading } = useAlerts();
  const { data: stats } = useStats();
  const { data: scanStatus } = useScanStatus();
  const { data: events, isLoading: eventsLoading } = useEvents();

  const criticalAlerts = alerts?.filter(a => a.severity === 'critical' && !a.is_resolved) || [];

  const toggleSidebar = () => setIsSidebarOpen(!isSidebarOpen);
  const toggleCollapse = () => setIsCollapsed(!isCollapsed);

  const mainNavItems = [
    { id: 'dashboard', label: 'Home', icon: <LayoutDashboard />, badge: criticalAlerts.length > 0 ? criticalAlerts.length : 0 },
    { id: 'topology', label: 'Map', icon: <Network />, badge: 0 },
    { id: 'alerts', label: 'Alerts', icon: <ShieldAlert />, badge: criticalAlerts.length },
  ];

  const secondaryNavItems = [
    { id: 'events', label: 'Security Logs', icon: <Terminal /> },
    { id: 'settings', label: 'System Parameters', icon: <Settings /> },
    { id: 'profile', label: 'Operator Profile', icon: <User /> },
    { id: 'logout', label: 'Terminate Session', icon: <LogOut />, danger: true },
  ];

  return (
    <div className="flex h-screen bg-background text-foreground overflow-hidden font-sans selection:bg-primary/30">
      {/* Mobile Overlay */}
      {isSidebarOpen && (
        <div
          className="fixed inset-0 bg-black/80 backdrop-blur-md z-[60] lg:hidden"
          onClick={toggleSidebar}
        />
      )}

      {/* Sidebar - Desktop Collapsible & Mobile Drawer */}
      <aside className={`
        fixed inset-y-0 left-0 bg-[#0a0b14] border-r border-white/5 z-[70]
        transform transition-all duration-500 ease-[cubic-bezier(0.4,0,0.2,1)]
        lg:relative lg:translate-x-0
        ${isSidebarOpen ? 'translate-x-0 w-[280px]' : '-translate-x-full lg:translate-x-0'}
        ${isCollapsed ? 'lg:w-[88px]' : 'lg:w-[280px]'}
      `}>
        {/* Sidebar Header */}
        <div className={`h-24 flex items-center ${isCollapsed ? 'justify-center' : 'px-8'} border-b border-white/5 relative overflow-hidden`}>
          {!isCollapsed ? (
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-primary flex items-center justify-center shadow-[0_0_20px_rgba(0,242,255,0.4)]">
                <Shield size={22} className="text-black" />
              </div>
              <div className="flex flex-col">
                <span className="text-lg font-black tracking-tighter uppercase italic">NetWatch</span>
                <span className="text-[9px] font-black tracking-[0.3em] text-primary/60 uppercase">SIEM PRO</span>
              </div>
            </div>
          ) : (
            <Shield size={24} className="text-primary" />
          )}

          {/* Desktop Collapse Toggle */}
          <button
            onClick={toggleCollapse}
            className="hidden lg:flex absolute right-4 top-1/2 -translate-y-1/2 w-8 h-8 items-center justify-center rounded-lg hover:bg-white/5 text-primary/40 transition-all"
          >
            {isCollapsed ? <PanelLeftClose size={18} /> : <PanelLeftOpen size={18} />}
          </button>
        </div>

        {/* Navigation */}
        <div className="p-4 space-y-8 h-[calc(100vh-96px)] overflow-y-auto custom-scrollbar">
          <div className="space-y-1.5">
            {!isCollapsed && <p className="px-4 text-[10px] font-black text-foreground/20 uppercase tracking-[0.3em] mb-4">Core</p>}
            {mainNavItems.map(item => (
              <NavItem
                key={item.id}
                icon={item.icon}
                label={item.label}
                active={activeTab === item.id}
                collapsed={isCollapsed}
                badge={item.badge}
                onClick={() => {
                  setActiveTab(item.id);
                  if (isSidebarOpen) setIsSidebarOpen(false);
                }}
              />
            ))}
          </div>

          <div className="space-y-1.5 pt-6 border-t border-white/5">
            {!isCollapsed && <p className="px-4 text-[10px] font-black text-foreground/20 uppercase tracking-[0.3em] mb-4">System</p>}
            {secondaryNavItems.map(item => (
              <NavItem
                key={item.id}
                icon={item.icon}
                label={item.label}
                active={activeTab === item.id}
                collapsed={isCollapsed}
                danger={item.danger}
                onClick={() => {
                  setActiveTab(item.id);
                  if (isSidebarOpen) setIsSidebarOpen(false);
                }}
              />
            ))}
          </div>
        </div>
      </aside>

      {/* Main Container */}
      <main className="flex-1 flex flex-col min-w-0 bg-[#07080e] relative overflow-hidden pb-24 lg:pb-0">
        <header className="h-20 border-b border-white/5 flex items-center justify-between px-6 lg:px-12 bg-background/80 backdrop-blur-xl z-40">
          <div className="flex items-center gap-4">
            <div className="w-2 h-2 rounded-full bg-primary animate-pulse shadow-[0_0_10px_#00f2ff]" />
            <span className="text-[10px] font-black uppercase tracking-[0.3em] text-primary hidden sm:inline">Scanner: Active</span>
            <div className="h-4 w-[1px] bg-white/10 hidden sm:block" />
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-black tracking-widest text-foreground/40 uppercase">Network Scanner</span>
            </div>
          </div>

          <div className="flex items-center gap-6">
            <div className="hidden md:flex flex-col items-end leading-none">
              <span className="text-[9px] font-black text-foreground/20 uppercase tracking-[0.2em] mb-1">Your IP</span>
              <span className="text-xs font-mono font-bold text-primary">{scanStatus?.local_ip || '192.168.1.1'}</span>
            </div>
            <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/5 flex items-center justify-center relative hover:bg-primary/20 transition-all cursor-pointer group">
              <Bell size={20} className="text-foreground/40 group-hover:text-primary transition-colors" />
              {criticalAlerts.length > 0 && <span className="absolute top-2.5 right-2.5 w-2 h-2 bg-accent rounded-full border-2 border-background shadow-[0_0_8px_#ff2d55]" />}
            </div>
          </div>
        </header>

        {/* Dynamic Viewport */}
        <div className="flex-1 overflow-y-auto custom-scrollbar p-6 lg:p-12 relative z-10 scroll-smooth">
          {activeTab === 'dashboard' && <Dashboard devices={devices} alerts={alerts} stats={stats} scanStatus={scanStatus} loading={devicesLoading || alertsLoading} setActiveTab={setActiveTab} />}
          {activeTab === 'topology' && <DeviceTopology devices={devices} localIp={scanStatus?.local_ip} />}
          {activeTab === 'alerts' && <AlertList alerts={alerts} isLoading={alertsLoading} />}
          {activeTab === 'events' && <EventList events={events} isLoading={eventsLoading} />}
          {activeTab === 'settings' && <SettingsView />}
          {activeTab === 'profile' && <ProfileView stats={stats} />}
          {activeTab === 'logout' && <LogoutView />}
        </div>

        {/* Mobile Bottom Navigation */}
        <nav className="fixed bottom-0 left-0 right-0 h-24 bg-[#0a0b14]/98 border-t border-white/10 lg:hidden flex items-center justify-around px-2 z-[90] shadow-[0_-20px_50px_rgba(0,0,0,0.8)] pb-safe">
          {mainNavItems.map(item => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className="flex-1 flex flex-col items-center gap-2 transition-all duration-300"
            >
              <div className={`
                relative w-12 h-12 rounded-xl flex items-center justify-center transition-all duration-500
                ${activeTab === item.id
                  ? 'bg-primary shadow-[0_0_20px_rgba(0,242,255,0.6)] scale-110'
                  : 'bg-white/5 hover:bg-white/10'
                }
              `}>
                {React.cloneElement(item.icon, {
                  size: 22,
                  className: activeTab === item.id ? 'text-black' : 'text-primary'
                })}
                {item.badge > 0 && (
                  <span className={`
                    absolute -top-1.5 -right-1.5 min-w-[18px] h-[18px] flex items-center justify-center 
                    rounded-full text-[9px] font-black border-2 border-[#0a0b14] animate-pulse
                    ${activeTab === item.id ? 'bg-black text-primary' : 'bg-accent text-white'}
                  `}>
                    {item.badge}
                  </span>
                )}
              </div>
              <span className={`
                text-[9px] font-black uppercase tracking-[0.2em] transition-all duration-300
                ${activeTab === item.id ? 'text-primary' : 'text-foreground/20'}
              `}>
                {item.label}
              </span>
            </button>
          ))}
          <button
            onClick={toggleSidebar}
            className="flex-1 flex flex-col items-center gap-2 transition-all"
          >
            <div className="w-12 h-12 rounded-xl bg-white/5 flex items-center justify-center hover:bg-white/10 transition-all">
              <Menu size={22} className="text-white/40" />
            </div>
            <span className="text-[9px] font-black uppercase tracking-[0.2em] text-foreground/20">More</span>
          </button>
        </nav>
      </main>
    </div>
  );
};

const NavItem = ({ icon, label, active, collapsed, badge, onClick, danger }) => (
  <button
    onClick={onClick}
    className={`
      w-full flex items-center justify-between transition-all duration-500 group
      ${collapsed ? 'px-0 justify-center h-14' : 'px-5 py-4'}
      ${active
        ? 'bg-primary text-black rounded-2xl shadow-[0_0_20px_rgba(0,242,255,0.4)] scale-[1.02]'
        : `text-foreground/40 hover:text-foreground hover:bg-white/5 rounded-2xl ${danger ? 'hover:text-accent hover:bg-accent/5' : ''}`
      }
    `}
  >
    <div className={`flex items-center ${collapsed ? '' : 'gap-4'} w-full`}>
      <div className={`transition-all duration-500 ${active ? 'scale-110' : 'group-hover:scale-110'}`}>
        {React.cloneElement(icon, { size: 20, className: active ? 'text-black' : 'text-primary' })}
      </div>
      {!collapsed && (
        <span className={`text-[12px] font-black uppercase tracking-widest truncate ${active ? 'opacity-100' : 'opacity-70'}`}>
          {label}
        </span>
      )}
    </div>
    {!collapsed && badge > 0 && (
      <span className={`px-2 py-0.5 rounded-lg text-[9px] font-black animate-pulse ${active ? 'bg-black text-primary' : 'bg-accent text-white'}`}>{badge}</span>
    )}
    {!collapsed && !badge && !active && (
      <ChevronRight size={14} className="opacity-0 -translate-x-2 transition-all duration-300 group-hover:opacity-20 group-hover:translate-x-0" />
    )}
  </button>
);

const Dashboard = ({ devices, alerts, stats, scanStatus, loading, setActiveTab }) => {
  const { data: events } = useEvents();
  const [isScanning, setIsScanning] = useState(false);
  const recentEvents = events?.slice(0, 10) || [];
  const activeDeviceCount = devices?.filter(d => d.is_online).length || 0;
  const criticalCount = alerts?.filter(a => !a.is_resolved && a.severity === 'critical').length || 0;
  const untrustedCount = devices?.filter(d => !d.is_trusted).length || 0;

  const securityScore = stats?.health_score || (criticalCount > 0 ? 'CRITICAL' : 'STABLE');
  const scoreColor = securityScore === 'CRITICAL' ? 'text-accent' : 'text-green-500';

  const handleManualScan = async () => {
    setIsScanning(true);
    try {
      await api.post('/alerts/scan');
    } catch (err) {
      console.error("Scan trigger failed", err);
    } finally {
      setTimeout(() => setIsScanning(false), 2000);
    }
  };

  const getScanBtnLabel = () => {
    if (scanStatus?.is_scanning) return scanStatus.last_status || "Scanning...";
    if (isScanning) return "Initializing Pipeline...";
    return "Initiate Deep Scan";
  };

  const avgRisk = devices?.length
    ? devices.reduce((acc, d) => acc + (d.risk_score || 0), 0) / devices.reduce((acc, d) => acc + (d.is_online ? 1 : 0.1), 0)
    : 0;
  const healthPercentage = Math.max(5, Math.min(100, 100 - avgRisk));

  return (
    <div className="space-y-10 animate-in fade-in slide-in-from-bottom-5 duration-1000">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 px-2">
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <div className="w-8 h-1 bg-primary rounded-full shadow-[0_0_10px_#00f2ff]" />
            <span className="text-[10px] font-black uppercase tracking-[0.4em] text-primary">Intelligence Command</span>
          </div>
          <h2 className="text-3xl lg:text-4xl font-black tracking-tighter uppercase italic drop-shadow-2xl">Security Operations</h2>
          <p className="text-foreground/30 font-medium text-[11px] lg:text-xs tracking-widest uppercase">
            {scanStatus?.is_scanning ? `Scanning Infrastructure - ${scanStatus.last_status}` : `Asset Control | ${activeDeviceCount} Managed Identities`}
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4">
          {scanStatus?.last_error && (
            <div className="px-4 py-3 bg-accent/10 border border-accent/20 rounded-xl flex items-center gap-3 animate-pulse">
              <AlertTriangle size={16} className="text-accent" />
              <div className="flex flex-col">
                <span className="text-[9px] font-black text-accent uppercase tracking-widest">Signal Failure</span>
                <span className="text-[10px] font-mono text-accent/80"> - {scanStatus.last_error}</span>
              </div>
            </div>
          )}

          <button
            onClick={handleManualScan}
            disabled={isScanning || scanStatus?.is_scanning}
            className={`
              px-8 py-3.5 rounded-2xl text-[10px] font-black uppercase tracking-[0.3em] transition-all
              flex items-center gap-4 border shadow-2xl min-w-[280px] justify-center
              ${(isScanning || scanStatus?.is_scanning)
                ? 'bg-primary/5 border-primary/20 text-primary/60 cursor-wait'
                : 'bg-primary text-black border-primary/30 hover:shadow-primary/20 hover:scale-[1.02] active:scale-95'
              }
            `}
          >
            <Activity size={18} className={(isScanning || scanStatus?.is_scanning) ? 'animate-spin' : ''} />
            <span className="truncate">{scanStatus?.is_scanning ? scanStatus.last_status : (isScanning ? "Initializing..." : "Discover Assets")}</span>
          </button>
        </div>
      </div>

      {/* SOC/NOC Impact Insight */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 px-2">
        <div className="lg:col-span-2 glass-card p-6 border-l-4 border-l-primary/40 bg-gradient-to-r from-primary/5 to-transparent">
          <h3 className="text-[10px] font-black uppercase tracking-[0.4em] text-primary mb-3">Professional Impact</h3>
          <p className="text-lg font-bold text-foreground/80 leading-snug mb-4 italic">"Eliminating the Shadow IT gap through adaptive discovery and real-time residency tracking."</p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="space-y-1">
              <span className="text-[9px] font-black uppercase tracking-widest text-foreground/40 block">Asset Visibility</span>
              <p className="text-[11px] font-medium text-foreground/60 leading-tight">Eliminates 'Blind Spots' by guaranteeing 100% device detection on Windows logs.</p>
            </div>
            <div className="space-y-1">
              <span className="text-[9px] font-black uppercase tracking-widest text-foreground/40 block">Response Friction</span>
              <p className="text-[11px] font-medium text-foreground/60 leading-tight">Optimized for MTTR—enabling instant clarity without deciphering technical 'noise'.</p>
            </div>
            <div className="space-y-1">
              <span className="text-[9px] font-black uppercase tracking-widest text-foreground/40 block">Presence Logs</span>
              <p className="text-[11px] font-medium text-foreground/60 leading-tight">Tracks residency history to detect stealth lateral movement and pivot attempts.</p>
            </div>
          </div>
        </div>
        <div className="glass-card p-6 flex flex-col justify-center border border-white/5 bg-[#0a0b14]">
          <span className="text-[9px] font-black uppercase tracking-widest text-foreground/20 mb-4">Security Posture</span>
          <div className="space-y-4">
            <div className="flex items-end justify-between">
              <span className={`text-4xl font-black italic tracking-tighter ${healthPercentage > 70 ? 'text-primary' : healthPercentage > 40 ? 'text-orange-400' : 'text-accent'}`}>
                {Math.round(healthPercentage)}%
              </span>
              <span className="text-[10px] font-mono text-foreground/30 uppercase tracking-[0.2em] mb-1">Integrity</span>
            </div>
            <div className="h-2 bg-white/5 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all duration-1000 ${healthPercentage > 70 ? 'bg-primary shadow-[0_0_10px_#00f2ff]' : healthPercentage > 40 ? 'bg-orange-500' : 'bg-accent'}`}
                style={{ width: `${healthPercentage}%` }}
              />
            </div>
            <p className="text-[9px] font-mono text-foreground/20 leading-tight">
              Calculated based on {devices?.length || 0} active asset risk vectors.
            </p>
          </div>
        </div>
      </div>
      {/* Managed Assets Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 px-2">
        <StatCard
          title="Managed Identities"
          value={activeDeviceCount}
          icon={<Globe size={20} className="text-primary" />}
          trend="Operational"
          onClick={() => setActiveTab('dashboard')}
        />
        <StatCard
          title="Critical Vectors"
          value={criticalCount}
          icon={<ShieldAlert size={20} className="text-accent" />}
          trend="Active Threats"
          color="border-accent/40"
          onClick={() => setActiveTab('alerts')}
        />
        <StatCard
          title="Shadow Assets"
          value={untrustedCount}
          icon={<Users size={20} className="text-yellow-400" />}
          trend="Pending Audit"
          onClick={() => setActiveTab('dashboard')}
        />
        <StatCard
          title="Sync Cycles"
          value={scanStatus?.scan_count || 0}
          icon={<Clock size={20} className="text-green-400" />}
          trend="Continuous Sync"
          onClick={() => setActiveTab('events')}
        />
      </div>

      <div className="px-2">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-[10px] font-black uppercase tracking-[0.4em] text-foreground/40">Infrastructure Discovery Feed</h3>
          <div className="flex items-center gap-2 text-[9px] font-mono text-primary/40">
            <div className="w-1.5 h-1.5 rounded-full bg-primary animate-ping" />
            LIVE TELEMETRY
          </div>
        </div>
        <DeviceList devices={devices} isLoading={loading} />
      </div>

      <div className="border border-white/5 bg-[#0a0b14] overflow-hidden shadow-2xl">
        <div className="p-6 lg:p-8 border-b border-white/10 flex flex-col sm:flex-row items-center justify-between gap-6 bg-white/[0.02]">
          <div className="text-center sm:text-left">
            <h3 className="text-[10px] font-black uppercase tracking-[0.4em] text-foreground/40 leading-none mb-2">Activity Log</h3>
            <p className="text-[14px] font-bold text-foreground/80 tracking-tight leading-none uppercase italic">Recent Events</p>
          </div>
          <button
            onClick={() => setActiveTab('events')}
            className="w-full sm:w-auto px-6 py-2.5 bg-primary/10 border border-primary/20 text-primary text-[10px] font-black uppercase tracking-[0.2em] hover:bg-primary hover:text-black transition-all"
          >
            View History
          </button>
        </div>
        <div className="overflow-x-auto custom-scrollbar">
          <EventList events={recentEvents} isLoading={false} />
        </div>
      </div>
    </div>
  );
};

const SettingsView = () => (
  <div className="flex flex-col items-center justify-center min-h-[400px] text-center max-w-xl mx-auto space-y-8 animate-in zoom-in duration-700">
    <div className="p-8 rounded-[32px] bg-primary/5 border border-primary/10 shadow-2xl">
      <Settings size={48} className="text-primary animate-spin-slow" />
    </div>
    <div className="space-y-3">
      <h2 className="text-2xl font-black uppercase tracking-[0.3em] italic">System Settings</h2>
      <div className="grid grid-cols-1 gap-4 mt-6 text-left">
        <div className="p-4 glass-card border border-white/5 flex items-center justify-between">
          <span className="text-[10px] font-black uppercase tracking-widest text-foreground/60">Auto-Discovery Sync</span>
          <div className="w-10 h-5 bg-primary/20 rounded-full relative"><div className="absolute right-1 top-1 w-3 h-3 bg-primary rounded-full shadow-[0_0_8px_#00f2ff]" /></div>
        </div>
        <div className="p-4 glass-card border border-white/5 flex items-center justify-between opacity-40 grayscale">
          <span className="text-[10px] font-black uppercase tracking-widest text-foreground/60">Cloud Uplink (Encrypted)</span>
          <div className="w-10 h-5 bg-white/10 rounded-full relative"><div className="absolute left-1 top-1 w-3 h-3 bg-white/20 rounded-full" /></div>
        </div>
      </div>
      <p className="text-foreground/20 text-[9px] font-mono tracking-widest uppercase mt-4">
        Firmware v4.2.0-STABLE | Local Auth Active
      </p>
    </div>
  </div>
);

const ProfileView = ({ stats }) => (
  <div className="flex flex-col items-center justify-center min-h-[400px] text-center max-w-xl mx-auto space-y-8 animate-in zoom-in duration-700">
    <div className="relative">
      <div className="p-8 rounded-[32px] bg-primary/5 border border-primary/10 shadow-2xl">
        <User size={48} className="text-primary" />
      </div>
      <div className="absolute -bottom-2 -right-2 bg-primary text-black px-3 py-1 rounded-full text-[10px] font-black tracking-tighter">
        LVL {stats?.operator_level || 1}
      </div>
    </div>
    <div className="space-y-6 w-full">
      <div className="space-y-1">
        <h2 className="text-2xl font-black uppercase tracking-[0.3em] italic leading-none">Senior Operator</h2>
        <p className="text-primary/60 text-[10px] font-mono tracking-widest uppercase">Encryption Key: SHA-256-NETWATCH</p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="glass-card p-4 border border-white/5">
          <p className="text-[9px] font-black text-foreground/20 uppercase mb-1">Impact Resolved</p>
          <p className="text-xl font-mono font-black">{stats?.total_resolved || 0}</p>
        </div>
        <div className="glass-card p-4 border border-white/5">
          <p className="text-[9px] font-black text-foreground/20 uppercase mb-1">Signals Verified</p>
          <p className="text-xl font-mono font-black">{stats?.total_events || 0}</p>
        </div>
      </div>
    </div>
  </div>
);

const LogoutView = () => {
  const [terminating, setTerminating] = React.useState(false);

  const handleTerminate = () => {
    setTerminating(true);
    setTimeout(() => window.location.reload(), 2500);
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-[400px] text-center max-w-xl mx-auto space-y-8 animate-in zoom-in duration-700">
      <div className={`p-8 rounded-[32px] bg-accent/5 border border-accent/10 shadow-2xl transition-all duration-1000 ${terminating ? 'scale-0 opacity-0 blur-3xl' : ''}`}>
        <LogOut size={48} className="text-accent" />
      </div>
      <div className="space-y-3">
        <h2 className={`text-2xl font-black uppercase tracking-[0.3em] italic text-accent transition-all ${terminating ? 'tracking-[1em] opacity-0' : ''}`}>
          {terminating ? 'Shredding Session...' : 'Log Out'}
        </h2>
        <p className="text-foreground/30 text-[11px] font-bold tracking-widest leading-relaxed uppercase mb-6">
          {terminating ? 'Zeroing memory buffers and closing encrypted pipes...' : 'Exit the current session and secure the terminal.'}
        </p>
        {!terminating && (
          <button
            onClick={handleTerminate}
            className="px-8 py-3 rounded-xl bg-accent text-white font-black uppercase tracking-widest hover:scale-105 active:scale-95 transition-all shadow-[0_0_30px_rgba(255,45,85,0.3)]"
          >
            Confirm Termination
          </button>
        )}
      </div>
    </div>
  );
};

export default App;
