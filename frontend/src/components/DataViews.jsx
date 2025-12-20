import React, { useState } from 'react';
import { Globe, AlertTriangle, ShieldCheck, ShieldAlert, Clock, MoreVertical, Terminal, Activity, Edit3, Shield } from 'lucide-react';
import api from '../api/client';
import { useQueryClient } from '@tanstack/react-query';

export const DeviceList = ({ devices, isLoading }) => {
    const queryClient = useQueryClient();
    const [renamingId, setRenamingId] = useState(null);
    const [tempName, setTempName] = useState("");

    const handleTrust = async (id) => {
        try {
            await api.post(`/devices/${id}/trust`);
            queryClient.invalidateQueries(['devices']);
        } catch (e) { console.error(e); }
    };

    const handleRename = async (id) => {
        if (!tempName.trim()) return setRenamingId(null);
        try {
            await api.post(`/devices/${id}/rename`, { name: tempName });
            setRenamingId(null);
            setTempName("");
            queryClient.invalidateQueries(['devices']);
        } catch (e) { console.error(e); }
    };

    if (isLoading) return (
        <div className="flex items-center gap-3 p-8 border border-white/5 bg-white/[0.01]">
            <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            <span className="text-[10px] font-black uppercase tracking-[0.3em] text-primary/60">Scanning Network Infrastructure...</span>
        </div>
    );

    return (
        <div className="border border-white/5 bg-[#0a0b14] overflow-x-auto custom-scrollbar shadow-2xl">
            <table className="w-full text-left border-collapse min-w-[800px]">
                <thead className="bg-white/[0.03] border-b border-white/10">
                    <tr>
                        <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Device Identity</th>
                        <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">MAC / Vendor</th>
                        <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Exposed Services</th>
                        <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Risk Level</th>
                        <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Status</th>
                        <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30 text-right">Protection</th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.05]">
                    {devices?.length > 0 ? devices.map((device) => {
                        let ports = [];
                        try { ports = device.open_ports ? JSON.parse(device.open_ports) : []; } catch (e) { }

                        return (
                            <tr key={device.id} className="bg-transparent hover:bg-white/[0.01] transition-colors">
                                <td className="px-6 py-4">
                                    <div className="flex items-center gap-4">
                                        <div className={`w-10 h-10 rounded-xl bg-white/[0.03] border border-white/5 flex items-center justify-center relative`}>
                                            <Globe size={16} className={device.is_online ? "text-primary/60" : "text-foreground/10"} />
                                            <span className={`absolute -top-1 -right-1 w-3 h-3 rounded-full border-2 border-[#0a0b14] ${device.is_online ? 'bg-primary' : 'bg-foreground/20'}`} />
                                        </div>
                                        <div className="flex flex-col group/name">
                                            {renamingId === device.id ? (
                                                <input
                                                    autoFocus
                                                    className="bg-primary/10 border border-primary/30 text-[13px] font-bold text-primary px-2 outline-none rounded"
                                                    value={tempName}
                                                    onChange={e => setTempName(e.target.value)}
                                                    onBlur={() => handleRename(device.id)}
                                                    onKeyDown={e => e.key === 'Enter' && handleRename(device.id)}
                                                />
                                            ) : (
                                                <div className="flex items-center gap-2">
                                                    <span
                                                        onClick={() => { setRenamingId(device.id); setTempName(device.device_name || device.hostname || ""); }}
                                                        className={`text-[13px] font-bold leading-tight cursor-pointer hover:text-primary transition-colors ${device.is_online ? 'text-foreground/90' : 'text-foreground/30'}`}
                                                    >
                                                        {device.device_name || device.hostname || 'Network Asset'}
                                                    </span>
                                                    <Edit3 size={10} className="opacity-0 group-hover/name:opacity-30" />
                                                </div>
                                            )}
                                            <span className="text-[11px] font-mono text-primary/50 tracking-tight">{device.ip_address}</span>
                                        </div>
                                    </div>
                                </td>
                                <td className="px-6 py-4">
                                    <div className="flex flex-col gap-0.5">
                                        <span className="text-[10px] font-mono text-foreground/40 tracking-wider uppercase">{device.mac_address}</span>
                                        <span className="text-[9px] font-black text-primary/30 uppercase tracking-[0.2em]">{device.vendor || 'Unknown Vendor'}</span>
                                    </div>
                                </td>
                                <td className="px-6 py-4">
                                    <div className="flex flex-wrap gap-1.5">
                                        {ports.length > 0 ? ports.map(port => (
                                            <span key={port} className="text-[9px] font-mono px-2 py-0.5 bg-white/5 border border-white/10 text-foreground/60 rounded-sm">
                                                {port === 80 || port === 8080 ? 'HTTP' : port === 443 ? 'HTTPS' : port === 22 ? 'SSH' : port === 3389 ? 'RDP' : port === 445 ? 'SMB' : port}
                                            </span>
                                        )) : <span className="text-[10px] text-foreground/10 italic">Secure / No services</span>}
                                    </div>
                                </td>
                                <td className="px-6 py-4">
                                    <div className="flex items-center gap-3">
                                        <div className="w-16 h-1 bg-white/5 rounded-full overflow-hidden">
                                            <div
                                                className={`h-full transition-all duration-1000 ${device.risk_score > 70 ? 'bg-accent' : device.risk_score > 40 ? 'bg-orange-500' : 'bg-primary'}`}
                                                style={{ width: `${device.risk_score}%` }}
                                            />
                                        </div>
                                        <span className={`text-[10px] font-mono ${device.risk_score > 70 ? 'text-accent font-bold' : 'text-foreground/30'}`}>
                                            {Math.round(device.risk_score)}%
                                        </span>
                                    </div>
                                </td>
                                <td className="px-6 py-4 text-[10px] font-mono">
                                    {device.is_online ? <span className="text-primary animate-pulse uppercase tracking-widest">Live</span> : <span className="text-foreground/20 uppercase tracking-widest">Offline</span>}
                                </td>
                                <td className="px-6 py-4 text-right">
                                    <button
                                        onClick={() => handleTrust(device.id)}
                                        className={`p-2 rounded-lg border transition-all ${device.is_trusted ? 'bg-green-500/10 border-green-500/20 text-green-500' : 'bg-white/5 border-white/10 text-foreground/20 hover:text-primary hover:border-primary/40'}`}
                                        title={device.is_trusted ? "Trusted Asset" : "Mark as Trusted"}
                                    >
                                        <Shield size={14} />
                                    </button>
                                </td>
                            </tr>
                        )
                    }) : (
                        <tr>
                            <td colSpan="6" className="px-6 py-20 text-center opacity-20">
                                <div className="flex flex-col items-center gap-4">
                                    <Terminal size={32} />
                                    <p className="text-[10px] font-black uppercase tracking-[0.4em]">Searching for devices...</p>
                                </div>
                            </td>
                        </tr>
                    )}
                </tbody>
            </table>
        </div>
    );
};

export const AlertList = ({ alerts, isLoading }) => {
    const queryClient = useQueryClient();

    const handleAcknowledge = async (id) => {
        try {
            await api.post(`/alerts/${id}/resolve`);
            queryClient.invalidateQueries(['alerts']);
            queryClient.invalidateQueries(['stats']);
        } catch (e) { console.error(e); }
    };

    if (isLoading) return (
        <div className="flex items-center gap-3 p-8 border border-white/5 bg-white/[0.01]">
            <div className="w-4 h-4 border-2 border-accent border-t-transparent rounded-full animate-spin" />
            <span className="text-[10px] font-black uppercase tracking-[0.3em] text-accent/60">Fetching Intelligence...</span>
        </div>
    );

    return (
        <div className="border border-white/5 bg-[#0a0b14] overflow-x-auto custom-scrollbar shadow-2xl">
            <table className="w-full text-left border-collapse min-w-[800px]">
                <thead className="bg-white/[0.03] border-b border-white/10">
                    <tr>
                        <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Priority</th>
                        <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Intelligence Data</th>
                        <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Capture Time</th>
                        <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Resolution</th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.05]">
                    {alerts?.length > 0 ? alerts.map((alert) => (
                        <tr key={alert.id} className="bg-transparent">
                            <td className="px-6 py-4">
                                <span className={`text-[9px] font-black uppercase px-2 py-0.5 border ${alert.severity === 'critical' ? 'bg-accent/5 text-accent border-accent/20' :
                                    alert.severity === 'high' ? 'bg-orange-500/5 text-orange-400 border-orange-500/20' :
                                        'bg-blue-500/5 text-blue-400 border-blue-500/20'
                                    } tracking-tighter`}>
                                    {alert.severity}
                                </span>
                            </td>
                            <td className="px-6 py-4">
                                <div className="flex flex-col">
                                    <span className="text-[13px] font-bold text-foreground/80 leading-tight">{alert.message}</span>
                                    <span className="text-[10px] font-mono text-foreground/30 tracking-tight uppercase">Reference ID: {alert.rule_id}</span>
                                </div>
                            </td>
                            <td className="px-6 py-4 text-[11px] font-mono text-foreground/40 tracking-tight">
                                {new Date(alert.timestamp).toLocaleString([], { hour12: false })}
                            </td>
                            <td className="px-6 py-4">
                                {alert.is_resolved ? (
                                    <span className="text-[10px] font-black text-green-500/60 uppercase tracking-widest border border-green-500/10 px-2 py-1 bg-green-500/5">Resolved</span>
                                ) : (
                                    <button
                                        onClick={() => handleAcknowledge(alert.id)}
                                        className="text-[10px] font-black text-primary uppercase tracking-widest hover:border-b border-primary/40 transition-all"
                                    >
                                        Acknowledge
                                    </button>
                                )}
                            </td>
                        </tr>
                    )) : (
                        <tr>
                            <td colSpan="4" className="px-6 py-20 text-center opacity-20">
                                <div className="flex flex-col items-center gap-4">
                                    <ShieldAlert size={32} />
                                    <p className="text-[10px] font-black uppercase tracking-[0.4em]">No Threat Signals Captured</p>
                                </div>
                            </td>
                        </tr>
                    )}
                </tbody>
            </table>
        </div>
    );
};

export const EventList = ({ events, isLoading }) => {
    if (isLoading) return (
        <div className="flex items-center gap-3 p-8 border border-white/5 bg-white/[0.01]">
            <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            <span className="text-[10px] font-black uppercase tracking-[0.3em] text-primary/60">Retrieving Network History...</span>
        </div>
    );

    return (
        <div className="border border-white/5 bg-[#0a0b14] overflow-x-auto custom-scrollbar shadow-2xl">
            <table className="w-full text-left border-collapse min-w-[800px]">
                <thead className="bg-white/[0.03] border-b border-white/10">
                    <tr>
                        <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Event Type</th>
                        <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Description</th>
                        <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Category</th>
                        <th className="px-6 py-4 text-[9px] font-black uppercase tracking-[0.3em] text-foreground/30">Time</th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.05]">
                    {events?.length > 0 ? events.map((event) => (
                        <tr key={event.id} className="bg-transparent hover:bg-white/[0.01] transition-colors">
                            <td className="px-6 py-4 border-l-2 border-l-transparent hover:border-l-primary/40 transition-all">
                                <span className={`text-[9px] font-black uppercase px-2 py-0.5 border ${event.event_type === 'left' ? 'bg-accent/10 text-accent border-accent/20' :
                                    event.event_type === 'joined' ? 'bg-primary/10 text-primary border-primary/20' :
                                        'bg-blue-500/10 text-blue-400 border-blue-500/20'
                                    } tracking-tighter`}>
                                    {event.event_type}
                                </span>
                            </td>
                            <td className="px-6 py-4">
                                <span className="text-[13px] font-bold text-foreground/80 leading-tight">{event.description}</span>
                            </td>
                            <td className="px-6 py-4 text-[10px] font-mono text-foreground/30 uppercase tracking-widest">
                                Infrastructure
                            </td>
                            <td className="px-6 py-4 text-[11px] font-mono text-foreground/40 tracking-tight">
                                {new Date(event.timestamp + 'Z').toLocaleString()}
                            </td>
                        </tr>
                    )) : (
                        <tr>
                            <td colSpan="4" className="px-6 py-20 text-center opacity-20">
                                <Activity size={32} className="mx-auto mb-4" />
                                <p className="text-[10px] font-black uppercase tracking-[0.4em]">No discovery events recorded</p>
                            </td>
                        </tr>
                    )}
                </tbody>
            </table>
        </div>
    );
};
