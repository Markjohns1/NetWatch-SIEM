import React from 'react';
import { Globe, AlertTriangle, ShieldCheck, ShieldAlert, Clock, MoreVertical } from 'lucide-react';

export const DeviceList = ({ devices, isLoading }) => {
    if (isLoading) return <div className="text-primary animate-pulse">Scanning network...</div>;

    return (
        <div className="glass-card overflow-hidden">
            <table className="w-full text-left">
                <thead className="border-b border-border bg-white/5">
                    <tr>
                        <th className="px-6 py-4 text-xs font-bold uppercase tracking-widest text-foreground/40">Device</th>
                        <th className="px-6 py-4 text-xs font-bold uppercase tracking-widest text-foreground/40">MAC Address</th>
                        <th className="px-6 py-4 text-xs font-bold uppercase tracking-widest text-foreground/40">Status</th>
                        <th className="px-6 py-4 text-xs font-bold uppercase tracking-widest text-foreground/40">Last Seen</th>
                        <th className="px-6 py-4"></th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-border">
                    {devices?.map((device) => (
                        <tr key={device.id} className="hover:bg-white/5 transition-colors group">
                            <td className="px-6 py-4">
                                <div className="flex items-center gap-3">
                                    <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
                                        <Globe size={16} className="text-primary" />
                                    </div>
                                    <div>
                                        <p className="font-bold text-sm">{device.hostname || 'Unknown'}</p>
                                        <p className="text-xs text-foreground/40 font-mono">{device.ip_address}</p>
                                    </div>
                                </div>
                            </td>
                            <td className="px-6 py-4 text-sm font-mono text-foreground/60">{device.mac_address}</td>
                            <td className="px-6 py-4">
                                {device.is_trusted ? (
                                    <span className="flex items-center gap-1.5 text-xs font-bold px-2 py-1 rounded-full bg-green-500/10 text-green-400 border border-green-500/20">
                                        <ShieldCheck size={12} /> TRUSTED
                                    </span>
                                ) : (
                                    <span className="flex items-center gap-1.5 text-xs font-bold px-2 py-1 rounded-full bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">
                                        <Globe size={12} /> DETECTED
                                    </span>
                                )}
                            </td>
                            <td className="px-6 py-4">
                                <div className="flex items-center gap-2 text-xs text-foreground/40">
                                    <Clock size={12} />
                                    {new Date(device.last_seen).toLocaleTimeString()}
                                </div>
                            </td>
                            <td className="px-6 py-4 text-right">
                                <button className="text-foreground/40 hover:text-primary transition-colors">
                                    <MoreVertical size={16} />
                                </button>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export const AlertList = ({ alerts, isLoading }) => {
    if (isLoading) return <div className="text-primary animate-pulse">Loading alerts...</div>;

    return (
        <div className="glass-card overflow-hidden">
            <table className="w-full text-left">
                <thead className="border-b border-border bg-white/5">
                    <tr>
                        <th className="px-6 py-4 text-xs font-bold uppercase tracking-widest text-foreground/40">Severity</th>
                        <th className="px-6 py-4 text-xs font-bold uppercase tracking-widest text-foreground/40">Event</th>
                        <th className="px-6 py-4 text-xs font-bold uppercase tracking-widest text-foreground/40">Time</th>
                        <th className="px-6 py-4 text-xs font-bold uppercase tracking-widest text-foreground/40">Status</th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-border">
                    {alerts?.map((alert) => (
                        <tr key={alert.id} className="hover:bg-white/5 transition-colors group">
                            <td className="px-6 py-4">
                                <span className={`text-[10px] font-black uppercase px-2 py-0.5 rounded border ${alert.severity === 'critical' ? 'bg-accent/10 text-accent border-accent/20' :
                                        alert.severity === 'high' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                                            'bg-blue-500/10 text-blue-400 border-blue-500/20'
                                    }`}>
                                    {alert.severity}
                                </span>
                            </td>
                            <td className="px-6 py-4">
                                <p className="text-sm font-medium">{alert.message}</p>
                                <p className="text-xs text-foreground/40 font-mono">Rule: {alert.rule_id}</p>
                            </td>
                            <td className="px-6 py-4 text-xs text-foreground/40">
                                {new Date(alert.timestamp).toLocaleString()}
                            </td>
                            <td className="px-6 py-4">
                                {alert.is_resolved ? (
                                    <span className="text-xs text-green-400 font-bold">RESOLVED</span>
                                ) : (
                                    <button className="text-xs text-primary font-bold hover:underline">MARK RESOLVED</button>
                                )}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};
