import React from 'react';
import { Globe, ShieldCheck, ShieldAlert, Cpu } from 'lucide-react';
import { motion } from 'framer-motion';

export const DeviceTopology = ({ devices }) => {
    // Simple topology layout: Gateway in center, devices orbiting
    const gateway = { ip: '192.168.1.1', type: 'gateway' };

    return (
        <div className="relative w-full h-[600px] glass-card overflow-hidden bg-background/50 border-primary/5">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,#00f2ff0a_0%,transparent_70%)]" />

            {/* Gateway Node */}
            <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-20">
                <Node
                    icon={<Cpu className="text-secondary" />}
                    label="Gateway"
                    sublabel={gateway.ip}
                    pulse
                    color="border-secondary"
                />
            </div>

            {/* Orbiting Devices */}
            {devices?.map((device, index) => {
                const angle = (index / (devices.length || 1)) * 2 * Math.PI;
                const radius = 220;
                const x = radius * Math.cos(angle);
                const y = radius * Math.sin(angle);

                return (
                    <motion.div
                        key={device.id}
                        initial={{ opacity: 0, scale: 0 }}
                        animate={{ opacity: 1, scale: 1, x, y }}
                        transition={{ delay: index * 0.1, type: 'spring' }}
                        className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-10"
                    >
                        <div className="relative">
                            {/* Connector Line */}
                            <svg className="absolute top-1/2 left-1/2 -z-10 pointer-events-none" style={{ width: radius, height: radius, transform: `translate(-50%, -50%) rotate(${angle + Math.PI}rad)` }}>
                                <line
                                    x1="0" y1="50%"
                                    x2="100%" y2="50%"
                                    stroke="rgba(0, 242, 255, 0.1)"
                                    strokeWidth="1"
                                    strokeDasharray="4 4"
                                />
                            </svg>

                            <Node
                                icon={device.is_trusted ? <ShieldCheck className="text-primary" /> : <ShieldAlert className="text-accent" />}
                                label={device.hostname || 'Node'}
                                sublabel={device.ip_address}
                                color={device.is_trusted ? 'border-primary' : 'border-accent'}
                            />
                        </div>
                    </motion.div>
                );
            })}
        </div>
    );
};

const Node = ({ icon, label, sublabel, pulse, color }) => (
    <div className="flex flex-col items-center gap-2 group cursor-pointer">
        <div className={`p-4 rounded-2xl bg-muted/80 backdrop-blur-xl border-2 ${color || 'border-border'} shadow-[0_0_20px_rgba(0,0,0,0.5)] group-hover:scale-110 transition-transform ${pulse ? 'animate-pulse' : ''}`}>
            {icon}
        </div>
        <div className="text-center">
            <p className="text-[10px] font-black uppercase tracking-[0.2em]">{label}</p>
            <p className="text-[9px] font-mono text-foreground/40">{sublabel}</p>
        </div>
    </div>
);
