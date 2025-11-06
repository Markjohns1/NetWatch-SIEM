class NetWatchRealtime {
    constructor() {
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 2000;
        this.isConnected = false;
        this.pageReady = false;
    }
    
    start() {
        if (typeof io === 'undefined') {
            console.error('Socket.IO not loaded');
            return;
        }
        this.pageReady = true;
        this.connect();
    }
    
    connect() {
        if (!this.pageReady) {
            setTimeout(() => this.connect(), 500);
            return;
        }
        
        if (this.socket && this.socket.connected) {
            return;
        }
        
        try {
            this.socket = io({
                reconnection: true,
                reconnectionDelay: 2000,
                reconnectionDelayMax: 10000,
                reconnectionAttempts: this.maxReconnectAttempts,
                transports: ['websocket', 'polling'],
                forceNew: true,
                upgrade: true
            });
            
            this.setupEventHandlers();
            console.log('Socket.IO connection initiated');
        } catch (error) {
            console.error('Failed to create socket:', error);
            this.handleReconnect();
        }
    }
    
    setupEventHandlers() {
        this.socket.on('connect', () => {
            console.log('Connected to NetWatch SIEM');
            this.isConnected = true;
            this.reconnectAttempts = 0;
            this.showConnectionStatus('connected');
            
            setTimeout(() => {
                this.socket.emit('request_dashboard_stats');
                this.socket.emit('request_device_list');
            }, 100);
            
            // Trigger real-time listener setup on all pages
            if (typeof setupRealtimeListeners === 'function') {
                setupRealtimeListeners();
            }
            if (typeof setupRealtimeUpdates === 'function') {
                setupRealtimeUpdates();
            }
        });
        
        this.socket.on('disconnect', (reason) => {
            console.log('Disconnected from NetWatch SIEM:', reason);
            this.isConnected = false;
            this.showConnectionStatus('disconnected');
        });
        
        this.socket.on('connected', (data) => {
            console.log('Server message:', data.message);
        });
        
        this.socket.on('dashboard_stats_update', (data) => {
            if (data && data.stats) {
                this.updateDashboardStats(data.stats);
                this.updateLastUpdateTime(data.timestamp);
            }
        });
        
        this.socket.on('device_status_update', (data) => {
            if (data && data.changes) {
                this.handleDeviceStatusChanges(data.changes);
                this.updateLastUpdateTime(data.timestamp);
            }
        });
        
        this.socket.on('device_list_update', (data) => {
            if (data && data.devices) {
                this.updateDeviceList(data.devices);
                this.updateLastUpdateTime(data.timestamp);
                
                // Force update dashboard stats when device list changes
                if (typeof updateDashboardStats === 'function') {
                    updateDashboardStats();
                }
            }
        });
        
        this.socket.on('error', (error) => {
            console.error('Socket error:', error);
        });
        
        this.socket.on('connect_error', (error) => {
            console.error('Connection error:', error);
            this.isConnected = false;
        });
    }
    
    handleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            console.log(`Reconnect attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts}`);
            this.showConnectionStatus('reconnecting');
            
            setTimeout(() => {
                this.connect();
            }, this.reconnectDelay * this.reconnectAttempts);
        } else {
            console.error('Max reconnection attempts reached');
            this.showConnectionStatus('failed');
        }
    }
    
    updateDashboardStats(stats) {
        const elements = {
            'totalDevices': stats.total_devices,
            'activeDevices': stats.active_devices,
            'criticalAlerts': stats.critical_alerts,
            'trustedDevices': stats.trusted_devices
        };
        
        Object.entries(elements).forEach(([id, value]) => {
            const el = document.getElementById(id);
            if (el) this.animateNumberChange(el, value);
        });
        
        const sidebarElements = {
            'onlineCount': stats.active_devices,
            'totalCount': stats.total_devices,
            'alertsCount': stats.active_alerts,
            'alertCount': stats.active_alerts,
            'newTodayCount': stats.new_today
        };
        
        Object.entries(sidebarElements).forEach(([id, value]) => {
            const el = document.getElementById(id);
            if (el) this.animateNumberChange(el, value);
        });
        
        const mobileElements = {
            'mobileOnlineCount': stats.active_devices,
            'mobileTotalCount': stats.total_devices,
            'mobileAlertsCount': stats.active_alerts,
            'mobileAlertCount': stats.active_alerts,
            'mobileNewTodayCount': stats.new_today
        };
        
        Object.entries(mobileElements).forEach(([id, value]) => {
            const el = document.getElementById(id);
            if (el) this.animateNumberChange(el, value);
        });
    }
    
    handleDeviceStatusChanges(changes) {
        changes.forEach(change => {
            const { ip, change: changeType } = change;
            let message = '';
            let type = 'info';
            
            if (changeType === 'came_online') {
                message = `Device ${ip} came online`;
                type = 'success';
            } else if (changeType === 'went_offline') {
                message = `Device ${ip} went offline`;
                type = 'warning';
            } else if (changeType === 'new_device') {
                message = `New device detected: ${ip}`;
                type = 'info';
            }
            
            this.showNotification(message, type);
        });
    }
    
    updateDeviceList(devices) {
        console.log('Device list updated:', devices.length, 'devices');
        
        // Update dashboard if on devices page
        if (typeof updatePageData === 'function') {
            updatePageData();
        }
        
        // Update active devices on dashboard
        if (typeof updateActiveDevices === 'function') {
            updateActiveDevices();
        }
    }
    
    animateNumberChange(element, newValue) {
        const currentValue = parseInt(element.textContent) || 0;
        if (currentValue === newValue) return;
        
        element.classList.add('number-change');
        element.textContent = newValue;
        
        setTimeout(() => {
            element.classList.remove('number-change');
        }, 300);
    }
    
    updateLastUpdateTime(timestamp) {
        const el = document.getElementById('lastScanTime');
        if (el) {
            const diff = Math.floor((new Date() - new Date(timestamp)) / 1000);
            
            if (diff < 60) {
                el.textContent = 'Just now';
            } else if (diff < 3600) {
                el.textContent = `${Math.floor(diff / 60)}m ago`;
            } else {
                el.textContent = new Date(timestamp).toLocaleTimeString();
            }
        }
    }
    
    showConnectionStatus(status) {
        let el = document.getElementById('connectionStatus');
        if (!el) {
            el = document.createElement('div');
            el.id = 'connectionStatus';
            el.style.cssText = 'position:fixed;top:10px;right:10px;padding:8px 12px;border-radius:4px;font-size:12px;font-weight:500;z-index:1000;transition:all 0.3s ease;';
            document.body.appendChild(el);
        }
        
        const config = {
            'connected': { text: 'Live', color: '#10b981', bg: '#064e3b' },
            'disconnected': { text: 'Offline', color: '#ef4444', bg: '#7f1d1d' },
            'reconnecting': { text: 'Connecting...', color: '#f59e0b', bg: '#78350f' },
            'failed': { text: 'Failed', color: '#ef4444', bg: '#7f1d1d' }
        };
        
        const c = config[status] || config['disconnected'];
        el.textContent = c.text;
        el.style.color = c.color;
        el.style.backgroundColor = c.bg;
    }
    
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.style.cssText = 'position:fixed;top:20px;right:20px;padding:12px 16px;border-radius:6px;color:white;font-size:14px;font-weight:500;z-index:1001;max-width:300px;box-shadow:0 4px 12px rgba(0,0,0,0.3);transform:translateX(100%);transition:transform 0.3s ease;';
        
        const colors = {
            'success': '#10b981',
            'error': '#ef4444',
            'warning': '#f59e0b',
            'info': '#3b82f6'
        };
        
        notification.style.backgroundColor = colors[type] || colors['info'];
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 10);
        
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 5000);
    }
    
    disconnect() {
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
        }
    }
}

window.netwatchRealtime = new NetWatchRealtime();

document.addEventListener('DOMContentLoaded', () => {
    window.netwatchRealtime.start();
});

window.addEventListener('load', () => {
    if (!window.netwatchRealtime.isConnected) {
        console.log('Page fully loaded, ensuring connection...');
        window.netwatchRealtime.start();
    }
});

const style = document.createElement('style');
style.textContent = '.number-change { animation: numberPulse 0.3s ease-in-out; } @keyframes numberPulse { 0% { transform: scale(1); } 50% { transform: scale(1.1); color: #3b82f6; } 100% { transform: scale(1); } }';
document.head.appendChild(style);