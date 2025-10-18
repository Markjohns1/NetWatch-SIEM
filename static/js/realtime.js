/**
 * Real-time WebSocket client for NetWatch SIEM
 * Provides live updates without page refresh
 */

class NetWatchRealtime {
    constructor() {
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
        this.isConnected = false;
        
        this.init();
    }
    
    init() {
        // Load Socket.IO client library
        this.loadSocketIO();
        
        // Set up connection after library loads
        setTimeout(() => {
            this.connect();
        }, 100);
    }
    
    loadSocketIO() {
        // Load Socket.IO client library if not already loaded
        if (typeof io === 'undefined') {
            const script = document.createElement('script');
            script.src = 'https://cdn.socket.io/4.7.2/socket.io.min.js';
            script.onload = () => {
                console.log('Socket.IO client loaded');
            };
            document.head.appendChild(script);
        }
    }
    
    connect() {
        if (typeof io === 'undefined') {
            console.error('Socket.IO not loaded, retrying...');
            setTimeout(() => this.connect(), 1000);
            return;
        }
        
        try {
            this.socket = io();
            this.setupEventHandlers();
            console.log('Connecting to NetWatch SIEM real-time server...');
        } catch (error) {
            console.error('Failed to connect to WebSocket:', error);
            this.handleReconnect();
        }
    }
    
    setupEventHandlers() {
        this.socket.on('connect', () => {
            console.log('✅ Connected to NetWatch SIEM real-time updates');
            this.isConnected = true;
            this.reconnectAttempts = 0;
            this.showConnectionStatus('connected');
            
            // Request initial data
            this.socket.emit('request_dashboard_stats');
            this.socket.emit('request_device_list');
        });
        
        this.socket.on('disconnect', () => {
            console.log('❌ Disconnected from NetWatch SIEM');
            this.isConnected = false;
            this.showConnectionStatus('disconnected');
            this.handleReconnect();
        });
        
        this.socket.on('connected', (data) => {
            console.log('Server message:', data.message);
        });
        
        this.socket.on('dashboard_stats_update', (data) => {
            this.updateDashboardStats(data.stats);
            this.updateLastUpdateTime(data.timestamp);
        });
        
        this.socket.on('device_status_update', (data) => {
            this.handleDeviceStatusChanges(data.changes);
            this.updateLastUpdateTime(data.timestamp);
        });
        
        this.socket.on('device_list_update', (data) => {
            this.updateDeviceList(data.devices);
            this.updateLastUpdateTime(data.timestamp);
        });
        
        this.socket.on('error', (data) => {
            console.error('Server error:', data.message);
            this.showNotification('Error: ' + data.message, 'error');
        });
    }
    
    handleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            console.log(`Attempting to reconnect... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
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
        // Update main dashboard stats
        const elements = {
            'totalDevices': stats.total_devices,
            'activeDevices': stats.active_devices,
            'criticalAlerts': stats.critical_alerts,
            'trustedDevices': stats.trusted_devices
        };
        
        Object.entries(elements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                // Animate number change
                this.animateNumberChange(element, value);
            }
        });
        
        // Update sidebar stats
        const sidebarElements = {
            'onlineCount': stats.active_devices,
            'totalCount': stats.total_devices,
            'alertsCount': stats.active_alerts,
            'alertCount': stats.active_alerts,
            'newTodayCount': stats.new_today
        };
        
        Object.entries(sidebarElements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                this.animateNumberChange(element, value);
            }
        });
        
        // Update mobile stats
        const mobileElements = {
            'mobileOnlineCount': stats.active_devices,
            'mobileTotalCount': stats.total_devices,
            'mobileAlertsCount': stats.active_alerts,
            'mobileAlertCount': stats.active_alerts,
            'mobileNewTodayCount': stats.new_today
        };
        
        Object.entries(mobileElements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                this.animateNumberChange(element, value);
            }
        });
    }
    
    handleDeviceStatusChanges(changes) {
        changes.forEach(change => {
            const { device_id, ip, mac, status, change: changeType } = change;
            
            // Show notification for status changes
            let message = '';
            let type = 'info';
            
            switch (changeType) {
                case 'came_online':
                    message = `Device ${ip} came online`;
                    type = 'success';
                    break;
                case 'went_offline':
                    message = `Device ${ip} went offline`;
                    type = 'warning';
                    break;
                case 'new_device':
                    message = `New device detected: ${ip}`;
                    type = 'info';
                    break;
            }
            
            this.showNotification(message, type);
            
            // Update device list if on devices page
            if (window.updatePageData) {
                window.updatePageData();
            }
        });
    }
    
    updateDeviceList(devices) {
        // This will be handled by the existing device list update functions
        if (window.updatePageData) {
            window.updatePageData();
        }
    }
    
    animateNumberChange(element, newValue) {
        const currentValue = parseInt(element.textContent) || 0;
        if (currentValue === newValue) return;
        
        // Add animation class
        element.classList.add('number-change');
        
        // Update value
        element.textContent = newValue;
        
        // Remove animation class after animation
        setTimeout(() => {
            element.classList.remove('number-change');
        }, 300);
    }
    
    updateLastUpdateTime(timestamp) {
        const lastScanElement = document.getElementById('lastScanTime');
        if (lastScanElement) {
            const updateTime = new Date(timestamp);
            const now = new Date();
            const diff = Math.floor((now - updateTime) / 1000);
            
            if (diff < 60) {
                lastScanElement.textContent = 'Just now';
            } else if (diff < 3600) {
                lastScanElement.textContent = `${Math.floor(diff / 60)} min ago`;
            } else {
                lastScanElement.textContent = updateTime.toLocaleTimeString();
            }
        }
    }
    
    showConnectionStatus(status) {
        // Create or update connection status indicator
        let statusElement = document.getElementById('connectionStatus');
        if (!statusElement) {
            statusElement = document.createElement('div');
            statusElement.id = 'connectionStatus';
            statusElement.style.cssText = `
                position: fixed;
                top: 10px;
                right: 10px;
                padding: 8px 12px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 500;
                z-index: 1000;
                transition: all 0.3s ease;
            `;
            document.body.appendChild(statusElement);
        }
        
        const statusConfig = {
            'connected': { text: '🟢 Live', color: '#10b981', bg: '#064e3b' },
            'disconnected': { text: '🔴 Offline', color: '#ef4444', bg: '#7f1d1d' },
            'reconnecting': { text: '🟡 Connecting...', color: '#f59e0b', bg: '#78350f' },
            'failed': { text: ' Failed', color: '#ef4444', bg: '#7f1d1d' }
        };
        
        const config = statusConfig[status] || statusConfig['disconnected'];
        statusElement.textContent = config.text;
        statusElement.style.color = config.color;
        statusElement.style.backgroundColor = config.bg;
        
        // Auto-hide connected status after 1 seconds
        if (status === 'connected') {
            setTimeout(() => {
                if (statusElement && statusElement.textContent === '🟢 Live') {
                    statusElement.style.opacity = '0.7';
                }
            }, 1000);
        }
    }
    
    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 16px;
            border-radius: 6px;
            color: white;
            font-size: 14px;
            font-weight: 500;
            z-index: 1001;
            max-width: 300px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            transform: translateX(100%);
            transition: transform 0.3s ease;
        `;
        
        const typeColors = {
            'success': '#10b981',
            'error': '#ef4444',
            'warning': '#f59e0b',
            'info': '#3b82f6'
        };
        
        notification.style.backgroundColor = typeColors[type] || typeColors['info'];
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 10);
        
        // Auto-remove after 5 seconds
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

// Initialize real-time client when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.netwatchRealtime = new NetWatchRealtime();
});

// Add CSS for number change animation
const style = document.createElement('style');
style.textContent = `
    .number-change {
        animation: numberPulse 0.3s ease-in-out;
    }
    
    @keyframes numberPulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.1); color: #3b82f6; }
        100% { transform: scale(1); }
    }
`;
document.head.appendChild(style);
