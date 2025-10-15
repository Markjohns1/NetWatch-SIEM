let activityChart = null;

function updateDashboardStats() {
    fetch('/api/dashboard/stats')
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                document.getElementById('totalDevices').textContent = data.data.total_devices;
                document.getElementById('activeDevices').textContent = data.data.active_devices;
                document.getElementById('criticalAlerts').textContent = data.data.critical_alerts;
                document.getElementById('trustedDevices').textContent = data.data.trusted_devices;
            }
        });
}

function updateRecentAlerts() {
    fetch('/api/alerts?limit=5')
        .then(res => res.json())
        .then(data => {
            const container = document.getElementById('alertsList');
            if (data.success && data.data.length > 0) {
                container.innerHTML = data.data.map(alert => `
                    <div class="alert-box ${alert.severity} fade-in">
                        <i data-feather="${
                            alert.severity === 'high' ? 'alert-octagon' :
                            alert.severity === 'medium' ? 'alert-triangle' : 'info'
                        }" class="text-${
                            alert.severity === 'high' ? 'red' :
                            alert.severity === 'medium' ? 'amber' : 'blue'
                        }-400"></i>
                        <div class="flex-1">
                            <p class="font-medium">${alert.title}</p>
                            <p class="text-xs text-slate-400">${alert.description} • ${formatTime(alert.timestamp)}</p>
                        </div>
                    </div>
                `).join('');
                feather.replace();
            } else {
                container.innerHTML = '<p class="text-slate-400 text-sm">No alerts</p>';
            }
        });
}

function updateActiveDevices() {
    fetch('/api/devices/active')
        .then(res => res.json())
        .then(data => {
            const container = document.getElementById('devicesList');
            if (data.success && data.data.length > 0) {
                container.innerHTML = data.data.slice(0, 5).map(device => `
                    <div class="device-card fade-in">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center gap-3">
                                <div class="w-8 h-8 rounded-full bg-emerald-500/20 flex items-center justify-center">
                                    <i data-feather="wifi" class="w-4 h-4 text-emerald-400"></i>
                                </div>
                                <div>
                                    <p class="font-medium">${device.device_name || device.hostname || 'Unknown Device'}</p>
                                    <p class="text-xs text-slate-400">${device.ip_address} • ${device.vendor || 'Unknown'}</p>
                                </div>
                            </div>
                            <span class="status-badge status-online">Online</span>
                        </div>
                    </div>
                `).join('');
                feather.replace();
            } else {
                container.innerHTML = '<p class="text-slate-400 text-sm">No devices detected</p>';
            }
        });
}

function updateActivityChart() {
    fetch('/api/activity/timeline')
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                const ctx = document.getElementById('networkChart').getContext('2d');
                
                if (activityChart) {
                    activityChart.destroy();
                }
                
                activityChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: data.data.map(d => new Date(d.time).toLocaleTimeString()),
                        datasets: [{
                            label: 'Network Events',
                            data: data.data.map(d => d.count),
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            fill: true,
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                display: false
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: 'rgba(51, 65, 85, 0.3)'
                                },
                                ticks: {
                                    color: '#94a3b8'
                                }
                            },
                            x: {
                                grid: {
                                    color: 'rgba(51, 65, 85, 0.3)'
                                },
                                ticks: {
                                    color: '#94a3b8',
                                    maxTicksLimit: 12
                                }
                            }
                        }
                    }
                });
            }
        });
}

function formatTime(timestamp) {
    const now = new Date();
    const time = new Date(timestamp);
    const diff = Math.floor((now - time) / 1000);
    
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)} hours ago`;
    return time.toLocaleDateString();
}

function updatePageData() {
    updateDashboardStats();
    updateRecentAlerts();
    updateActiveDevices();
    updateActivityChart();
}

window.updatePageData = updatePageData;

updatePageData();
setInterval(updatePageData, 5000);
