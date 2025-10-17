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
        })
        .catch(err => console.error('Stats error:', err));
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
        })
        .catch(err => console.error('Alerts error:', err));
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
        })
        .catch(err => console.error('Devices error:', err));
}

function updateActivityChart() {
    fetch('/api/activity/timeline')
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                const ctx = document.getElementById('networkChart').getContext('2d');
                
                // Prepare data for chart
                const chartData = {
                    labels: data.data.map(d => {
                        const time = new Date(d.time);
                        return time.toLocaleTimeString('en-US', { 
                            hour: '2-digit', 
                            minute: '2-digit',
                            hour12: false 
                        });
                    }),
                    datasets: [{
                        label: 'Network Events',
                        data: data.data.map(d => d.count),
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 4,
                        pointBackgroundColor: '#3b82f6',
                        pointBorderColor: '#ffffff',
                        pointBorderWidth: 2,
                        pointHoverRadius: 6
                    }]
                };
                
                
                if (activityChart) {
                    activityChart.destroy();
                }
                
                // Create new chart
                activityChart = new Chart(ctx, {
                    type: 'line',
                    data: chartData,
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        animation: {
                            duration: 300 // Smooth animation on update
                        },
                        plugins: {
                            legend: {
                                display: false
                            },
                            tooltip: {
                                backgroundColor: 'rgba(15, 23, 42, 0.8)',
                                borderColor: '#3b82f6',
                                borderWidth: 1,
                                titleColor: '#e2e8f0',
                                bodyColor: '#cbd5e1',
                                padding: 12,
                                cornerRadius: 6
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: 'rgba(51, 65, 85, 0.3)',
                                    drawBorder: false
                                },
                                ticks: {
                                    color: '#94a3b8',
                                    font: {
                                        size: 12
                                    }
                                }
                            },
                            x: {
                                grid: {
                                    color: 'rgba(51, 65, 85, 0.2)',
                                    drawBorder: false
                                },
                                ticks: {
                                    color: '#94a3b8',
                                    font: {
                                        size: 12
                                    },
                                    maxTicksLimit: 12
                                }
                            }
                        }
                    }
                });
            }
        })
        .catch(err => console.error('Timeline error:', err));
}

function formatTime(timestamp) {
    const now = new Date();
    const time = new Date(timestamp);
    const diff = Math.floor((now - time) / 1000);
    
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return time.toLocaleDateString();
}

function updatePageData() {
    updateDashboardStats();
    updateRecentAlerts();
    updateActiveDevices();
    updateActivityChart();
}

window.updatePageData = updatePageData;

// Initial load
updatePageData();


setInterval(() => {
    updateDashboardStats();
    updateRecentAlerts();
    updateActiveDevices();
}, 3000);

setInterval(() => {
    updateActivityChart();
}, 2000);