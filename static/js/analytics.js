// Enhanced Analytics Dashboard with Useful Charts
let charts = {};

// Chart configuration
const chartConfig = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
        legend: {
            labels: {
                color: '#94a3b8',
                font: {
                    size: 12
                }
            }
        },
        tooltip: {
            backgroundColor: 'rgba(15, 23, 42, 0.9)',
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
            grid: {
                color: 'rgba(51, 65, 85, 0.3)',
                drawBorder: false
            },
            ticks: {
                color: '#94a3b8',
                font: {
                    size: 11
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
                    size: 11
                }
            }
        }
    }
};

// Load network health data
async function loadNetworkHealth() {
    try {
        const response = await fetch('/api/analytics/network-health');
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('healthScore').textContent = data.data.health_score;
            document.getElementById('onlineCount').textContent = data.data.online_devices;
            document.getElementById('trustedCount').textContent = data.data.trusted_devices;
            document.getElementById('alertsCount').textContent = data.data.active_alerts;
            document.getElementById('activityCount').textContent = data.data.recent_activity;
            
            // Update health score color
            const healthScore = data.data.health_score;
            const healthElement = document.getElementById('healthScore');
            if (healthScore >= 80) {
                healthElement.className = 'text-3xl font-bold text-emerald-400';
            } else if (healthScore >= 60) {
                healthElement.className = 'text-3xl font-bold text-yellow-400';
            } else {
                healthElement.className = 'text-3xl font-bold text-red-400';
            }
        }
    } catch (error) {
        console.error('Error loading network health:', error);
    }
}

// Load device trends
async function loadDeviceTrends() {
    try {
        const response = await fetch('/api/analytics/device-trends');
        const data = await response.json();
        
        if (data.success) {
            // Device status distribution
            createStatusChart(data.data.status_distribution);
            
            // Vendor distribution
            createVendorChart(data.data.vendor_distribution);
            
            // Device trends over time
            createDeviceTrendsChart(data.data.device_trends);
        }
    } catch (error) {
        console.error('Error loading device trends:', error);
    }
}

// Load alert trends
async function loadAlertTrends() {
    try {
        const response = await fetch('/api/analytics/alert-trends');
        const data = await response.json();
        
        if (data.success) {
            // Alert trends chart
            createAlertTrendsChart(data.data.alert_trends);
            
            // Hourly alert pattern
            createHourlyChart(data.data.hourly_alerts);
            
            // Alert types list
            createAlertTypesList(data.data.alert_types);
        }
    } catch (error) {
        console.error('Error loading alert trends:', error);
    }
}

// Create device status pie chart
function createStatusChart(data) {
    const ctx = document.getElementById('statusChart').getContext('2d');
    
    if (charts.statusChart) {
        charts.statusChart.destroy();
    }
    
    const colors = {
        'online': '#10b981',
        'offline': '#ef4444',
        'unknown': '#f59e0b'
    };
    
    charts.statusChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(item => item.status),
            datasets: [{
                data: data.map(item => item.count),
                backgroundColor: data.map(item => colors[item.status] || '#6b7280'),
                borderWidth: 0
            }]
        },
        options: {
            ...chartConfig,
            plugins: {
                ...chartConfig.plugins,
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        padding: 20,
                        usePointStyle: true
                    }
                }
            }
        }
    });
}

// Create vendor distribution chart
function createVendorChart(data) {
    const ctx = document.getElementById('vendorChart').getContext('2d');
    
    if (charts.vendorChart) {
        charts.vendorChart.destroy();
    }
    
    const colors = [
        '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
        '#06b6d4', '#84cc16', '#f97316', '#ec4899', '#6366f1'
    ];
    
    charts.vendorChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(item => item.vendor),
            datasets: [{
                label: 'Device Count',
                data: data.map(item => item.count),
                backgroundColor: colors.slice(0, data.length),
                borderColor: colors.slice(0, data.length),
                borderWidth: 1
            }]
        },
        options: {
            ...chartConfig,
            indexAxis: 'y'
        }
    });
}

// Create alert trends chart
function createAlertTrendsChart(data) {
    const ctx = document.getElementById('alertTrendsChart').getContext('2d');
    
    if (charts.alertTrendsChart) {
        charts.alertTrendsChart.destroy();
    }
    
    charts.alertTrendsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(item => new Date(item.date).toLocaleDateString()),
            datasets: [
                {
                    label: 'High Severity',
                    data: data.map(item => item.high),
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Medium Severity',
                    data: data.map(item => item.medium),
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Low Severity',
                    data: data.map(item => item.low),
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4
                }
            ]
        },
        options: chartConfig
    });
}

// Create hourly alert pattern chart
function createHourlyChart(data) {
    const ctx = document.getElementById('hourlyChart').getContext('2d');
    
    if (charts.hourlyChart) {
        charts.hourlyChart.destroy();
    }
    
    // Fill in missing hours with 0
    const hourlyData = Array.from({length: 24}, (_, i) => {
        const hourData = data.find(item => item.hour === i);
        return hourData ? hourData.count : 0;
    });
    
    charts.hourlyChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Array.from({length: 24}, (_, i) => `${i}:00`),
            datasets: [{
                label: 'Alerts',
                data: hourlyData,
                backgroundColor: 'rgba(59, 130, 246, 0.6)',
                borderColor: '#3b82f6',
                borderWidth: 1
            }]
        },
        options: {
            ...chartConfig,
            scales: {
                ...chartConfig.scales,
                x: {
                    ...chartConfig.scales.x,
                    ticks: {
                        ...chartConfig.scales.x.ticks,
                        maxTicksLimit: 12
                    }
                }
            }
        }
    });
}

// Create device trends chart
function createDeviceTrendsChart(data) {
    const ctx = document.getElementById('deviceTrendsChart').getContext('2d');
    
    if (charts.deviceTrendsChart) {
        charts.deviceTrendsChart.destroy();
    }
    
    charts.deviceTrendsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(item => new Date(item.date).toLocaleDateString()),
            datasets: [{
                label: 'New Devices',
                data: data.map(item => item.count),
                borderColor: '#10b981',
                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: chartConfig
    });
}

// Create risk level chart
function createRiskChart(riskData) {
    const ctx = document.getElementById('riskChart').getContext('2d');
    
    if (charts.riskChart) {
        charts.riskChart.destroy();
    }
    
    const colors = {
        'minimal': '#10b981',
        'low': '#3b82f6',
        'medium': '#f59e0b',
        'high': '#ef4444'
    };
    
    charts.riskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: riskData.map(item => item.level),
            datasets: [{
                data: riskData.map(item => item.count),
                backgroundColor: riskData.map(item => colors[item.level] || '#6b7280'),
                borderWidth: 0
            }]
        },
        options: {
            ...chartConfig,
            plugins: {
                ...chartConfig.plugins,
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        padding: 20,
                        usePointStyle: true
                    }
                }
            }
        }
    });
}

// Create alert types list
function createAlertTypesList(alertTypes) {
    const container = document.getElementById('alertTypesList');
    
    if (alertTypes.length === 0) {
        container.innerHTML = '<p class="text-slate-400 text-sm col-span-full text-center">No alert types data available</p>';
        return;
    }
    
    const colors = ['#ef4444', '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6', '#06b6d4'];
    
    container.innerHTML = alertTypes.map((item, index) => `
        <div class="cyber-card rounded-lg p-4">
            <div class="flex items-center justify-between mb-2">
                <h3 class="font-medium text-slate-200">${item.type.replace(/_/g, ' ').toUpperCase()}</h3>
                <span class="text-2xl font-bold" style="color: ${colors[index % colors.length]}">${item.count}</span>
            </div>
            <div class="w-full bg-slate-700 rounded-full h-2">
                <div class="h-2 rounded-full" style="background-color: ${colors[index % colors.length]}; width: ${(item.count / Math.max(...alertTypes.map(t => t.count))) * 100}%"></div>
            </div>
        </div>
    `).join('');
}

// Load risk levels from network health data
async function loadRiskLevels() {
    try {
        const response = await fetch('/api/analytics/network-health');
        const data = await response.json();
        
        if (data.success && data.data.risk_levels) {
            createRiskChart(data.data.risk_levels);
        }
    } catch (error) {
        console.error('Error loading risk levels:', error);
    }
}

// Initialize all charts
async function initializeAnalytics() {
    await Promise.all([
        loadNetworkHealth(),
        loadDeviceTrends(),
        loadAlertTrends(),
        loadRiskLevels()
    ]);
}

// Auto-refresh data every 30 seconds
setInterval(initializeAnalytics, 30000);

// Initialize on page load
document.addEventListener('DOMContentLoaded', initializeAnalytics);

