function updateAlertsList() {
    fetch('/api/alerts')
        .then(res => res.json())
        .then(data => {
            const container = document.getElementById('alertsContainer');
            if (data.success && data.data.length > 0) {
                container.innerHTML = data.data.map(alert => `
                    <div class="alert-box ${alert.severity} fade-in">
                        <i data-feather="${
                            alert.severity === 'high' ? 'alert-octagon' :
                            alert.severity === 'medium' ? 'alert-triangle' : 'info'
                        }" class="text-${
                            alert.severity === 'high' ? 'red' :
                            alert.severity === 'medium' ? 'amber' : 'blue'
                        }-400 mt-0.5"></i>
                        <div class="flex-1">
                            <p class="font-medium">${alert.title}</p>
                            <p class="text-sm text-slate-300 mt-1">${alert.description}</p>
                            <div class="flex items-center gap-4 mt-2 text-xs text-slate-400">
                                <span>${formatTime(alert.timestamp)}</span>
                                ${alert.ip_address ? `<span>Device: ${alert.ip_address}</span>` : ''}
                                <span class="px-2 py-0.5 rounded ${
                                    alert.severity === 'high' ? 'bg-red-500/20 text-red-400' :
                                    alert.severity === 'medium' ? 'bg-amber-500/20 text-amber-400' :
                                    'bg-blue-500/20 text-blue-400'
                                }">${alert.severity.toUpperCase()}</span>
                            </div>
                        </div>
                        <div class="flex gap-2">
                            ${alert.status === 'active' ? `
                                <button onclick="markAlertSafe(${alert.id})" 
                                        class="px-3 py-1 bg-emerald-600 hover:bg-emerald-700 rounded text-sm flex items-center gap-1"
                                        title="Mark as safe/false positive">
                                    <i data-feather="shield" class="w-3 h-3"></i>
                                    Safe
                                </button>
                                <button onclick="resolveAlert(${alert.id})" 
                                        class="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded text-sm flex items-center gap-1">
                                    <i data-feather="check" class="w-3 h-3"></i>
                                    Resolve
                                </button>
                            ` : `
                                <span class="px-3 py-1 bg-slate-700 rounded text-sm text-slate-400">Resolved</span>
                            `}
                        </div>
                    </div>
                `).join('');
                feather.replace();
            } else {
                container.innerHTML = '<p class="text-slate-400 text-sm">No alerts found</p>';
            }
        });
}

function markAlertSafe(alertId) {
    if (!confirm('Mark this alert as safe/false positive? This will resolve it permanently.')) {
        return;
    }
    
    fetch(`/api/alerts/${alertId}/mark-safe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            updateAlertsList();
            showNotification('Alert marked as safe', 'success');
        } else {
            showNotification('Error: ' + data.error, 'error');
        }
    });
}

function resolveAlert(alertId) {
    fetch(`/api/alerts/${alertId}/resolve`, {
        method: 'POST'
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            updateAlertsList();
            showNotification('Alert resolved', 'success');
        }
    });
}

function formatTime(timestamp) {
    try {
        return new Date(timestamp).toLocaleString('en-KE', {
            timeZone: 'Africa/Nairobi',
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch {
        return new Date(timestamp).toLocaleString();
    }
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 px-4 py-3 rounded shadow-lg ${
        type === 'success' ? 'bg-emerald-500' : 'bg-red-500'
    } text-white z-50`;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => notification.remove(), 3000);
}

window.updatePageData = updateAlertsList;

updateAlertsList();
setInterval(updateAlertsList, 5000);