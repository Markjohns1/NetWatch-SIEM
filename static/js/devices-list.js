let devicesData = [];
let selectedDevices = new Set();

function loadDevices() {
    fetch('/api/devices')
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                devicesData = data.data;
                renderDeviceTable();
            }
        })
        .catch(err => console.error('Error loading devices:', err));
}

function renderDeviceTable() {
    const tbody = document.getElementById('devicesTableBody');
    if (!tbody) return;
    
    if (devicesData.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="py-4 text-center text-slate-400">No devices found</td></tr>';
        return;
    }
    
    let html = '';
    
    devicesData.forEach(device => {
        const statusClass = device.status === 'online' ? 'status-online' : 'status-offline';
        const isTrusted = device.is_trusted ? 'checked' : '';
        // Normalize device name display - show "Unknown" if no name/hostname available
        let deviceName = device.device_name || device.hostname || null;
        if (!deviceName || deviceName.trim() === '' || deviceName === 'Unknown') {
            deviceName = 'Unknown';
        }
        
        html += `
            <tr class="hover:bg-slate-800/50 transition">
                <td class="px-4 py-3">
                    <input type="checkbox" class="device-checkbox" value="${device.id}" onchange="updateDeleteButton()">
                </td>
                <td class="px-4 py-3">
                    <input type="text" value="${deviceName}" class="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs w-32" onchange="updateDeviceName(${device.id}, this.value)" placeholder="Device name">
                </td>
                <td class="px-4 py-3 font-mono text-blue-400 text-xs">${device.ip_address || 'N/A'}</td>
                <td class="px-4 py-3 font-mono text-slate-300 text-xs">${device.mac_address || 'N/A'}</td>
                <td class="px-4 py-3 text-slate-300 text-xs">${device.vendor || 'Unknown'}</td>
                <td class="px-4 py-3">
                    <span class="status-badge ${statusClass}">${device.status}</span>
                </td>
                <td class="px-4 py-3">
                    <input type="checkbox" ${isTrusted} onchange="toggleTrust(${device.id}, this.checked)">
                </td>
                <td class="px-4 py-3 text-xs">
                    <button onclick="deleteDevice(${device.id})" class="text-red-400 hover:text-red-300">Delete</button>
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
    
    if (typeof feather !== 'undefined') {
        feather.replace();
    }
}

function selectAllDevices() {
    const checkboxes = document.querySelectorAll('.device-checkbox');
    const allChecked = Array.from(checkboxes).every(cb => cb.checked);
    
    checkboxes.forEach(cb => {
        cb.checked = !allChecked;
    });
    
    updateDeleteButton();
}

function updateDeleteButton() {
    const btn = document.getElementById('deleteSelectedBtn');
    const checkboxes = document.querySelectorAll('.device-checkbox:checked');
    btn.disabled = checkboxes.length === 0;
}

function deleteSelectedDevices() {
    const checkboxes = document.querySelectorAll('.device-checkbox:checked');
    if (checkboxes.length === 0) return;
    
    const deviceIds = Array.from(checkboxes).map(cb => parseInt(cb.value));
    
    if (!confirm(`Delete ${deviceIds.length} device(s)? This cannot be undone.`)) {
        return;
    }
    
    fetch('/api/devices/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_ids: deviceIds })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            alert(`Deleted ${data.deleted_count} device(s)`);
            loadDevices();
        } else {
            alert('Error deleting devices: ' + data.error);
        }
    })
    .catch(err => {
        console.error('Delete error:', err);
        alert('Error deleting devices');
    });
}

function deleteDevice(deviceId) {
    if (!confirm('Delete this device? This cannot be undone.')) {
        return;
    }
    
    fetch('/api/devices/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_ids: [deviceId] })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            loadDevices();
        } else {
            alert('Error deleting device: ' + data.error);
        }
    })
    .catch(err => {
        console.error('Delete error:', err);
        alert('Error deleting device');
    });
}

function updateDeviceName(deviceId, newName) {
    fetch(`/api/devices/${deviceId}/name`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newName })
    })
    .then(res => res.json())
    .then(data => {
        if (!data.success) {
            alert('Error updating device name: ' + data.error);
            loadDevices();
        }
    })
    .catch(err => {
        console.error('Update error:', err);
        alert('Error updating device name');
    });
}

function toggleTrust(deviceId, isTrusted) {
    fetch(`/api/devices/${deviceId}/trust`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_trusted: isTrusted ? 1 : 0 })
    })
    .then(res => res.json())
    .then(data => {
        if (!data.success) {
            alert('Error updating trust status: ' + data.error);
            loadDevices();
        }
    })
    .catch(err => {
        console.error('Trust error:', err);
        alert('Error updating trust status');
    });
}

function updatePageData() {
    console.log('Refreshing devices...');
    loadDevices();
    return true;
}

window.updatePageData = updatePageData;

// Make sure it's always available
if (typeof window.updatePageData === 'undefined') {
    window.updatePageData = updatePageData;
}

// Real-time updates via Socket.IO
function setupRealtimeUpdates() {
    if (typeof io !== 'undefined' && window.netwatchRealtime && window.netwatchRealtime.socket) {
        // Remove existing listeners to avoid duplicates
        window.netwatchRealtime.socket.off('device_list_update');
        window.netwatchRealtime.socket.off('device_status_update');
        
        window.netwatchRealtime.socket.on('device_list_update', (data) => {
            if (data && data.devices) {
                devicesData = data.devices;
                renderDeviceTable();
            }
        });
        
        window.netwatchRealtime.socket.on('device_status_update', (data) => {
            if (data && data.changes) {
                // Refresh device list when status changes
                loadDevices();
            }
        });
    } else {
        // Retry if socket not ready yet
        setTimeout(setupRealtimeUpdates, 500);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadDevices();
    // Setup real-time updates once socket is ready
    setupRealtimeUpdates();
});

// Also setup when socket connects
if (window.netwatchRealtime) {
    const originalConnect = window.netwatchRealtime.setupEventHandlers;
    window.netwatchRealtime.setupEventHandlers = function() {
        if (originalConnect) originalConnect.call(this);
        setTimeout(setupRealtimeUpdates, 100);
    };
}