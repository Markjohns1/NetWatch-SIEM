let selectedDevices = new Set();

function updateDevicesList() {
    fetch('/api/devices')
        .then(res => res.json())
        .then(data => {
            const tbody = document.getElementById('devicesTableBody');
            if (data.success && data.data.length > 0) {
                tbody.innerHTML = data.data.map(device => `
                    <tr>
                        <td class="py-3">
                            <input type="checkbox" 
                                   class="device-checkbox" 
                                   data-device-id="${device.id}"
                                   ${selectedDevices.has(device.id) ? 'checked' : ''}
                                   onchange="toggleDeviceSelection(${device.id}, this.checked)">
                        </td>
                        <td class="py-3">
                            <div class="flex items-center gap-2">
                                <i data-feather="${device.status === 'online' ? 'wifi' : 'wifi-off'}" 
                                   class="w-4 h-4 text-${device.status === 'online' ? 'emerald' : 'slate'}-400"></i>
                                <span>${device.device_name || device.hostname || 'Unknown Device'}</span>
                            </div>
                        </td>
                        <td class="py-3 font-mono text-sm">${device.ip_address}</td>
                        <td class="py-3 font-mono text-sm">${device.mac_address}</td>
                        <td class="py-3">${device.vendor || 'Unknown'}</td>
                        <td class="py-3">
                            <span class="status-badge ${device.status === 'online' ? 'status-online' : 'status-offline'}">
                                ${device.status}
                            </span>
                        </td>
                        <td class="py-3">
                            <button onclick="toggleTrust(${device.id}, ${device.is_trusted})" 
                                    class="text-xs px-2 py-1 rounded ${device.is_trusted ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-700 text-slate-300'}">
                                ${device.is_trusted ? 'Trusted' : 'Untrusted'}
                            </button>
                        </td>
                        <td class="py-3">
                            <button onclick="editDeviceName(${device.id}, '${device.device_name || ''}')" 
                                    class="text-blue-400 hover:text-blue-300">
                                <i data-feather="edit-2" class="w-4 h-4"></i>
                            </button>
                        </td>
                    </tr>
                `).join('');
                feather.replace();
                updateDeleteButton();
            } else {
                tbody.innerHTML = '<tr><td colspan="8" class="py-4 text-center text-slate-400">No devices found</td></tr>';
            }
        });
}

function toggleDeviceSelection(deviceId, isChecked) {
    if (isChecked) {
        selectedDevices.add(deviceId);
    } else {
        selectedDevices.delete(deviceId);
    }
    updateDeleteButton();
}

function selectAllDevices() {
    const checkboxes = document.querySelectorAll('.device-checkbox');
    const selectAll = selectedDevices.size === 0;
    
    checkboxes.forEach(cb => {
        cb.checked = selectAll;
        const deviceId = parseInt(cb.dataset.deviceId);
        if (selectAll) {
            selectedDevices.add(deviceId);
        } else {
            selectedDevices.delete(deviceId);
        }
    });
    updateDeleteButton();
}

function updateDeleteButton() {
    const deleteBtn = document.getElementById('deleteSelectedBtn');
    if (deleteBtn) {
        deleteBtn.disabled = selectedDevices.size === 0;
        deleteBtn.textContent = selectedDevices.size > 0 
            ? `Delete Selected (${selectedDevices.size})` 
            : 'Delete Selected';
    }
}

function deleteSelectedDevices() {
    if (selectedDevices.size === 0) return;
    
    if (!confirm(`Are you sure you want to delete ${selectedDevices.size} device(s)?`)) {
        return;
    }
    
    fetch('/api/devices/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_ids: Array.from(selectedDevices) })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            selectedDevices.clear();
            updateDevicesList();
            showNotification(`Successfully deleted ${data.deleted_count} device(s)`, 'success');
        } else {
            showNotification('Error deleting devices: ' + data.error, 'error');
        }
    });
}

function toggleTrust(deviceId, currentTrust) {
    fetch(`/api/devices/${deviceId}/trust`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_trusted: currentTrust ? 0 : 1 })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            updateDevicesList();
        }
    });
}

function editDeviceName(deviceId, currentName) {
    const newName = prompt('Enter device name:', currentName);
    if (newName !== null) {
        fetch(`/api/devices/${deviceId}/name`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: newName })
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                updateDevicesList();
            }
        });
    }
}

function showNotification(message, type = 'info') {
    // Simple notification - you can enhance this
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 px-4 py-3 rounded shadow-lg ${
        type === 'success' ? 'bg-emerald-500' : 'bg-red-500'
    } text-white z-50`;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

window.updatePageData = updateDevicesList;

// Initialize
updateDevicesList();
setInterval(updateDevicesList, 10000);