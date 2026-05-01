/**
 * ReconVault UI Logic - design.js
 * Modified for Background Progress and Dynamic UI Updates
 */
// --- settings ---
// --- settings ---
let initialSettingsSnapshot = null;

const THREAT_LEVEL_PRESETS = {
    low: {
        subfinder_timeout: 60,
        amass_timeout: 60,
        gobuster_timeout: 120,
        httpx_timeout: 45,
        nuclei_timeout: 60
    },
    medium: {
        subfinder_timeout: 120,
        amass_timeout: 120,
        gobuster_timeout: 180,
        httpx_timeout: 60,
        nuclei_timeout: 90
    },
    high: {
        subfinder_timeout: 180,
        amass_timeout: 180,
        gobuster_timeout: 300,
        httpx_timeout: 90,
        nuclei_timeout: 120
    }
};

function hideAlerts() {
    const successAlert = document.getElementById('success-alert');
    const errorAlert = document.getElementById('error-alert');

    if (successAlert) successAlert.style.display = 'none';
    if (errorAlert) errorAlert.style.display = 'none';
}

function applyThreatLevelPreset(saveAfterApply = true) {
    const form = document.getElementById('settingsForm');
    if (!form) return;

    const threatLevelInput = form.querySelector('[name="threat_level"]');
    if (!threatLevelInput) return;

    const level = (threatLevelInput.value || 'medium').toLowerCase();
    const preset = THREAT_LEVEL_PRESETS[level];

    if (!preset) return;

    Object.entries(preset).forEach(([name, value]) => {
        const input = form.querySelector(`[name="${name}"]`);
        if (input) {
            input.value = value;
        }
    });

    hideAlerts();

    if (saveAfterApply) {
        saveSettings();
    }
}

function resetSettingsForm() {
    const form = document.getElementById('settingsForm');
    if (!form || !initialSettingsSnapshot) return;

    const entries = Array.from(initialSettingsSnapshot.entries());
    form.reset();

    const checkboxNames = ['theme_mode', 'notifications', 'auto_scan', 'ssl_verification', 'threat_alerts', 'data_encryption'];

    checkboxNames.forEach(name => {
        const input = form.querySelector(`[name="${name}"]`);
        if (input) {
            input.checked = entries.some(([key]) => key === name);
        }
    });

    [
        'language',
        'scan_timeout',
        'max_retries',
        'threat_level',
        'subfinder_timeout',
        'amass_timeout',
        'gobuster_timeout',
        'httpx_timeout',
        'nuclei_timeout'
    ].forEach(name => {
        const input = form.querySelector(`[name="${name}"]`);
        const valueEntry = entries.find(([key]) => key === name);
        if (input && valueEntry) {
            input.value = valueEntry[1];
        }
    });

    hideAlerts();
}

function saveSettings() {
    const form = document.getElementById('settingsForm');
    if (!form) return;

    const formData = new FormData(form);
    hideAlerts();

    fetch('/update_settings', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            const alert = document.getElementById('success-alert');
            if (alert) {
                alert.style.display = 'block';
                setTimeout(() => {
                    alert.style.display = 'none';
                }, 2500);
            }
            setTimeout(() => window.location.reload(), 900);
        } else {
            const errorAlert = document.getElementById('error-alert');
            const errorText = document.getElementById('error-text');
            if (errorText) {
                errorText.textContent = data.message || 'Unable to save settings.';
            }
            if (errorAlert) {
                errorAlert.style.display = 'block';
            }
        }
    })
    .catch(error => {
        const errorAlert = document.getElementById('error-alert');
        const errorText = document.getElementById('error-text');
        if (errorText) {
            errorText.textContent = 'Network or server error while saving settings.';
        }
        if (errorAlert) {
            errorAlert.style.display = 'block';
        }
        console.error('Error:', error);
    });
}


document.addEventListener('DOMContentLoaded', function() {
    // --- 1. ELEMENT SELECTORS ---
    const reconForm = document.getElementById('reconForm');
    const fastRadio = document.getElementById('fast');
    const fullRadio = document.getElementById('full');
    const modulePanel = document.getElementById('module-selection');
    const toggleAll = document.getElementById('toggle-all');
    const moduleCheckboxes = document.querySelectorAll('.module-checkbox');
    const settingsForm = document.getElementById('settingsForm');

    // SELECTORS FOR BACKGROUND PROGRESS
    const statusContainer = document.getElementById('recon-status-container');
    const progressBar = document.getElementById('recon-progress-bar');
    const progressPercent = document.getElementById('progress-percent');
    const logArea = document.getElementById('system-logs-area');
    const activeTargetLabel = document.getElementById('active-target');
    const startBtn = document.getElementById('startBtn');

    // SELECTORS FOR RESULT CARDS
    const resSubdomains = document.getElementById('res-subdomains');
    const resHosts = document.getElementById('res-hosts');
    const resOsint = document.getElementById('res-osint');

    // --- NOTIFICATION FUNCTIONS FOR SCAN COMPLETION ---
    function notifyUser(target) {
        if (Notification.permission === "granted") {
            const noti = new Notification("ReconVault: Reconnaissance Complete", {
                body: `Comprehensive scan for ${target} has finished successfully. Review the generated report for detailed insights.`,
                icon: "/static/img/logo.png",
                tag: "recon-complete",
                requireInteraction: true,
                silent: false
            });
            noti.onclick = () => {
                window.focus();
                window.location.href = `/scan?target=${encodeURIComponent(target)}`;
            };
        }
    }

    function showCompletionModal(target) {
        const label = document.getElementById('scan-complete-target');
        if (label) label.textContent = target;
        openModal('modal-scan-complete');
    }

    function gotoReport() {
        const target = document.getElementById('scan-complete-target')?.textContent || '';
        if (target) {
            window.location.href = `/scan?target=${encodeURIComponent(target)}`;
        }
    }

    // --- 2. MODULE TOGGLE LOGIC ---
    function toggleModules() {
        if (fullRadio && modulePanel) {
            modulePanel.classList.toggle('d-none', !fullRadio.checked);
        }
    }

    if (fastRadio && fullRadio) {
        fastRadio.addEventListener('change', toggleModules);
        fullRadio.addEventListener('change', toggleModules);
    }

    if (toggleAll) {
        toggleAll.addEventListener('change', function() {
            moduleCheckboxes.forEach(checkbox => checkbox.checked = toggleAll.checked);
        });
    }

   

    // --- 4. REPORT MANAGEMENT LOGIC ---
    document.addEventListener('submit', function(e) {
        const targetForm = e.target;
        if (targetForm.classList.contains('delete-report-form')) {
            const targetName = targetForm.getAttribute('data-target');
            if (!confirm(`Are you sure you want to delete the report for ${targetName}?`)) {
                e.preventDefault();
            }
        }
        if (targetForm.id === 'purge-all-form') {
            if (!confirm("WARNING: This will permanently delete ALL your scan reports and files. Proceed?")) {
                e.preventDefault();
            }
        }
        });

    bindKaliPanelInput();
});


    // --- 4. Remote Kali LOGIC ---
function setCommand(value) {
    const input = document.getElementById('commandInput');
    if (!input) return;
    input.value = value;
    input.focus();
}

function bindKaliPanelInput() {
    const input = document.getElementById('commandInput');
    if (!input) return;

    input.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            runKaliShell();
        }
    });

    input.focus();
}
async function runKaliShell() {
    const input = document.getElementById('commandInput');
    const terminal = document.getElementById('terminalOutput');
    const cwdLabel = document.getElementById('cwdLabel');
    const shellStatus = document.getElementById('shellStatus');
    const runButton = document.getElementById('runCommandBtn');
    const root = document.getElementById('kaliPanelRoot');
    const command = input?.value.trim();

    if (!input || !terminal || !cwdLabel || !shellStatus || !runButton || !root || !command) return;

    const kaliUser = root.dataset.kaliUser || 'kali';
    const kaliHost = root.dataset.kaliHost || 'kali-host';

    terminal.textContent += `\n$ ${command}\n`;
    terminal.scrollTop = terminal.scrollHeight;

    shellStatus.textContent = 'Running...';
    runButton.disabled = true;

    try {
        const res = await fetch('/api/kali/shell', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command })
        });

        const data = await res.json();

        if (!data.ok) {
            terminal.textContent += `[ERROR] ${data.error}\n`;
            shellStatus.textContent = 'Failed';
        } else {
            if (data.output === '__CLEAR__') {
                terminal.textContent = '';
            } else {
                terminal.textContent += `${data.output || ''}\n`;
            }

            if (data.cwd) {
                cwdLabel.textContent = `${kaliUser}@${kaliHost}:${data.cwd}`;
            }

            shellStatus.textContent = 'Done';
        }
    } catch (err) {
        terminal.textContent += `[ERROR] ${err}\n`;
        shellStatus.textContent = 'Failed';
    }

    terminal.scrollTop = terminal.scrollHeight;
    input.value = '';
    input.focus();
    runButton.disabled = false;
}

// --- File upload sandbox---
function handleMalwareSubmit(form) {
    const button = form.querySelector('button[type="submit"]');
    if (!button) return true;

    button.disabled = true;
    button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Uploading to VirusTotal...';

    setTimeout(() => {
        button.disabled = false;
        button.innerHTML = 'Run virus scan';
    }, 8000);

    return true;
}

function toggleBannerHelp(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.toggle('show');
}

document.addEventListener('click', function(e) {
    if (!e.target.closest('.banner-help-wrap')) {
        document.querySelectorAll('.banner-help-pop.show').forEach(function(pop) {
            pop.classList.remove('show');
        });
    }
});




function enableDraggableProgressWidget() {
    const widget = document.getElementById('scan-progress-widget');
    if (!widget) return;

    const handle = document.getElementById('scan-progress-widget-handle') || widget;

    let isDragging = false;
    let startX = 0;
    let startY = 0;
    let startLeft = 0;
    let startTop = 0;

    function onMouseDown(e) {
        if (e.button !== 0) return; // left click only
        isDragging = true;
        widget.classList.add('dragging');

        const rect = widget.getBoundingClientRect();
        startLeft = rect.left;
        startTop = rect.top;
        startX = e.clientX;
        startY = e.clientY;

        // switch from right/bottom anchoring to left/top when user drags
        widget.style.left = `${startLeft}px`;
        widget.style.top = `${startTop}px`;
        widget.style.right = 'auto';
        widget.style.bottom = 'auto';

        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
    }

    function onMouseMove(e) {
        if (!isDragging) return;

        let nextLeft = startLeft + (e.clientX - startX);
        let nextTop = startTop + (e.clientY - startY);

        // keep inside viewport
        const rect = widget.getBoundingClientRect();
        const maxLeft = window.innerWidth - rect.width;
        const maxTop = window.innerHeight - rect.height;

        nextLeft = Math.max(0, Math.min(nextLeft, maxLeft));
        nextTop = Math.max(0, Math.min(nextTop, maxTop));

        widget.style.left = `${nextLeft}px`;
        widget.style.top = `${nextTop}px`;
    }

    function onMouseUp() {
        isDragging = false;
        widget.classList.remove('dragging');
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
    }

    handle.addEventListener('mousedown', onMouseDown);
}

document.addEventListener('DOMContentLoaded', enableDraggableProgressWidget);
