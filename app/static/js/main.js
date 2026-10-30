/**
 * CloudAuditChain — Enterprise Cybersecurity SOC Client Controller
 * Production-grade interactivity: Toast notifications, clipboard engine,
 * real-time node telemetry, drag-and-drop file ingestion, and client filtering.
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize real-time node telemetry
    updateSystemHealth();

    // 2. Initialize Bootstrap tooltips with body container
    initTooltips();

    // 3. Initialize auto-dismiss for standard flash alerts
    initAlertDismissal();

    // 4. Initialize password toggles across auth screens
    initPasswordToggles();

    // 5. Initialize password strength meter if present
    initPasswordStrength();

    // 6. Initialize global form double-submission protection
    initFormSubmitSpinners();
});

/**
 * Initialize Bootstrap tooltips
 */
function initTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"], [title]'));
    tooltipTriggerList.forEach(el => {
        if (!el.getAttribute('data-bs-toggle')) {
            try {
                new bootstrap.Tooltip(el, { container: 'body', trigger: 'hover' });
            } catch (e) {}
        }
    });
}

/**
 * Auto-dismiss inline alerts
 */
function initAlertDismissal() {
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) bsAlert.close();
        }, 6000);
    });
}

/**
 * Enterprise Toast Notification System
 * @param {string} title
 * @param {string} message
 * @param {'success'|'danger'|'warning'|'info'} type
 * @param {number} duration
 */
function showToast(title, message, type = 'info', duration = 4000) {
    let container = document.getElementById('soc-toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'soc-toast-container';
        container.className = 'soc-toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = 'soc-toast';

    let iconHtml = '<i class="bi bi-info-circle-fill text-info fs-5"></i>';
    if (type === 'success') {
        iconHtml = '<i class="bi bi-check-circle-fill text-success fs-5"></i>';
    } else if (type === 'danger' || type === 'error') {
        iconHtml = '<i class="bi bi-exclamation-octagon-fill text-danger fs-5"></i>';
    } else if (type === 'warning') {
        iconHtml = '<i class="bi bi-exclamation-triangle-fill text-warning fs-5"></i>';
    }

    toast.innerHTML = `
        <div class="d-flex align-items-center">${iconHtml}</div>
        <div class="flex-grow-1" style="min-width: 0;">
            <div class="fw-semibold text-dark small mb-0">${title}</div>
            <div class="text-secondary" style="font-size: 0.78rem; word-break: break-all;">${message}</div>
        </div>
        <button type="button" class="btn-close btn-sm" aria-label="Close"></button>
    `;

    const closeBtn = toast.querySelector('.btn-close');
    closeBtn.addEventListener('click', () => {
        toast.remove();
    });

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.25s ease-out';
        setTimeout(() => toast.remove(), 250);
    }, duration);
}

/**
 * Universal Clipboard Copy Engine
 * @param {string} text - Exact string to copy
 * @param {HTMLElement|null} btn - Button element triggering the copy
 * @param {string} entityName - Name of entity for toast notification
 */
async function copyToClipboard(text, btn = null, entityName = 'Item') {
    if (!text) return;

    try {
        await navigator.clipboard.writeText(text);

        if (btn) {
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="bi bi-check2 text-success"></i>';
            btn.classList.add('text-success');
            setTimeout(() => {
                btn.innerHTML = originalHtml;
                btn.classList.remove('text-success');
            }, 1800);
        }

        const previewText = text.length > 32 ? text.substring(0, 16) + '...' + text.substring(text.length - 8) : text;
        showToast('Copied to Clipboard', `${entityName}: ${previewText}`, 'success', 3000);
    } catch (err) {
        console.error('Clipboard copy failed:', err);
        showToast('Copy Failed', 'Unable to copy text to clipboard', 'danger', 3000);
    }
}

/**
 * Fetch health status from /health API and update UI indicator
 */
async function updateSystemHealth() {
    const healthBadge = document.getElementById('navbar-health-badge');
    if (!healthBadge) return;

    try {
        const response = await fetch('/health');
        const data = await response.json();

        if (response.ok && data.status === 'healthy') {
            healthBadge.innerHTML = `
                <span class="status-dot active"></span>
                <span>Node Active • EVM 1337</span>
            `;
            healthBadge.className = 'node-telemetry-pill d-none d-sm-inline-flex';
            healthBadge.title = `Database: ${data.database} | Tables: ${data.tables ? data.tables.join(', ') : 'All'}`;
        } else {
            healthBadge.innerHTML = `
                <span class="status-dot danger"></span>
                <span>Degraded (${data.database || 'Error'})</span>
            `;
            healthBadge.className = 'node-telemetry-pill d-none d-sm-inline-flex';
        }
    } catch (err) {
        healthBadge.innerHTML = `
            <span class="status-dot pending"></span>
            <span>Checking Node...</span>
        `;
        healthBadge.className = 'node-telemetry-pill d-none d-sm-inline-flex';
    }
}

/**
 * Prevent duplicate form submissions with visual loading indicator
 */
function handleFormSubmitLoading(form, loadingText = 'Processing...') {
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.disabled = true;
        const originalHtml = submitBtn.innerHTML;
        submitBtn.setAttribute('data-original-html', originalHtml);
        submitBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>${loadingText}`;
    }
}

function initFormSubmitSpinners() {
    document.querySelectorAll('form[data-loading-text]').forEach(form => {
        form.addEventListener('submit', (e) => {
            const loadingText = form.getAttribute('data-loading-text') || 'Processing...';
            handleFormSubmitLoading(form, loadingText);
        });
    });
}

/**
 * Password Visibility Toggle
 */
function initPasswordToggles() {
    document.querySelectorAll('.password-toggle-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            const input = document.getElementById(targetId);
            if (!input) return;

            const icon = btn.querySelector('i');
            if (input.type === 'password') {
                input.type = 'text';
                if (icon) {
                    icon.classList.remove('bi-eye');
                    icon.classList.add('bi-eye-slash');
                }
                btn.setAttribute('aria-label', 'Hide password');
            } else {
                input.type = 'password';
                if (icon) {
                    icon.classList.remove('bi-eye-slash');
                    icon.classList.add('bi-eye');
                }
                btn.setAttribute('aria-label', 'Show password');
            }
        });
    });
}

/**
 * Password Strength Meter for Registration
 */
function initPasswordStrength() {
    const pwdInput = document.getElementById('reg-password');
    const segments = document.querySelectorAll('.strength-segment');
    const label = document.getElementById('pwd-strength-label');
    if (!pwdInput || !segments.length) return;

    pwdInput.addEventListener('input', () => {
        const val = pwdInput.value;
        let score = 0;

        if (val.length >= 8) score++;
        if (/[A-Z]/.test(val) && /[a-z]/.test(val)) score++;
        if (/[0-9]/.test(val)) score++;
        if (/[^A-Za-z0-9]/.test(val)) score++;

        segments.forEach((seg, idx) => {
            if (idx < score) {
                if (score <= 1) seg.style.background = 'var(--status-danger)';
                else if (score <= 2) seg.style.background = 'var(--status-pending)';
                else if (score === 3) seg.style.background = 'var(--accent-cyan)';
                else seg.style.background = 'var(--status-verified)';
            } else {
                seg.style.background = 'rgba(255, 255, 255, 0.1)';
            }
        });

        if (label) {
            if (val.length === 0) label.textContent = 'Minimum 8 characters';
            else if (score <= 1) label.textContent = 'Weak password';
            else if (score <= 2) label.textContent = 'Fair password';
            else if (score === 3) label.textContent = 'Strong password';
            else label.textContent = 'Very strong password';
        }
    });
}

/**
 * Drag & Drop File Zone Ingestion
 * @param {string} dropzoneId
 * @param {string} inputId
 * @param {string} feedbackId
 */
function setupDropzone(dropzoneId, inputId, feedbackId) {
    const dropzone = document.getElementById(dropzoneId);
    const input = document.getElementById(inputId);
    const feedback = document.getElementById(feedbackId);
    if (!dropzone || !input) return;

    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove('dragover');
        });
    });

    dropzone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length) {
            input.files = files;
            updateFileFeedback(files[0], feedback);
        }
    });

    dropzone.addEventListener('click', () => {
        input.click();
    });

    input.addEventListener('change', () => {
        if (input.files.length) {
            updateFileFeedback(input.files[0], feedback);
        }
    });
}

function updateFileFeedback(file, feedbackElement) {
    if (!file || !feedbackElement) return;
    const sizeKb = (file.size / 1024).toFixed(1);
    feedbackElement.innerHTML = `
        <div class="d-inline-flex align-items-center gap-2 px-3 py-1 rounded-pill bg-light border text-dark small">
            <i class="bi bi-file-earmark-check text-success"></i>
            <span class="fw-medium">${file.name}</span>
            <span class="text-secondary font-mono">(${sizeKb} KB)</span>
        </div>
    `;
}
