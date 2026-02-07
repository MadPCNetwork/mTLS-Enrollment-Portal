/**
 * mTLS PKI Portal - Main Application
 * Handles OIDC authentication, API communication, and UI management.
 */

import {
    generateRSAKeyPair,
    generateCSR,
    generateStrongPassword,
    createPKCS12,
    downloadBlob,
} from './crypto/keygen.js';

// ============================================================================
// Configuration
// ============================================================================

// OIDC configuration - loaded from backend API and discovery document
const CONFIG = {
    oidcIssuer: '',
    oidcClientId: '',
    oidcRedirectUri: window.location.origin + '/callback',
    oidcScopes: 'openid profile email groups',
    // Endpoints from discovery document
    oidcAuthorizationEndpoint: '',
    oidcTokenEndpoint: '',
    apiBase: '/api/v1',
};

// ============================================================================
// State
// ============================================================================

let state = {
    user: null,
    accessToken: null,
    cas: [],
    requests: [],
    certificates: [],
    pendingApprovals: [],
    isAdmin: false,
    adminCertificates: [],
    adminTotal: 0,
    adminPage: 1,
    adminPageSize: 25,
    adminHasMore: false,
    adminSearch: '',
    adminStatusFilter: '',
    adminLoading: false,
    passwordSaved: false,  // Track if password was saved in generation flow
};

// Password modal state for confirmation dialogs
let isPasswordModalActive = false;
let passwordModalContent = '';
let passwordP12Blob = null;

// Search debounce timer
let adminSearchTimer = null;

// ============================================================================
// OIDC Authentication
// ============================================================================

/**
 * Initialize OIDC configuration from the backend API.
 * Backend fetches discovery document, avoiding CORS issues.
 */
async function initOIDC() {
    try {
        // Get OIDC config from backend (includes discovery endpoints)
        const response = await fetch('/api/v1/oidc-config');
        if (response.ok) {
            const config = await response.json();
            CONFIG.oidcIssuer = config.issuer;
            CONFIG.oidcClientId = config.client_id;
            CONFIG.oidcScopes = config.scopes;
            CONFIG.oidcAuthorizationEndpoint = config.authorization_endpoint;
            CONFIG.oidcTokenEndpoint = config.token_endpoint;

            console.log('OIDC config loaded:', {
                issuer: CONFIG.oidcIssuer,
                authorization: CONFIG.oidcAuthorizationEndpoint,
                token: CONFIG.oidcTokenEndpoint
            });
        }
    } catch (error) {
        console.error('Could not load OIDC config:', error);
    }
}

/**
 * Generate a random state for OIDC.
 */
function generateState() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate PKCE code verifier and challenge.
 */
async function generatePKCE() {
    // Generate code verifier
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const verifier = Array.from(array, b => b.toString(16).padStart(2, '0')).join('');

    // Generate code challenge
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const challenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');

    return { verifier, challenge };
}

/**
 * Start the OIDC login flow.
 */
async function login() {
    const loginBtn = document.getElementById('login-btn');
    
    // Ensure OIDC config is loaded
    if (!CONFIG.oidcAuthorizationEndpoint) {
        console.error('OIDC authorization endpoint not configured. Config:', CONFIG);
        showToast('OIDC not configured properly. Check backend logs.', 'error');
        return;
    }

    // Set loading state and persist it
    setButtonLoading(loginBtn, true, 'Redirecting...');
    sessionStorage.setItem('login_in_progress', 'true');

    try {
        const state = generateState();
        const { verifier, challenge } = await generatePKCE();

        // Store state and verifier
        sessionStorage.setItem('oidc_state', state);
        sessionStorage.setItem('oidc_verifier', verifier);

        // Build authorization URL using discovered endpoint
        const authUrl = new URL(CONFIG.oidcAuthorizationEndpoint);
        authUrl.searchParams.set('response_type', 'code');
        authUrl.searchParams.set('client_id', CONFIG.oidcClientId);
        authUrl.searchParams.set('redirect_uri', CONFIG.oidcRedirectUri);
        authUrl.searchParams.set('scope', CONFIG.oidcScopes);
        authUrl.searchParams.set('state', state);
        authUrl.searchParams.set('code_challenge', challenge);
        authUrl.searchParams.set('code_challenge_method', 'S256');

        console.log('Redirecting to:', authUrl.toString());

        // Redirect to OIDC provider (page will unload, so loading state will persist visually)
        window.location.href = authUrl.toString();
    } catch (error) {
        console.error('Login failed:', error);
        sessionStorage.removeItem('login_in_progress');
        setButtonLoading(loginBtn, false);
        showToast('Failed to initiate login', 'error');
    }
}

/**
 * Handle the OIDC callback.
 */
async function handleCallback() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const returnedState = params.get('state');
    const error = params.get('error');

    if (error) {
        console.error('OIDC error:', error, params.get('error_description'));
        hideLoadingOverlay();
        showToast('Authentication failed: ' + (params.get('error_description') || error), 'error');
        sessionStorage.removeItem('login_in_progress');
        window.history.replaceState({}, '', '/');
        return false;
    }

    if (!code) {
        return false;
    }

    // Loading overlay already shown in init() - just verify state and proceed

    // Verify state
    const savedState = sessionStorage.getItem('oidc_state');
    if (returnedState !== savedState) {
        console.error('State mismatch');
        hideLoadingOverlay();
        showToast('Authentication failed: state mismatch', 'error');
        // Clear state to prevent reuse
        sessionStorage.removeItem('oidc_state');
        sessionStorage.removeItem('oidc_verifier');
        sessionStorage.removeItem('login_in_progress');
        window.history.replaceState({}, '', '/');
        return false;
    }

    // Get verifier
    const verifier = sessionStorage.getItem('oidc_verifier');
    
    // Immediately clear state and verifier to prevent replay attacks
    sessionStorage.removeItem('oidc_state');
    sessionStorage.removeItem('oidc_verifier');

    try {
        // Exchange code for tokens using discovered endpoint
        const response = await fetch(CONFIG.oidcTokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: CONFIG.oidcRedirectUri,
                client_id: CONFIG.oidcClientId,
                code_verifier: verifier,
            }),
        });

        if (!response.ok) {
            throw new Error('Token exchange failed');
        }

        const tokens = await response.json();

        // Store tokens
        state.accessToken = tokens.access_token;
        sessionStorage.setItem('access_token', tokens.access_token);

        // Parse ID token for user info
        if (tokens.id_token) {
            const payload = JSON.parse(atob(tokens.id_token.split('.')[1]));
            state.user = {
                sub: payload.sub,
                email: payload.email,
                name: payload.name || payload.preferred_username || payload.email,
                groups: payload.groups || [],
            };
        }

        // Clean up (state and verifier already cleared above)
        sessionStorage.removeItem('login_in_progress');
        window.history.replaceState({}, '', '/');

        hideLoadingOverlay();
        return true;
    } catch (error) {
        console.error('Token exchange failed:', error);
        hideLoadingOverlay();
        showToast('Authentication failed', 'error');
        sessionStorage.removeItem('login_in_progress');
        window.history.replaceState({}, '', '/');
        return false;
    }
}

/**
 * Logout the user.
 */
function logout() {
    state.user = null;
    state.accessToken = null;
    sessionStorage.removeItem('access_token');
    showScreen('login');
}

/**
 * Check if user is authenticated.
 */
function isAuthenticated() {
    if (state.accessToken) return true;

    // Try to restore from session
    const token = sessionStorage.getItem('access_token');
    if (token) {
        state.accessToken = token;
        return true;
    }

    return false;
}

// ============================================================================
// API Client
// ============================================================================

/**
 * Make an authenticated API request.
 */
async function api(endpoint, options = {}) {
    const url = CONFIG.apiBase + endpoint;
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers,
    };

    if (state.accessToken) {
        headers['Authorization'] = `Bearer ${state.accessToken}`;
    }

    const response = await fetch(url, {
        ...options,
        headers,
    });

    if (response.status === 401) {
        logout();
        throw new Error('Session expired');
    }

    if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(error.detail || 'Request failed');
    }

    if (response.status === 204) {
        return null;
    }

    return response.json();
}

// ============================================================================
// Data Loading
// ============================================================================

async function loadCAs() {
    try {
        state.cas = await api('/cas');
        renderCAList();
    } catch (error) {
        console.error('Failed to load CAs:', error);
        // Re-throw transient errors so loadAllData can retry
        if (error.message && error.message.includes('OIDC provider unavailable')) throw error;
        showToast('Failed to load certificate authorities', 'error');
    }
}

async function loadRequests() {
    try {
        state.requests = await api('/requests');
        renderRequestsList();
    } catch (error) {
        console.error('Failed to load requests:', error);
        if (error.message && error.message.includes('OIDC provider unavailable')) throw error;
    }
}

async function loadCertificates() {
    try {
        state.certificates = await api('/certificates');
        renderCertificatesList();
    } catch (error) {
        console.error('Failed to load certificates:', error);
        if (error.message && error.message.includes('OIDC provider unavailable')) throw error;
    }
}

async function loadPendingApprovals() {
    try {
        state.pendingApprovals = await api('/pending');
        renderPendingList();
        updateApproveTab();
    } catch (error) {
        console.error('Failed to load pending approvals:', error);
        if (error.message && error.message.includes('OIDC provider unavailable')) throw error;
    }
}

async function checkIfAdmin() {
    try {
        const result = await api('/admin/is-admin');
        state.isAdmin = result.is_admin;
        updateAdminTab();
        if (state.isAdmin) {
            await loadAdminCertificates();
        }
    } catch (error) {
        console.error('Failed to check admin status:', error);
        if (error.message && error.message.includes('OIDC provider unavailable')) throw error;
        state.isAdmin = false;
    }
}

async function loadAdminCertificates(append = false) {
    if (state.adminLoading) return;

    state.adminLoading = true;
    renderAdminCertificatesList(); // Render loading state immediately

    try {
        const params = new URLSearchParams({
            page: state.adminPage.toString(),
            page_size: state.adminPageSize.toString(),
        });

        if (state.adminSearch) {
            params.set('search', state.adminSearch);
        }
        if (state.adminStatusFilter) {
            params.set('status_filter', state.adminStatusFilter);
        }

        const response = await api(`/admin/certificates?${params.toString()}`);

        if (append) {
            state.adminCertificates = [...state.adminCertificates, ...response.certificates];
        } else {
            state.adminCertificates = response.certificates;
        }

        state.adminTotal = response.total;
        state.adminHasMore = response.has_more;
        state.adminPage = response.page;

        renderAdminCertificatesList();
    } catch (error) {
        console.error('Failed to load admin certificates:', error);
        renderAdminCertificatesList(); // Render error/empty state
    } finally {
        state.adminLoading = false;
        renderAdminCertificatesList(); // Render final state
    }
}

// Reset to first page and reload
async function searchAdminCertificates() {
    state.adminPage = 1;
    state.adminCertificates = [];
    await loadAdminCertificates(false);
}

// Load next page of results
async function loadMoreAdminCertificates() {
    if (!state.adminHasMore || state.adminLoading) return;
    state.adminPage++;
    await loadAdminCertificates(true);
}

// Debounced search handler
window.handleAdminSearch = function (value) {
    state.adminSearch = value;

    // Clear previous timer
    if (adminSearchTimer) {
        clearTimeout(adminSearchTimer);
    }

    // Debounce the search
    adminSearchTimer = setTimeout(() => {
        searchAdminCertificates();
    }, 300);
};

// Status filter handler
window.handleAdminStatusFilter = function (value) {
    state.adminStatusFilter = value;
    searchAdminCertificates();
};

function updateAdminTab() {
    const tab = document.getElementById('admin-tab');
    if (state.isAdmin) {
        tab.classList.remove('hidden');
    } else {
        tab.classList.add('hidden');
    }
}

async function loadAllData(retries = 2) {
    try {
        await Promise.all([
            loadCAs(),
            loadRequests(),
            loadCertificates(),
            loadPendingApprovals(),
            checkIfAdmin(),
        ]);
    } catch (error) {
        // Retry on transient 503s (OIDC provider not yet available after login)
        if (retries > 0 && error.message && error.message.includes('OIDC provider unavailable')) {
            console.warn(`Data load failed with transient error, retrying in 1s... (${retries} retries left)`);
            await new Promise(resolve => setTimeout(resolve, 1000));
            return loadAllData(retries - 1);
        }
        console.error('Failed to load data:', error);
    }
}

// ============================================================================
// UI Rendering
// ============================================================================

function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    document.getElementById(screenId + '-screen').classList.add('active');
}

function showTab(tabId) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelector(`.tab[data-tab="${tabId}"]`).classList.add('active');
    document.getElementById(tabId + '-section').classList.add('active');
}

function updateUserInfo() {
    if (state.user) {
        document.getElementById('user-name').textContent = state.user.name;
        document.getElementById('user-avatar').textContent = (state.user.name || 'U')[0].toUpperCase();
    }
}

function updateApproveTab() {
    const tab = document.getElementById('approve-tab');
    const badge = document.getElementById('pending-count');

    // Check if user is an approver for any CA
    const isApprover = state.cas.some(ca => ca.can_approve);

    if (state.pendingApprovals.length > 0 || isApprover) {
        tab.classList.remove('hidden');
        badge.textContent = state.pendingApprovals.length;
    } else {
        tab.classList.add('hidden');
    }
}

function renderCAList() {
    const container = document.getElementById('ca-list');

    if (state.cas.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M12 2L4 5V11C4 16.55 7.84 21.74 12 23C16.16 21.74 20 16.55 20 11V5L12 2Z"/>
                </svg>
                <p>No certificate authorities available</p>
                <span>Contact your administrator for access</span>
            </div>
        `;
        return;
    }

    container.innerHTML = state.cas.map(ca => {
        // Check if there's already a pending request for this CA
        const pendingRequest = state.requests.find(req =>
            req.ca_id === ca.id &&
            (req.status === 'pending_approval' || req.status === 'approved_awaiting_gen')
        );

        const isPending = !!pendingRequest;
        let buttonText = 'Request Certificate';
        let buttonClass = 'btn-primary';
        let buttonDisabled = false;
        let quotaHtml = '';

        if (isPending) {
            buttonText = pendingRequest.status === 'approved_awaiting_gen' ? 'Ready to Generate' : 'Pending Approval';
            buttonClass = 'btn-secondary';
            buttonDisabled = true;
        } else if (ca.max_active_certs !== null && ca.max_active_certs !== undefined) {
            // Quota logic
            const usage = ca.active_cert_count || 0;
            const limit = ca.max_active_certs;
            const percent = Math.min((usage / limit) * 100, 100);

            let barClass = '';
            if (percent >= 100) barClass = 'danger';
            else if (percent >= 80) barClass = 'warning';

            // Check if blocked
            if (ca.quota_exceeded) {
                if (!ca.allow_request_over_quota) {
                    buttonText = 'Quota Reached';
                    buttonClass = 'btn-secondary';
                    buttonDisabled = true;
                } else {
                    buttonText = 'Request (Approval Required)';
                }
            }

            const graceHours = ca.renewal_grace_period_hours || 0;
            const certsInGrace = ca.certs_in_grace_period || 0;
            let graceHtml = '';
            if (graceHours > 0) {
                graceHtml = `
                    <div class="quota-grace-info">
                        <span class="quota-grace-label">Renewal window: ${formatTTL(graceHours)} before expiry</span>
                        ${certsInGrace > 0 ? `<span class="quota-grace-detail">${certsInGrace} cert(s) in renewal window (not counted against quota)</span>` : ''}
                    </div>
                `;
            }

            quotaHtml = `
                 <div class="quota-container">
                     <div class="quota-header">
                         <span class="quota-label">Active Certificates</span>
                         <span class="quota-value">${usage} / ${limit}</span>
                     </div>
                     <div class="quota-progress">
                         <div class="quota-progress-bar ${barClass}" style="width: ${percent}%"></div>
                     </div>
                     ${ca.quota_exceeded && !ca.allow_request_over_quota ?
                    `<div class="quota-error-text">Limit reached - revoke certificates to request more</div>` :
                    (ca.quota_exceeded ? `<div class="quota-warning-text">Limit reached - requests require manual approval</div>` : '')}
                     ${graceHtml}
                 </div>
             `;
        }

        return `
        <div class="card ca-card" data-ca-id="${ca.id}">
            <div class="card-header">
                <div>
                    <h3 class="card-title">${escapeHtml(ca.name)}</h3>
                    <p class="card-subtitle">${ca.auto_approve ? 'Auto-approved' : 'Requires approval'}</p>
                </div>
                <span class="status ${ca.auto_approve ? 'status-generated' : 'status-pending'}">
                    ${ca.auto_approve ? 'Instant' : 'Manual'}
                </span>
            </div>
            <div class="card-body">
                <div class="card-row">
                    <span class="card-label">Max TTL</span>
                    <span class="card-value">${formatTTL(ca.max_ttl_hours)}</span>
                </div>
                ${quotaHtml}
            </div>
            <div class="card-actions">
                <button class="btn ${buttonClass}" onclick="requestCertificate('${ca.id}', this)" ${buttonDisabled ? 'disabled' : ''}>
                    ${buttonText}
                </button>
            </div>
        </div>
    `}).join('');
}

function renderRequestsList() {
    // Combine with certificates view
    renderCertificatesList();
    // Also update CA list to reflect pending statuses
    renderCAList();
}

function renderCertificatesList() {
    const container = document.getElementById('certificates-list');

    // Merge requests and certificates
    const items = state.requests.map(req => {
        const cert = state.certificates.find(c => c.request_id === req.id);
        return { ...req, certificate: cert };
    });

    if (items.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M12 2L4 5V11C4 16.55 7.84 21.74 12 23C16.16 21.74 20 16.55 20 11V5L12 2Z"/>
                </svg>
                <p>No certificates yet</p>
                <span>Request a certificate to get started</span>
            </div>
        `;
        return;
    }

    container.innerHTML = items.map(item => {
        const statusClass = getStatusClass(item.status, item.certificate);
        const statusLabel = getStatusLabel(item.status, item.certificate);

        let actions = '';
        if (item.status === 'approved_awaiting_gen') {
            actions = `
                <button class="btn btn-primary" onclick="generateCertificate(${item.id}, this)">
                    Generate Identity
                </button>
            `;
        } else if (item.certificate && item.certificate.is_valid) {
            actions = `
                <button class="btn btn-danger" onclick="revokeCertificate(${item.certificate.id}, this)">
                    Revoke
                </button>
            `;
        }

        return `
            <div class="card">
                <div class="card-header">
                    <div>
                        <h3 class="card-title">${escapeHtml(item.ca_name)}</h3>
                        <p class="card-subtitle">Requested ${formatDate(item.created_at)}</p>
                    </div>
                    <span class="status ${statusClass}">${statusLabel}</span>
                </div>
                ${item.certificate ? `
                    <div class="card-body">
                        <div class="card-row">
                            <span class="card-label">Subject</span>
                            <span class="card-value">${escapeHtml(item.certificate.subject)}</span>
                        </div>
                        <div class="card-row">
                            <span class="card-label">Serial</span>
                            <span class="card-value">${escapeHtml(item.certificate.serial_number)}</span>
                        </div>
                        <div class="card-row">
                            <span class="card-label">Expires</span>
                            <span class="card-value">${formatDate(item.certificate.not_after)}</span>
                        </div>
                    </div>
                ` : ''}
                ${actions ? `<div class="card-actions">${actions}</div>` : ''}
            </div>
        `;
    }).join('');
}

function renderPendingList() {
    const container = document.getElementById('pending-list');

    if (state.pendingApprovals.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
                <p>No pending requests</p>
                <span>All caught up!</span>
            </div>
        `;
        return;
    }

    container.innerHTML = state.pendingApprovals.map(req => `
        <div class="card">
            <div class="card-header">
                <div>
                    <h3 class="card-title">${escapeHtml(req.user_display_name || req.user_email || req.user_id)}</h3>
                    <p class="card-subtitle">${escapeHtml(req.ca_name)}</p>
                </div>
                <span class="status status-pending">Pending</span>
            </div>
            <div class="card-body">
                <div class="card-row">
                    <span class="card-label">Requested</span>
                    <span class="card-value">${formatDate(req.created_at)}</span>
                </div>
                <div class="card-row">
                    <span class="card-label">TTL</span>
                    <span class="card-value">${formatTTL(req.requested_ttl_hours)}</span>
                </div>
            </div>
            <div class="card-actions">
                <button class="btn btn-success" onclick="approveRequest(${req.id}, this)">
                    Approve
                </button>
                <button class="btn btn-danger" onclick="denyRequest(${req.id}, this)">
                    Deny
                </button>
            </div>
        </div>
    `).join('');
}

function renderAdminCertificatesList() {
    const container = document.getElementById('admin-certificates-list');

    // Build the search/filter header
    const searchHeader = `
        <div class="admin-search-header">
            <div class="admin-search-row">
                <div class="admin-search-input-wrapper">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="11" cy="11" r="8"/>
                        <path d="m21 21-4.35-4.35"/>
                    </svg>
                    <input 
                        type="text" 
                        id="admin-search-input"
                        class="admin-search-input" 
                        placeholder="Search by user, email, subject, or serial..." 
                        value="${escapeHtml(state.adminSearch)}"
                        oninput="handleAdminSearch(this.value)"
                    />
                    ${state.adminSearch ? `
                        <button class="admin-search-clear" onclick="handleAdminSearch(''); document.getElementById('admin-search-input').value = '';">
                            ×
                        </button>
                    ` : ''}
                </div>
                <select class="admin-filter-select" onchange="handleAdminStatusFilter(this.value)">
                    <option value="" ${state.adminStatusFilter === '' ? 'selected' : ''}>All Certificates</option>
                    <option value="active" ${state.adminStatusFilter === 'active' ? 'selected' : ''}>Active</option>
                    <option value="revoked" ${state.adminStatusFilter === 'revoked' ? 'selected' : ''}>Revoked</option>
                    <option value="expired" ${state.adminStatusFilter === 'expired' ? 'selected' : ''}>Expired</option>
                </select>
            </div>
            <div class="admin-search-meta">
                ${state.adminLoading ?
            '<span class="admin-loading">Loading...</span>' :
            `<span>Showing ${state.adminCertificates.length} of ${state.adminTotal} certificates</span>`
        }
            </div>
        </div>
    `;

    if (state.adminCertificates.length === 0 && !state.adminLoading) {
        container.innerHTML = searchHeader + `
            <div class="empty-state">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M12 2L4 5V11C4 16.55 7.84 21.74 12 23C16.16 21.74 20 16.55 20 11V5L12 2Z"/>
                </svg>
                <p>${state.adminSearch ? 'No certificates match your search' : 'No certificates in the system'}</p>
                <span>${state.adminSearch ? 'Try adjusting your search criteria' : 'Users can request certificates from the Request tab'}</span>
            </div>
        `;
        return;
    }

    const loadMoreBtn = state.adminHasMore ? `
        <div class="admin-load-more">
            <button class="btn btn-secondary" onclick="loadMoreAdminCertificates()" ${state.adminLoading ? 'disabled' : ''}>
                ${state.adminLoading ? '<span class="spinner-sm"></span> Loading...' : 'Load More'}
            </button>
        </div>
    ` : '';

    container.innerHTML = searchHeader + `
        <table class="admin-table">
            <thead>
                <tr>
                    <th>User</th>
                    <th>CA</th>
                    <th>Subject</th>
                    <th>Serial</th>
                    <th>Expires</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${state.adminCertificates.map(cert => {
        const statusClass = cert.is_revoked ? 'status-revoked' :
            cert.is_expired ? 'status-expired' : 'status-generated';
        const statusLabel = cert.is_revoked ? 'Revoked' :
            cert.is_expired ? 'Expired' : 'Active';
        return `
                        <tr>
                            <td>
                                <strong>${escapeHtml(cert.user_display_name || cert.user_email || cert.user_id)}</strong>
                                ${cert.user_email ? `<br><small>${escapeHtml(cert.user_email)}</small>` : ''}
                            </td>
                            <td>${escapeHtml(cert.ca_name)}</td>
                            <td class="monospace">${escapeHtml(cert.subject)}</td>
                            <td class="monospace">${escapeHtml(cert.serial_number.substring(0, 16))}...</td>
                            <td>${formatDate(cert.not_after)}</td>
                            <td><span class="status ${statusClass}">${statusLabel}</span></td>
                            <td>
                                ${cert.is_valid ? `
                                    <button class="btn btn-danger btn-sm" onclick="adminRevokeCertificate(${cert.id}, '${escapeHtml(cert.user_display_name || cert.user_email || cert.user_id)}', this)">
                                        Revoke
                                    </button>
                                ` : '-'}
                            </td>
                        </tr>
                    `;
    }).join('')}
            </tbody>
        </table>
    ` + loadMoreBtn;
}

window.loadMoreAdminCertificates = loadMoreAdminCertificates;

window.adminRevokeCertificate = async function (certId, userName, buttonElement) {
    if (!confirm(`Are you sure you want to revoke the certificate for "${userName}"?\n\nThis action cannot be undone.`)) {
        return;
    }

    // Set loading state if button element is provided
    if (buttonElement) {
        setButtonLoading(buttonElement, true, 'Revoking...');
    }

    try {
        await api(`/admin/revoke/${certId}`, { method: 'POST' });
        showToast('Certificate revoked successfully', 'success');
        // Reload current view preserving search context
        await searchAdminCertificates();
    } catch (error) {
        showToast('Failed to revoke certificate: ' + error.message, 'error');
        if (buttonElement) {
            setButtonLoading(buttonElement, false);
        }
    }
};

// ============================================================================
// Actions
// ============================================================================



window.requestCertificate = function (caId) {
    showModal('request_confirmation', caId);
};

window.performRequest = async function (caId) {
    const confirmBtn = document.querySelector('.modal-actions .btn-primary');

    // Set loading state
    setButtonLoading(confirmBtn, true, 'Requesting...');

    try {
        const result = await api('/request', {
            method: 'POST',
            body: JSON.stringify({ ca_id: caId }),
        });

        closeModal();
        showToast('Certificate requested successfully', 'success');
        await loadAllData();
        showTab('certificates');

        // If auto-approved, prompt to generate immediately
        if (result.status === 'approved_awaiting_gen') {
            setTimeout(() => {
                showModal('generate', result.id);
            }, 300);
        }
    } catch (error) {
        showToast('Failed to request certificate: ' + error.message, 'error');
        // Reset button state on error
        setButtonLoading(confirmBtn, false);
    }
};

window.generateCertificate = async function (requestId, buttonElement) {
    // Set loading state if button element is provided
    if (buttonElement) {
        setButtonLoading(buttonElement, true, 'Loading...');
    }
    
    showModal('generate', requestId);
    
    // Reset button state after modal opens
    if (buttonElement) {
        setButtonLoading(buttonElement, false);
    }
};

window.revokeCertificate = async function (certId, buttonElement) {
    if (!confirm('Are you sure you want to revoke this certificate? This action cannot be undone.')) {
        return;
    }

    // Set loading state if button element is provided
    if (buttonElement) {
        setButtonLoading(buttonElement, true, 'Revoking...');
    }

    try {
        await api(`/revoke/${certId}`, { method: 'POST' });
        showToast('Certificate revoked', 'success');
        await loadAllData();
    } catch (error) {
        showToast('Failed to revoke certificate: ' + error.message, 'error');
        if (buttonElement) {
            setButtonLoading(buttonElement, false);
        }
    }
};

window.approveRequest = async function (requestId, buttonElement) {
    // Set loading state if button element is provided
    if (buttonElement) {
        setButtonLoading(buttonElement, true, 'Approving...');
    }

    try {
        await api(`/approve/${requestId}`, { method: 'POST' });
        showToast('Request approved', 'success');
        await loadPendingApprovals();
    } catch (error) {
        showToast('Failed to approve request: ' + error.message, 'error');
        if (buttonElement) {
            setButtonLoading(buttonElement, false);
        }
    }
};

window.denyRequest = async function (requestId, buttonElement) {
    const reason = prompt('Enter reason for denial (optional):');

    // Set loading state if button element is provided
    if (buttonElement) {
        setButtonLoading(buttonElement, true, 'Denying...');
    }

    try {
        await api(`/deny/${requestId}`, {
            method: 'POST',
            body: JSON.stringify({ reason }),
        });
        showToast('Request denied', 'success');
        await loadPendingApprovals();
    } catch (error) {
        showToast('Failed to deny request: ' + error.message, 'error');
        if (buttonElement) {
            setButtonLoading(buttonElement, false);
        }
    }
};

// ============================================================================
// Certificate Generation Flow
// ============================================================================

async function performCertificateGeneration(requestId) {
    const modalContent = document.getElementById('modal-content');

    try {
        // Step 1: Generate key pair
        updateGenerationStep(modalContent, 1, 'active');
        const keyPair = await generateRSAKeyPair();
        updateGenerationStep(modalContent, 1, 'complete');

        // Step 2: Generate CSR
        updateGenerationStep(modalContent, 2, 'active');
        const csrPem = await generateCSR(keyPair.privateKey, keyPair.publicKey);
        updateGenerationStep(modalContent, 2, 'complete');

        // Step 3: Submit CSR and get signed certificate
        updateGenerationStep(modalContent, 3, 'active');
        const signedResult = await api(`/sign/${requestId}`, {
            method: 'POST',
            body: JSON.stringify({ csr_pem: csrPem }),
        });
        updateGenerationStep(modalContent, 3, 'complete');

        // Step 4: Bundle into PKCS#12
        updateGenerationStep(modalContent, 4, 'active');
        const password = generateStrongPassword();
        const friendlyName = state.user.email || signedResult.subject || 'mTLS Identity';
        const p12Blob = await createPKCS12(
            keyPair.privateKey,
            signedResult.certificate_pem,
            signedResult.ca_chain_pem,
            password,
            friendlyName
        );
        updateGenerationStep(modalContent, 4, 'complete');

        // Show password and download
        showPasswordModal(password, p12Blob, signedResult.subject);

    } catch (error) {
        console.error('Certificate generation failed:', error);
        modalContent.innerHTML = `
            <div class="modal-title" style="color: var(--color-error);">Generation Failed</div>
            <div class="modal-body">
                <p>${escapeHtml(error.message)}</p>
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal()">Close</button>
            </div>
`;
    }
}

function updateGenerationStep(container, step, status) {
    const stepEl = container.querySelector(`.progress-step:nth-child(${step})`);
    if (stepEl) {
        stepEl.className = `progress-step ${status}`;
    }
}

function showPasswordModal(password, p12Blob, subject) {
    const modalContent = document.getElementById('modal-content');

    // Mark that we're in password display mode
    isPasswordModalActive = true;
    state.passwordSaved = false;

    // Store blob for going back functionality
    passwordP12Blob = p12Blob;

    const htmlContent = `
        <div class="modal-title">Certificate Generated Successfully!</div>
        <div class="modal-body">
            <div class="password-warning">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/>
                    <line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
                <span><strong>Save this password!</strong> It will only be shown once and is required to use your certificate.</span>
            </div>
            
            <div class="password-display">
                <code id="generated-password">${escapeHtml(password)}</code>
            </div>
            
            <p style="margin-bottom: var(--space-md); font-size: 0.875rem;">
                <strong>Subject:</strong> ${escapeHtml(subject)}
            </p>
        </div>
        <div class="modal-actions">
            <button class="btn btn-secondary" onclick="copyPassword()">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                </svg>
                Copy Password
            </button>
            <button class="btn btn-primary" id="download-btn">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                    <polyline points="7 10 12 15 17 10"/>
                    <line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                Download identity.p12
            </button>
        </div>
`;

    modalContent.innerHTML = htmlContent;

    // Store for going back functionality
    passwordModalContent = htmlContent;

    // Attach download handler
    document.getElementById('download-btn').onclick = () => {
        downloadBlob(p12Blob, 'identity.p12');
        state.passwordSaved = true;
        showToast('Certificate downloaded! Password marked as saved.', 'success');
        loadAllData();
    };
}

window.copyPassword = function () {
    const password = document.getElementById('generated-password').textContent;
    navigator.clipboard.writeText(password).then(() => {
        state.passwordSaved = true;
        showToast('Password copied to clipboard', 'success');
    });
};

// ============================================================================
// Modal
// ============================================================================

function showModal(type, data) {
    const overlay = document.getElementById('modal-overlay');
    const content = document.getElementById('modal-content');

    if (type === 'request_confirmation') {
        const ca = state.cas.find(c => c.id === data);
        content.innerHTML = `
            <div class="modal-title">Request Certificate</div>
            <div class="modal-body">
                <p>Are you sure you want to request a new certificate${ca ? ` from <strong>${escapeHtml(ca.name)}</strong>` : ''}?</p>
                <p style="color: var(--color-text-muted); margin-top: 0.5rem; font-size: 0.875rem;">
                    ${ca && ca.auto_approve ? 'This certificate will be auto-approved.' : 'This will send a request to the administrator for approval.'}
                </p> 
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button class="btn btn-primary" onclick="performRequest('${data}')">Confirm Request</button>
            </div>
        `;
        overlay.classList.add('active');
    } else if (type === 'generate') {
        // Reset password saved state
        state.passwordSaved = false;

        content.innerHTML = `
            <div class="modal-title">Generate Certificate</div>
            <div class="modal-body">
                <div class="confirmation-warning">
                    <div class="confirmation-warning-icon">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                        <span>Important: Please Read</span>
                    </div>
                    <div class="confirmation-warning-text">
                        <ul>
                            <li><strong>System-Specific Certificate:</strong> This certificate will be bound to your current system and browser. Make sure you are generating this on a device where you intend to use the certificate.</li>
                            <li><strong>One-Time Password:</strong> A secure password will be generated for your certificate. <strong>This password will only be displayed once</strong> and cannot be recovered.</li>
                            <li><strong>Secure Storage Required:</strong> You must save the password in a secure location (e.g., password manager) before closing the dialog.</li>
                        </ul>
                    </div>
                </div>
                
                <div class="confirmation-checkbox">
                    <input type="checkbox" id="confirm-understand" onchange="updateGenerateButton()">
                    <label for="confirm-understand">I understand that I am generating a certificate on this system, and I am prepared to securely save the password that will be displayed.</label>
                </div>
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button class="btn btn-primary" id="proceed-generate-btn" disabled onclick="startGeneration(${data})">Proceed with Generation</button>
            </div>
`;
    } else if (type === 'generating') {
        content.innerHTML = `
            <div class="modal-title">Generating Certificate</div>
        <div class="modal-body">
            <div class="progress-steps">
                <div class="progress-step active">
                    <div class="progress-step-icon">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                        </svg>
                    </div>
                    <span class="progress-step-label">Key Pair</span>
                </div>
                <div class="progress-step">
                    <div class="progress-step-icon">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                            <polyline points="14 2 14 8 20 8" />
                        </svg>
                    </div>
                    <span class="progress-step-label">CSR</span>
                </div>
                <div class="progress-step">
                    <div class="progress-step-icon">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 2L4 5V11C4 16.55 7.84 21.74 12 23C16.16 21.74 20 16.55 20 11V5L12 2Z" />
                        </svg>
                    </div>
                    <span class="progress-step-label">Sign</span>
                </div>
                <div class="progress-step">
                    <div class="progress-step-icon">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                            <polyline points="7 10 12 15 17 10" />
                            <line x1="12" y1="15" x2="12" y2="3" />
                        </svg>
                    </div>
                    <span class="progress-step-label">Bundle</span>
                </div>
            </div>
            <p style="text-align: center; color: var(--color-text-muted);">Please wait...</p>
        </div>
`;
        overlay.classList.add('active');

        // Start generation
        setTimeout(() => performCertificateGeneration(data), 100);
        return;
    }

    overlay.classList.add('active');
}

window.updateGenerateButton = function () {
    const checkbox = document.getElementById('confirm-understand');
    const button = document.getElementById('proceed-generate-btn');
    if (checkbox && button) {
        button.disabled = !checkbox.checked;
    }
};

window.startGeneration = function (requestId) {
    showModal('generating', requestId);
};

window.closeModal = function () {
    // Check if we're in password modal and password wasn't saved
    if (isPasswordModalActive && !state.passwordSaved) {
        showPasswordCloseConfirmation();
        return;
    }

    // Reset states
    isPasswordModalActive = false;
    state.passwordSaved = false;
    document.getElementById('modal-overlay').classList.remove('active');
};

function showPasswordCloseConfirmation() {
    const content = document.getElementById('modal-content');
    const currentContent = content.innerHTML;

    content.innerHTML = `
        <div class="modal-title">Are you sure?</div>
        <div class="modal-body">
            <div class="password-save-reminder">
                <div class="password-save-reminder-icon">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                    <span>Password Not Saved!</span>
                </div>
                <div class="password-save-reminder-text">
                    <p>It looks like you haven't copied or downloaded your password yet.</p>
                    <p><strong>Warning:</strong> The password will NOT be shown again. If you close this window without saving it, you will not be able to use your certificate.</p>
                </div>
            </div>
        </div>
        <div class="modal-actions">
            <button class="btn btn-secondary" onclick="goBackToPassword()">Go Back</button>
            <button class="btn btn-primary" onclick="confirmCloseWithoutPassword()">I've Saved The Password</button>
        </div>
    `;
}

window.goBackToPassword = function () {
    const content = document.getElementById('modal-content');
    content.innerHTML = passwordModalContent;

    // Reattach download handler
    if (passwordP12Blob) {
        document.getElementById('download-btn').onclick = () => {
            downloadBlob(passwordP12Blob, 'identity.p12');
            state.passwordSaved = true;
            loadAllData();
        };
    }
};

window.confirmCloseWithoutPassword = function () {
    state.passwordSaved = true;  // Mark as confirmed
    isPasswordModalActive = false;
    document.getElementById('modal-overlay').classList.remove('active');
    loadAllData();
};

// ============================================================================
// Utilities
// ============================================================================

/**
 * Set button loading state with spinner and optional text.
 * @param {HTMLButtonElement} button - The button element
 * @param {boolean} loading - Whether to show loading state
 * @param {string} [loadingText] - Optional text to show while loading
 */
function setButtonLoading(button, loading, loadingText = null) {
    if (!button) return;
    
    if (loading) {
        // Store original content
        button.dataset.originalContent = button.innerHTML;
        button.disabled = true;
        
        // Set loading content
        const text = loadingText || button.textContent;
        button.innerHTML = `<span class="spinner-sm"></span>${text}`;
    } else {
        // Restore original content
        if (button.dataset.originalContent) {
            button.innerHTML = button.dataset.originalContent;
            delete button.dataset.originalContent;
        }
        button.disabled = false;
    }
}

/**
 * Show a full-screen loading overlay with message.
 * @param {string} message - Loading message to display
 */
function showLoadingOverlay(message = 'Loading...') {
    let overlay = document.getElementById('loading-overlay');
    
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'loading-overlay';
        overlay.style.cssText = `
            position: fixed;
            inset: 0;
            background: rgba(10, 10, 15, 0.95);
            backdrop-filter: blur(8px);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            gap: 1rem;
        `;
        
        const spinner = document.createElement('div');
        spinner.className = 'spinner';
        
        const text = document.createElement('div');
        text.id = 'loading-overlay-text';
        text.style.cssText = `
            color: var(--color-text-secondary);
            font-size: 0.875rem;
        `;
        text.textContent = message;
        
        overlay.appendChild(spinner);
        overlay.appendChild(text);
        document.body.appendChild(overlay);
    } else {
        document.getElementById('loading-overlay-text').textContent = message;
        overlay.style.display = 'flex';
    }
}

/**
 * Hide the loading overlay.
 */
function hideLoadingOverlay() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
}

function formatTTL(hours) {
    if (hours >= 8760) {
        return Math.floor(hours / 8760) + ' year(s)';
    } else if (hours >= 720) {
        return Math.floor(hours / 720) + ' month(s)';
    } else if (hours >= 24) {
        return Math.floor(hours / 24) + ' day(s)';
    }
    return hours + ' hour(s)';
}

function getStatusClass(status, cert) {
    if (cert?.is_revoked) return 'status-revoked';
    if (cert?.is_expired) return 'status-expired';
    if (cert?.is_valid) return 'status-generated';

    switch (status) {
        case 'pending_approval': return 'status-pending';
        case 'approved_awaiting_gen': return 'status-approved';
        case 'generated': return 'status-generated';
        case 'revoked': return 'status-revoked';
        case 'denied': return 'status-denied';
        default: return '';
    }
}

function getStatusLabel(status, cert) {
    if (cert?.is_revoked) return 'Revoked';
    if (cert?.is_expired) return 'Expired';
    if (cert?.is_valid) return 'Active';

    switch (status) {
        case 'pending_approval': return 'Pending Approval';
        case 'approved_awaiting_gen': return 'Ready to Generate';
        case 'generated': return 'Generated';
        case 'revoked': return 'Revoked';
        case 'denied': return 'Denied';
        default: return status;
    }
}

function showToast(message, type = 'info') {
    // Simple toast implementation
    const toast = document.createElement('div');
    toast.style.cssText = `
position: fixed;
bottom: 20px;
right: 20px;
padding: 12px 24px;
background: ${type === 'error' ? 'var(--color-error)' : type === 'success' ? 'var(--color-success)' : 'var(--color-info)'};
color: white;
border-radius: 8px;
font-size: 14px;
z-index: 2000;
animation: fadeIn 0.3s ease;
`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// ============================================================================
// Initialization
// ============================================================================

async function init() {
    // Check for callback FIRST - show loading overlay immediately before anything renders
    if (window.location.search.includes('code=')) {
        showLoadingOverlay('Completing sign in...');
    }

    // Event listeners - Attach first so UI works even if API fails
    document.getElementById('login-btn').addEventListener('click', login);
    document.getElementById('logout-btn').addEventListener('click', logout);
    document.getElementById('modal-close').addEventListener('click', closeModal);

    // Tab switching
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            showTab(tab.dataset.tab);
        });
    });

    // Close modal on overlay click
    document.getElementById('modal-overlay').addEventListener('click', (e) => {
        if (e.target === e.currentTarget) {
            closeModal();
        }
    });

    // Initialize OIDC config
    await initOIDC();

    // Check for callback
    if (window.location.search.includes('code=')) {
        const success = await handleCallback();
        if (success) {
            showScreen('dashboard');
            updateUserInfo();
            await loadAllData();
            return;
        }
    }

    // Check if already authenticated
    if (isAuthenticated()) {
        showScreen('dashboard');
        // Try to get user info from token
        const token = state.accessToken;
        if (token) {
            try {
                const payload = JSON.parse(atob(token.split('.')[1]));
                state.user = {
                    sub: payload.sub,
                    email: payload.email,
                    name: payload.name || payload.preferred_username || payload.email,
                    groups: payload.groups || [],
                };
            } catch (e) {
                console.warn('Could not parse token');
            }
        }
        updateUserInfo();
        await loadAllData();
    } else {
        showScreen('login');
        
        // Restore login button loading state if login was in progress
        if (sessionStorage.getItem('login_in_progress')) {
            const loginBtn = document.getElementById('login-btn');
            setButtonLoading(loginBtn, true, 'Redirecting...');
        }
    }
}

// Start the app
document.addEventListener('DOMContentLoaded', init);
