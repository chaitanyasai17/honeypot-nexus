// Honeypot Nexus - Central REST API Client

function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute('content') : '';
}

export async function apiRequest(endpoint, options = {}) {
  const headers = {
    'Accept': 'application/json',
    ...(options.headers || {})
  };

  const csrf = getCsrfToken();
  if (csrf && ['POST', 'PUT', 'DELETE', 'PATCH'].includes((options.method || 'GET').toUpperCase())) {
    headers['X-CSRFToken'] = csrf;
  }

  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }

  const response = await fetch(endpoint, {
    ...options,
    headers
  });

  if (response.status === 401) {
    window.location.href = '/auth/login?next=' + encodeURIComponent(window.location.pathname);
    throw new Error('Authentication required');
  }

  const data = await response.json();
  if (!response.ok) {
    const errorMsg = (data.error && data.error.message) ? data.error.message : 'API Request Failed';
    throw new Error(errorMsg);
  }

  return data;
}

export const API = {
  getSummary: (since = '24h') => apiRequest(`/api/dashboard/summary?since=${since}`),
  getEvents: (params = {}) => apiRequest('/api/events?' + new URLSearchParams(params).toString()),
  getEventById: (id) => apiRequest(`/api/events/${id}`),
  getAlerts: (params = {}) => apiRequest('/api/alerts?' + new URLSearchParams(params).toString()),
  ackAlert: (id) => apiRequest(`/api/alerts/${id}/acknowledge`, { method: 'POST' }),
  resolveAlert: (id) => apiRequest(`/api/alerts/${id}/resolve`, { method: 'POST' }),
  getAttackers: (params = {}) => apiRequest('/api/attackers?' + new URLSearchParams(params).toString()),
  getAttackerDetail: (id) => apiRequest(`/api/attackers/${id}`),
  getSessions: (params = {}) => apiRequest('/api/sessions?' + new URLSearchParams(params).toString()),
  getSessionDetail: (id) => apiRequest(`/api/sessions/${id}`),
  getRules: () => apiRequest('/api/detection/rules'),
  toggleRule: (id, enabled) => apiRequest(`/api/detection/rules/${id}`, { method: 'PUT', body: { enabled } }),
  getHealth: () => apiRequest('/api/system/health'),
  getSurfaces: () => apiRequest('/api/honeypot/status'),
  getAudit: (params = {}) => apiRequest('/api/audit?' + new URLSearchParams(params).toString()),
  getPreventionOverview: () => apiRequest('/api/prevention/overview'),
  getPreventionBlocks: (params = {}) => apiRequest('/api/prevention/blocks?' + new URLSearchParams(params).toString()),
  blockIp: (data) => apiRequest('/api/prevention/block', { method: 'POST', body: data }),
  unblockIp: (data) => apiRequest('/api/prevention/unblock', { method: 'POST', body: data }),
  getPreventionEvents: (limit = 50) => apiRequest(`/api/prevention/events?limit=${limit}`),
  runDemo: (scenario, intensity = 2) => apiRequest('/api/demo/run', { method: 'POST', body: { scenario, intensity } }),
  resetDemo: () => apiRequest('/api/demo/reset', { method: 'POST', body: { confirm: 'RESET' } }),
};

