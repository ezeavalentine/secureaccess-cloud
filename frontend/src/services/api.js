import axios from 'axios';
export const api = axios.create({baseURL: '/api', withCredentials: true, timeout: 20000, headers: {'Content-Type': 'application/json', 'X-SecureAccess-CSRF': '1'}});
api.interceptors.response.use(r => r, error => {
  if (error.response?.status === 401 && !error.config?.url?.includes('/auth/login') && !error.config?.url?.includes('/auth/me')) window.dispatchEvent(new Event('secureaccess:unauthorized'));
  const detail = error.response?.data?.detail;
  const message = Array.isArray(detail) ? detail.map(item => item.msg).join('; ') : detail;
  return Promise.reject(new Error(message || (error.response ? 'Request failed' : 'Cannot connect to the API. Please check the backend.')));
});
const get = async (path, options) => (await api.get(path, options)).data;
const post = async (path, body, options) => (await api.post(path, body, options)).data;
export const authService = {
  login: (username, password, otp, recoveryCode) => post('/auth/login', {username, password, otp: otp || null, recovery_code: recoveryCode || null}),
  getCurrentUser: () => get('/auth/me'),
  logout: () => post('/auth/logout'),
  changePassword: data => post('/auth/password', data),
  setupMfa: currentPassword => post('/auth/mfa/setup', {current_password: currentPassword}),
  enableMfa: otp => post('/auth/mfa/enable', {otp}),
  verifyMfa: otp => post('/auth/mfa/verify', {otp}),
  recoveryCodes: data => post('/auth/mfa/recovery-codes', data),
};
export const requestService = {
  createRequest: (data, key) => post('/requests', data, {headers: {'Idempotency-Key': key}}),
  getRequests: params => get('/requests', {params}),
  cancel: id => post(`/requests/${id}/cancel`),
  evaluate: data => post('/requests/evaluate', data),
};
export const approvalService = {
  getPending: params => get('/approvals/pending', {params}),
  decide: (id, approved, reason) => post(`/approvals/${id}/decide`, {approved, reason}),
};
export const sessionService = {
  getActiveSessions: params => get('/sessions/active', {params}),
  history: params => get('/sessions/history', {params}),
  credentials: id => post(`/sessions/${id}/credentials`),
  console: id => post(`/sessions/${id}/console`),
  revokeSession: id => post(`/sessions/${id}/revoke`),
};
export const auditService = {
  getLogs: params => get('/audit/logs', {params}),
  getCloudTrail: () => get('/audit/cloudtrail'),
  verify: () => get('/audit/verify-chain'),
  exportLogs: () => get('/audit/export'),
};
export const userService = {
  list: params => get('/users', {params}),
  create: data => post('/users', data),
  update: async (id, data) => (await api.patch(`/users/${id}`, data)).data,
  updatePolicy: async (name, data) => (await api.patch(`/users/roles/${name}`, data)).data,
  roles: () => get('/users/roles/catalog'),
  accounts: () => get('/users/accounts/catalog'),
  entitlements: id => get(`/users/${id}/entitlements`),
  grant: (id, data) => post(`/users/${id}/entitlements`, data),
  revokeGrant: (id, data) => post(`/users/${id}/entitlements/revoke`, data),
  recover: (id, data) => post(`/users/${id}/recover`, data),
};

export function subscribeEvents(onRefresh, onExpired) {
  let socket, reconnect, stopped = false;
  const connect = () => {
    if (stopped) return;
    socket = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/events`);
    socket.onmessage = event => {if (JSON.parse(event.data).type === 'refresh') onRefresh();};
    socket.onclose = event => {
      if (stopped) return;
      if (event.code === 1008) {onExpired(); return;}
      reconnect = setTimeout(connect, 10000);
    };
    socket.onerror = () => socket.close();
  };
  connect();
  return () => {stopped = true; clearTimeout(reconnect); socket?.close();};
}
export const systemService = {
  health: () => get('/health'),
  status: () => get('/system/status'),
  notifications: () => get('/notifications'),
  read: id => post(`/notifications/${id}/read`),
};
