// Same-origin API client. The session lives in an httpOnly cookie set by the API, so no token is
// ever readable by (or stored in) JavaScript. The custom header is what the API requires on
// state-changing requests to reject cross-site form posts (CSRF).
import axios from 'axios';

export const api = axios.create({
  baseURL: '/api',
  headers: { 'X-Requested-With': 'soar' },
  timeout: 60000,
});

api.interceptors.response.use(
  (r) => r,
  (err) => {
    const url = err.config?.url || '';
    if (err.response?.status === 401 && !url.startsWith('/auth/login') && !url.startsWith('/auth/me')) {
      window.dispatchEvent(new Event('soar:unauthorized'));
    }
    return Promise.reject(err);
  },
);

/** Human-readable message from an axios error (FastAPI returns `detail` as string or list). */
export function errMsg(e) {
  const d = e?.response?.data?.detail;
  if (Array.isArray(d)) return d.map((x) => x.msg).join('; ');
  if (typeof d === 'string') return d;
  if (e?.response?.status === 429) return 'Too many attempts. Please wait and try again.';
  if (!e?.response) return 'Cannot reach the API. Is the backend running?';
  return e.message || 'Request failed';
}
