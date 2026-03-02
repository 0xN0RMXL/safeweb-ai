import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';

// ── Axios instance ──────────────────────────────────────────────────
const api = axios.create({
    baseURL: '/api',
    headers: { 'Content-Type': 'application/json' },
});

// ── Token helpers ───────────────────────────────────────────────────
export const getAccessToken = () => localStorage.getItem('access_token');
export const getRefreshToken = () => localStorage.getItem('refresh_token');
export const setTokens = (access: string, refresh: string) => {
    localStorage.setItem('access_token', access);
    localStorage.setItem('refresh_token', refresh);
};
export const clearTokens = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
};

// ── Request interceptor – attach JWT ────────────────────────────────
api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
    const token = getAccessToken();
    if (token && config.headers) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

// ── Response interceptor – auto-refresh on 401 ─────────────────────
let isRefreshing = false;
let failedQueue: { resolve: (v: unknown) => void; reject: (e: unknown) => void }[] = [];

const processQueue = (error: unknown) => {
    failedQueue.forEach((p) => (error ? p.reject(error) : p.resolve(undefined)));
    failedQueue = [];
};

api.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
        const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

        if (error.response?.status === 401 && !originalRequest._retry) {
            const refresh = getRefreshToken();
            if (!refresh) {
                clearTokens();
                window.location.href = '/login';
                return Promise.reject(error);
            }

            if (isRefreshing) {
                return new Promise((resolve, reject) => {
                    failedQueue.push({ resolve, reject });
                }).then(() => api(originalRequest));
            }

            originalRequest._retry = true;
            isRefreshing = true;

            try {
                const { data } = await axios.post('/api/auth/refresh/', { refresh });
                setTokens(data.access, data.refresh || refresh);
                processQueue(null);
                return api(originalRequest);
            } catch (refreshError) {
                processQueue(refreshError);
                clearTokens();
                window.location.href = '/login';
                return Promise.reject(refreshError);
            } finally {
                isRefreshing = false;
            }
        }

        return Promise.reject(error);
    },
);

// ── Auth endpoints ──────────────────────────────────────────────────
export const authAPI = {
    register: (data: { name: string; email: string; password: string; confirmPassword: string }) =>
        api.post('/auth/register/', data),

    login: (data: { email: string; password: string; rememberMe?: boolean }) =>
        api.post('/auth/login/', data),

    logout: (refresh: string) =>
        api.post('/auth/logout/', { refresh }),

    verify: () => api.get('/auth/verify/'),

    refresh: (refresh: string) =>
        api.post('/auth/refresh/', { refresh }),

    forgotPassword: (email: string) =>
        api.post('/auth/forgot-password/', { email }),

    resetPassword: (data: { token: string; password: string }) =>
        api.post('/auth/reset-password/', data),

    googleAuth: (token: string) =>
        api.post('/auth/google/', { token }),
};

// ── User / Profile endpoints ────────────────────────────────────────
export const userAPI = {
    getProfile: () => api.get('/user/profile/'),

    updateProfile: (data: Record<string, unknown>) =>
        api.patch('/user/profile/', data),

    changePassword: (data: { currentPassword: string; newPassword: string; confirmPassword: string }) =>
        api.post('/auth/change-password/', data),

    getAPIKeys: () => api.get('/user/profile/api-keys/'),

    createAPIKey: (name: string) =>
        api.post('/user/profile/api-keys/', { name }),

    deleteAPIKey: (id: string) =>
        api.delete(`/user/profile/api-keys/${id}/`),

    getSessions: () => api.get('/user/profile/sessions/'),

    enable2FA: () => api.post('/user/profile/2fa/enable/'),

    verify2FA: (token: string) =>
        api.post('/user/profile/2fa/verify/', { token }),
};

// ── Scan endpoints ──────────────────────────────────────────────────
export const scanAPI = {
    scanWebsite: (data: {
        url: string;
        scanDepth: string;
        includeSubdomains: boolean;
        checkSsl: boolean;
        followRedirects: boolean;
    }) => api.post('/scan/website/', data),

    scanFile: (formData: FormData) =>
        api.post('/scan/file/', formData, {
            headers: { 'Content-Type': 'multipart/form-data' },
        }),

    scanUrl: (url: string) =>
        api.post('/scan/url/', { url }),

    getResults: (id: string) =>
        api.get(`/scan/${id}/`),

    getList: (params?: Record<string, string>) =>
        api.get('/scans/', { params }),

    deleteScan: (id: string) =>
        api.delete(`/scan/${id}/delete/`),

    rescan: (id: string) =>
        api.post(`/scan/${id}/rescan/`),

    exportScan: (id: string, format: string) =>
        api.get(`/scan/${id}/export/`, {
            params: { export_format: format },
            responseType: format === 'json' ? 'json' : 'blob',
        }),
};

// ── Dashboard ───────────────────────────────────────────────────────
export const dashboardAPI = {
    get: () => api.get('/dashboard/'),
};

// ── Chat endpoints ──────────────────────────────────────────────────
export const chatAPI = {
    send: (data: { message: string; sessionId?: string; scanId?: string }) =>
        api.post('/chat/', data),

    getSessions: () => api.get('/chat/sessions/'),

    getSession: (id: string) =>
        api.get(`/chat/sessions/${id}/`),

    deleteSession: (id: string) =>
        api.delete(`/chat/sessions/${id}/`),
};

// ── Admin endpoints ─────────────────────────────────────────────────
export const adminAPI = {
    getDashboard: (params?: Record<string, string>) =>
        api.get('/admin/dashboard/', { params }),

    getUsers: (params?: Record<string, string>) =>
        api.get('/admin/users/', { params }),

    createUser: (data: Record<string, unknown>) =>
        api.post('/admin/users/', data),

    updateUser: (id: string, data: Record<string, unknown>) =>
        api.patch(`/admin/users/${id}/`, data),

    deleteUser: (id: string) =>
        api.delete(`/admin/users/${id}/`),

    getScans: (params?: Record<string, string>) =>
        api.get('/admin/scans/', { params }),

    deleteScan: (id: string) =>
        api.delete(`/admin/scans/${id}/`),

    getML: () => api.get('/admin/ml/'),

    trainModel: (modelType: string) =>
        api.post('/admin/ml/', { type: modelType }),

    getSettings: () => api.get('/admin/settings/'),

    updateSettings: (data: Record<string, unknown>) =>
        api.put('/admin/settings/', data),

    // Contact message management
    getContacts: (params?: Record<string, string>) =>
        api.get('/admin/contacts/', { params }),

    replyContact: (id: string, data: { reply?: string; is_read?: boolean }) =>
        api.patch(`/admin/contacts/${id}/`, data),

    deleteContact: (id: string) =>
        api.delete(`/admin/contacts/${id}/`),

    // Job application management
    getApplications: (params?: Record<string, string>) =>
        api.get('/admin/applications/', { params }),

    updateApplication: (id: string, data: { status?: string; admin_notes?: string }) =>
        api.patch(`/admin/applications/${id}/`, data),

    deleteApplication: (id: string) =>
        api.delete(`/admin/applications/${id}/`),
};

// ── Learn endpoints ─────────────────────────────────────────────────
export const learnAPI = {
    getArticles: (params?: Record<string, string>) =>
        api.get('/learn/articles/', { params }),

    getArticle: (slug: string) =>
        api.get(`/learn/articles/${slug}/`),
};

// ── Contact endpoints ───────────────────────────────────────────────
export const contactAPI = {
    send: (data: { name: string; email: string; subject: string; message: string }) =>
        api.post('/contact/', data),
};

// ── Careers endpoints ───────────────────────────────────────────────
export const careersAPI = {
    apply: (data: {
        position: string;
        name: string;
        email: string;
        phone?: string;
        coverLetter?: string;
        resumeUrl?: string;
        portfolioUrl?: string;
    }) => api.post('/careers/apply/', data),
};

export default api;
