// src/lib/api.ts
import { AuthResponse, ApiError } from '@/types/auth';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5001/api';

export class ApiClient {
  private static instance: ApiClient;
  private accessToken: string | null = null;

  private constructor() {}

  static getInstance(): ApiClient {
    if (!ApiClient.instance) {
      ApiClient.instance = new ApiClient();
    }
    return ApiClient.instance;
  }

  setAccessToken(token: string | null) {
    this.accessToken = token;
    if (typeof window !== 'undefined') {
      if (token) {
        localStorage.setItem('accessToken', token);
      } else {
        localStorage.removeItem('accessToken');
      }
    }
  }

  getAccessToken(): string | null {
    if (typeof window !== 'undefined' && !this.accessToken) {
      this.accessToken = localStorage.getItem('accessToken');
    }
    return this.accessToken;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    // Use the internal API routes for frontend requests
    const url = `/api${endpoint}`;
    
    const config: RequestInit = {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      credentials: 'include', // Include cookies for authentication
    };

    try {
      const response = await fetch(url, config);
      const data = await response.json();

      if (!response.ok) {
        throw {
          message: data.error?.message || 'An error occurred',
          code: data.error?.code,
          status: response.status,
        } as ApiError;
      }

      return data;
    } catch (error) {
      if (error instanceof Error) {
        throw {
          message: error.message,
          status: 500,
        } as ApiError;
      }
      throw error;
    }
  }

  // Auth endpoints
  async login(email: string, password: string, rememberMe?: boolean): Promise<AuthResponse> {
    return this.request<AuthResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, rememberMe }),
    });
  }

  async register(data: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    acceptTerms: boolean;
  }): Promise<AuthResponse> {
    return this.request<AuthResponse>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async logout(): Promise<void> {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } finally {
      this.setAccessToken(null);
      if (typeof window !== 'undefined') {
        localStorage.removeItem('refreshToken');
      }
    }
  }

  async refreshToken(refreshToken: string): Promise<AuthResponse> {
    return this.request<AuthResponse>('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refreshToken }),
    });
  }

  async forgotPassword(email: string): Promise<{ success: boolean; message: string }> {
    return this.request('/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  async resetPassword(token: string, newPassword: string): Promise<{ success: boolean }> {
    return this.request('/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, newPassword, confirmPassword: newPassword }),
    });
  }

  async verifyEmail(token: string): Promise<{ success: boolean }> {
    return this.request('/auth/verify-email', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  async resendVerificationEmail(email: string): Promise<{ success: boolean }> {
    return this.request('/auth/resend-verification', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  // User endpoints
  async getCurrentUser(): Promise<{ success: boolean; data: { user: any } }> {
    return this.request('/users/me');
  }

  async updateCurrentUser(data: any): Promise<{ success: boolean; data: { user: any } }> {
    return this.request('/users/me', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async getUser(id: string): Promise<{ success: boolean; data: { user: any } }> {
    return this.request(`/users/${id}`);
  }

  async updateUser(id: string, data: any): Promise<{ success: boolean; data: { user: any } }> {
    return this.request(`/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async deleteUser(id: string): Promise<{ success: boolean }> {
    return this.request(`/users/${id}`, {
      method: 'DELETE',
    });
  }

  // Dashboard endpoints
  async getDashboardData(): Promise<{ success: boolean; data: any }> {
    return this.request('/dashboard');
  }

  async getDashboardStats(): Promise<{ success: boolean; data: { stats: any } }> {
    return this.request('/dashboard/stats');
  }

  // Projects endpoints
  async getProjects(params?: Record<string, any>): Promise<{
    success: boolean;
    results: number;
    pagination: any;
    data: { projects: any[] };
  }> {
    const queryParams = params ? new URLSearchParams(params).toString() : '';
    return this.request(`/projects${queryParams ? `?${queryParams}` : ''}`);
  }

  async getProject(id: string): Promise<{ success: boolean; data: { project: any } }> {
    return this.request(`/projects/${id}`);
  }

  async getProjectDashboard(id: string): Promise<{ success: boolean; data: { dashboard: any } }> {
    return this.request(`/projects/${id}/dashboard`);
  }

  async createProject(projectData: any): Promise<{ success: boolean; data: { project: any } }> {
    return this.request('/projects', {
      method: 'POST',
      body: JSON.stringify(projectData),
    });
  }

  async updateProject(id: string, projectData: any): Promise<{ success: boolean; data: { project: any } }> {
    return this.request(`/projects/${id}`, {
      method: 'PUT',
      body: JSON.stringify(projectData),
    });
  }

  async deleteProject(id: string): Promise<{ success: boolean }> {
    return this.request(`/projects/${id}`, {
      method: 'DELETE',
    });
  }

  async getProjectStats(params?: Record<string, any>): Promise<{ success: boolean; data: { stats: any } }> {
    const queryParams = params ? new URLSearchParams(params).toString() : '';
    return this.request(`/projects/stats${queryParams ? `?${queryParams}` : ''}`);
  }

  async getProjectsByClient(clientId: string, params?: Record<string, any>): Promise<{
    success: boolean;
    data: { projects: any[] };
  }> {
    const queryParams = params ? new URLSearchParams(params).toString() : '';
    return this.request(`/projects/by-client/${clientId}${queryParams ? `?${queryParams}` : ''}`);
  }

  async archiveProject(id: string, reason: string): Promise<{ success: boolean; data: { project: any } }> {
    return this.request(`/projects/${id}/archive`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  }

  async generateProjectReport(id: string, options?: any): Promise<{ success: boolean; data: any }> {
    return this.request(`/projects/${id}/reports/status`, {
      method: 'GET',
      headers: {
        ...options,
      },
    });
  }

  async exportProject(id: string, format: string = 'json'): Promise<{ success: boolean; data: any }> {
    return this.request(`/projects/${id}/export?format=${format}`);
  }

  // Clients endpoints
  async getClients(params?: Record<string, any>): Promise<{
    success: boolean;
    results: number;
    pagination: any;
    data: { clients: any[] };
  }> {
    const queryParams = params ? new URLSearchParams(params).toString() : '';
    return this.request(`/clients${queryParams ? `?${queryParams}` : ''}`);
  }

  async getClient(id: string, options?: Record<string, any>): Promise<{ success: boolean; data: { client: any } }> {
    const queryParams = options ? new URLSearchParams(options).toString() : '';
    return this.request(`/clients/${id}${queryParams ? `?${queryParams}` : ''}`);
  }

  async getClientByCode(code: string): Promise<{ success: boolean; data: { client: any } }> {
    return this.request(`/clients/code/${code}`);
  }

  async createClient(clientData: any): Promise<{ success: boolean; data: { client: any } }> {
    return this.request('/clients', {
      method: 'POST',
      body: JSON.stringify(clientData),
    });
  }

  async updateClient(id: string, clientData: any): Promise<{ success: boolean; data: { client: any } }> {
    return this.request(`/clients/${id}`, {
      method: 'PUT',
      body: JSON.stringify(clientData),
    });
  }

  async deleteClient(id: string): Promise<{ success: boolean }> {
    return this.request(`/clients/${id}`, {
      method: 'DELETE',
    });
  }

  async getClientStats(params?: Record<string, any>): Promise<{ success: boolean; data: { stats: any } }> {
    const queryParams = params ? new URLSearchParams(params).toString() : '';
    return this.request(`/clients/stats${queryParams ? `?${queryParams}` : ''}`);
  }

  async searchClients(query: string, filters?: Record<string, any>): Promise<{
    success: boolean;
    results: number;
    data: { clients: any[] };
  }> {
    const params = { q: query, ...filters };
    const queryParams = new URLSearchParams(params).toString();
    return this.request(`/clients/search?${queryParams}`);
  }

  async getHighRiskClients(params?: Record<string, any>): Promise<{
    success: boolean;
    data: { clients: any[] };
  }> {
    const queryParams = params ? new URLSearchParams(params).toString() : '';
    return this.request(`/clients/high-risk${queryParams ? `?${queryParams}` : ''}`);
  }

  async updateClientStatus(id: string, status: string, reason?: string): Promise<{
    success: boolean;
    data: { client: any };
  }> {
    return this.request(`/clients/${id}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status, reason }),
    });
  }

  async suspendClient(id: string, reason: string): Promise<{ success: boolean; data: { client: any } }> {
    return this.request(`/clients/${id}/suspend`, {
      method: 'PUT',
      body: JSON.stringify({ reason }),
    });
  }

  async exportClients(params?: Record<string, any>): Promise<{ success: boolean; data: any }> {
    const queryParams = params ? new URLSearchParams(params).toString() : '';
    return this.request(`/clients/export${queryParams ? `?${queryParams}` : ''}`);
  }

  // Team endpoints
  async getTeamMembers(params?: Record<string, any>): Promise<{
    success: boolean;
    results: number;
    data: { users: any[] };
  }> {
    const queryParams = params ? new URLSearchParams(params).toString() : '';
    return this.request(`/users/team${queryParams ? `?${queryParams}` : ''}`);
  }

  async getAllUsers(params?: Record<string, any>): Promise<{
    success: boolean;
    results: number;
    pagination: any;
    data: { users: any[] };
  }> {
    const queryParams = params ? new URLSearchParams(params).toString() : '';
    return this.request(`/users${queryParams ? `?${queryParams}` : ''}`);
  }

  async getUserStats(): Promise<{ success: boolean; data: { stats: any } }> {
    return this.request('/users/stats/overview');
  }

  async inviteTeamMember(inviteData: {
    email: string;
    role: string;
    firstName: string;
    lastName: string;
  }): Promise<{ success: boolean; data: any }> {
    return this.request('/users/invite', {
      method: 'POST',
      body: JSON.stringify(inviteData),
    });
  }

  async updateUserRole(id: string, role: string): Promise<{ success: boolean; data: { user: any } }> {
    return this.request(`/users/${id}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role }),
    });
  }

  async updateUserStatus(id: string, status: string): Promise<{ success: boolean; data: { user: any } }> {
    return this.request(`/users/${id}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status }),
    });
  }

  // Reports endpoints
  async getReports(type?: string, params?: Record<string, any>): Promise<{
    success: boolean;
    data: { reports: any[] };
  }> {
    const queryParams = new URLSearchParams({ ...(type && { type }), ...params }).toString();
    return this.request(`/reports${queryParams ? `?${queryParams}` : ''}`);
  }

  async generateReport(reportConfig: {
    type: string;
    parameters: Record<string, any>;
    format?: string;
  }): Promise<{ success: boolean; data: any }> {
    return this.request('/reports/generate', {
      method: 'POST',
      body: JSON.stringify(reportConfig),
    });
  }

  async getReport(id: string): Promise<{ success: boolean; data: { report: any } }> {
    return this.request(`/reports/${id}`);
  }

  async downloadReport(id: string, format: string = 'pdf'): Promise<{ success: boolean; data: any }> {
    return this.request(`/reports/${id}/download?format=${format}`);
  }

  // Analytics endpoints
  async getAnalytics(type: string, params?: Record<string, any>): Promise<{
    success: boolean;
    data: any;
  }> {
    const queryParams = params ? new URLSearchParams(params).toString() : '';
    return this.request(`/analytics/${type}${queryParams ? `?${queryParams}` : ''}`);
  }

  async getProjectAnalytics(id: string, timeRange?: string): Promise<{
    success: boolean;
    data: any;
  }> {
    const params = timeRange ? `?timeRange=${timeRange}` : '';
    return this.request(`/analytics/projects/${id}${params}`);
  }

  async getClientAnalytics(id: string, timeRange?: string): Promise<{
    success: boolean;
    data: any;
  }> {
    const params = timeRange ? `?timeRange=${timeRange}` : '';
    return this.request(`/analytics/clients/${id}${params}`);
  }

  // Notifications endpoints
  async getNotifications(params?: Record<string, any>): Promise<{
    success: boolean;
    data: { notifications: any[] };
  }> {
    const queryParams = params ? new URLSearchParams(params).toString() : '';
    return this.request(`/notifications${queryParams ? `?${queryParams}` : ''}`);
  }

  async markNotificationAsRead(id: string): Promise<{ success: boolean }> {
    return this.request(`/notifications/${id}/read`, {
      method: 'PUT',
    });
  }

  async markAllNotificationsAsRead(): Promise<{ success: boolean }> {
    return this.request('/notifications/read-all', {
      method: 'PUT',
    });
  }

  async deleteNotification(id: string): Promise<{ success: boolean }> {
    return this.request(`/notifications/${id}`, {
      method: 'DELETE',
    });
  }

  // File upload helper
  async uploadFile(file: File, endpoint: string, additionalData?: Record<string, any>): Promise<{
    success: boolean;
    data: any;
  }> {
    const formData = new FormData();
    formData.append('file', file);
    
    if (additionalData) {
      Object.entries(additionalData).forEach(([key, value]) => {
        formData.append(key, value as string);
      });
    }

    const url = `/api${endpoint}`;
    const response = await fetch(url, {
      method: 'POST',
      body: formData,
      credentials: 'include',
    });

    const data = await response.json();

    if (!response.ok) {
      throw {
        message: data.error?.message || 'Upload failed',
        status: response.status,
      } as ApiError;
    }

    return data;
  }

  async uploadAvatar(file: File): Promise<{ success: boolean; data: { avatarUrl: string } }> {
    return this.uploadFile(file, '/users/me/avatar');
  }

  async uploadProjectDocument(projectId: string, file: File, documentType?: string): Promise<{
    success: boolean;
    data: any;
  }> {
    return this.uploadFile(file, `/projects/${projectId}/documents`, {
      ...(documentType && { type: documentType }),
    });
  }

  async uploadClientDocument(clientId: string, file: File, documentType?: string): Promise<{
    success: boolean;
    data: any;
  }> {
    return this.uploadFile(file, `/clients/${clientId}/documents`, {
      ...(documentType && { type: documentType }),
    });
  }

  // Generic CRUD methods for extensibility
  async get<T>(endpoint: string, params?: Record<string, any>): Promise<T> {
    const queryParams = params ? new URLSearchParams(params).toString() : '';
    return this.request<T>(`${endpoint}${queryParams ? `?${queryParams}` : ''}`, { method: 'GET' });
  }

  async post<T>(endpoint: string, data?: any): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async put<T>(endpoint: string, data?: any): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async patch<T>(endpoint: string, data?: any): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'PATCH',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async delete<T>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, { method: 'DELETE' });
  }
}

export const apiClient = ApiClient.getInstance();