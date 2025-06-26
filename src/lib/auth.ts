// src/lib/auth.ts
import { apiClient } from './api';
import { User, AuthTokens } from '@/types/auth';

const TOKEN_KEY = 'accessToken';
const REFRESH_TOKEN_KEY = 'refreshToken';
const USER_KEY = 'user';

export class AuthService {
  static saveTokens(tokens: AuthTokens) {
    if (typeof window !== 'undefined') {
      localStorage.setItem(TOKEN_KEY, tokens.accessToken);
      localStorage.setItem(REFRESH_TOKEN_KEY, tokens.refreshToken);
      apiClient.setAccessToken(tokens.accessToken);
    }
  }

  static saveUser(user: User) {
    if (typeof window !== 'undefined') {
      localStorage.setItem(USER_KEY, JSON.stringify(user));
    }
  }

  static getUser(): User | null {
    if (typeof window === 'undefined') return null;
    
    const userStr = localStorage.getItem(USER_KEY);
    if (!userStr) return null;
    
    try {
      return JSON.parse(userStr);
    } catch {
      return null;
    }
  }

  static getAccessToken(): string | null {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem(TOKEN_KEY);
  }

  static getRefreshToken(): string | null {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem(REFRESH_TOKEN_KEY);
  }

  static clearAuth() {
    if (typeof window !== 'undefined') {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(REFRESH_TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
      apiClient.setAccessToken(null);
    }
  }

  static isAuthenticated(): boolean {
    return !!this.getAccessToken();
  }

  static async refreshAccessToken(): Promise<boolean> {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) return false;

    try {
      const response = await apiClient.refreshToken(refreshToken);
      if (response.success && response.data) {
        this.saveTokens(response.data.tokens);
        this.saveUser(response.data.user);
        return true;
      }
      return false;
    } catch (error) {
      this.clearAuth();
      return false;
    }
  }

  static async validateSession(): Promise<User | null> {
    try {
      const response = await apiClient.get<{ success: boolean; data: { user: User } }>('/auth/me');
      if (response.success && response.data) {
        this.saveUser(response.data.user);
        return response.data.user;
      }
      return null;
    } catch (error) {
      // Try to refresh token
      const refreshed = await this.refreshAccessToken();
      if (refreshed) {
        return this.getUser();
      }
      return null;
    }
  }
}