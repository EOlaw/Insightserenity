// src/lib/auth.ts
import { apiClient } from './api';
import { User, AuthTokens } from '@/types/auth';

const TOKEN_KEY = 'accessToken';
const REFRESH_TOKEN_KEY = 'refreshToken';
const USER_KEY = 'user';

export class AuthService {
  static saveTokens(tokens: AuthTokens | null) {
    if (typeof window !== 'undefined' && tokens && tokens.accessToken && tokens.refreshToken) {
      localStorage.setItem(TOKEN_KEY, tokens.accessToken);
      localStorage.setItem(REFRESH_TOKEN_KEY, tokens.refreshToken);
      apiClient.setAccessToken(tokens.accessToken);
    }
  }

  static saveUser(user: User | null) {
    if (typeof window !== 'undefined' && user) {
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
      if (response.success && response.data && response.data.tokens) {
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
      // Updated to use the correct users/me endpoint
      const response = await apiClient.get<{ success: boolean; data: { user: User } }>('/users/me');
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

  /**
   * Check if user needs email verification
   * @param user User object
   * @returns boolean indicating if verification is needed
   */
  static requiresEmailVerification(user: User | null): boolean {
    return user ? !user.isEmailVerified : false;
  }

  /**
   * Handle post-registration flow based on user state
   * @param user User object
   * @param tokens Authentication tokens (may be null)
   * @returns object with next action and redirect path
   */
  static getPostRegistrationFlow(user: User | null, tokens: AuthTokens | null) {
    if (!user) {
      return { action: 'error', redirect: '/auth/register' };
    }

    if (tokens && tokens.accessToken) {
      // Immediate authentication - user can proceed to dashboard
      return { action: 'authenticate', redirect: '/dashboard' };
    }

    if (this.requiresEmailVerification(user)) {
      // Email verification required
      return { action: 'verify_email', redirect: '/auth/verify-email' };
    }

    // Account created but additional setup may be required
    return { action: 'setup', redirect: '/auth/setup' };
  }
}