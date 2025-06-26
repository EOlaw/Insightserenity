// src/hooks/useAuth.ts
'use client';

import { useEffect, useState, useCallback, createContext, useContext, ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import { User } from '@/types/auth';
import { AuthService } from '@/lib/auth';
import { apiClient } from '@/lib/api';

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>;
  register: (data: any) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const refreshUser = useCallback(async () => {
    try {
      const validatedUser = await AuthService.validateSession();
      setUser(validatedUser);
    } catch (error) {
      setUser(null);
    }
  }, []);

  useEffect(() => {
    const initAuth = async () => {
      setIsLoading(true);
      try {
        if (AuthService.isAuthenticated()) {
          await refreshUser();
        }
      } finally {
        setIsLoading(false);
      }
    };

    initAuth();
  }, [refreshUser]);

  const login = async (email: string, password: string, rememberMe?: boolean) => {
    const response = await apiClient.login(email, password, rememberMe);
    if (response.success && response.data) {
      AuthService.saveTokens(response.data.tokens);
      AuthService.saveUser(response.data.user);
      setUser(response.data.user);
    }
  };

  const register = async (data: any) => {
    const response = await apiClient.register(data);
    if (response.success && response.data) {
      AuthService.saveTokens(response.data.tokens);
      AuthService.saveUser(response.data.user);
      setUser(response.data.user);
    }
  };

  const logout = async () => {
    try {
      await apiClient.logout();
    } finally {
      AuthService.clearAuth();
      setUser(null);
      router.push('/login');
    }
  };

  const value = {
    user,
    isLoading,
    isAuthenticated: !!user,
    login,
    register,
    logout,
    refreshUser,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}