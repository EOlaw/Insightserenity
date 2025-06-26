// src/types/auth.ts
export interface User {
  _id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  organizations?: Organization[];
  emailVerified: boolean;
  active: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface Organization {
  organizationId: string;
  name: string;
  role: string;
  active: boolean;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface LoginCredentials {
  email: string;
  password: string;
  rememberMe?: boolean;
}

export interface RegisterData {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  organizationId?: string;
  acceptTerms: boolean;
}

export interface AuthResponse {
  success: boolean;
  data?: {
    user: User;
    tokens: AuthTokens;
  };
  error?: {
    message: string;
    code?: string;
  };
}

export interface ApiError {
  message: string;
  code?: string;
  status?: number;
}