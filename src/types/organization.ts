// src/types/organization.ts

export interface Organization {
  _id: string;
  platformId: string;
  tenantRef: string;
  tenantId: string;
  tenantCode: string;
  name: string;
  displayName?: string;
  legalName?: string;
  slug: string;
  businessInfo?: {
    registrationNumber?: string;
    taxId?: string;
    vatNumber?: string;
    businessType?: string;
    industry?: {
      primary?: {
        code: string;
        name: string;
        category: string;
      };
      secondary?: Array<{
        code: string;
        name: string;
        category: string;
      }>;
    };
    founded?: {
      year?: number;
      date?: string;
    };
  };
  headquarters?: {
    address?: {
      street?: string;
      city?: string;
      state?: string;
      country?: string;
      zipCode?: string;
      coordinates?: {
        latitude: number;
        longitude: number;
      };
    };
    phone?: string;
    email?: string;
    timezone?: string;
  };
  website?: string;
  description?: {
    short?: string;
    long?: string;
    mission?: string;
    vision?: string;
    values?: string[];
  };
  branding?: {
    logo?: string;
    favicon?: string;
    primaryColor?: string;
    secondaryColor?: string;
    theme?: string;
  };
  domains?: {
    subdomain: string;
    customDomains?: Array<{
      domain: string;
      verified: boolean;
      isPrimary: boolean;
      sslEnabled: boolean;
      addedAt: string;
    }>;
  };
  platformConfig?: {
    tier: 'starter' | 'growth' | 'professional' | 'enterprise' | 'custom';
    features?: {
      customBranding?: boolean;
      apiAccess?: boolean;
      ssoIntegration?: boolean;
      advancedAnalytics?: boolean;
      customIntegrations?: boolean;
      prioritySupport?: boolean;
    };
    limits?: {
      users?: number;
      projects?: number;
      storage?: number;
      apiCalls?: number;
      customDomains?: number;
    };
  };
  subscription?: {
    plan?: {
      id: string;
      name: string;
      interval: 'monthly' | 'yearly';
    };
    status: 'trial' | 'active' | 'past_due' | 'canceled' | 'unpaid';
    currentPeriodStart?: string;
    currentPeriodEnd?: string;
    trialEnd?: string;
    cancelAtPeriodEnd?: boolean;
  };
  team?: {
    owner: string;
    admins?: Array<{
      user: string;
      addedAt: string;
      addedBy: string;
    }>;
    members?: Array<{
      user: string;
      role: string;
      permissions?: string[];
      addedAt: string;
      addedBy: string;
    }>;
    invitations?: Array<{
      email: string;
      role: string;
      invitedBy: string;
      invitedAt: string;
      expiresAt: string;
      status: 'pending' | 'accepted' | 'expired' | 'revoked';
    }>;
  };
  integrations?: {
    emailProvider?: {
      provider: string;
      config: Record<string, any>;
      active: boolean;
    };
    paymentProvider?: {
      provider: string;
      config: Record<string, any>;
      active: boolean;
    };
    sso?: Array<{
      provider: string;
      config: Record<string, any>;
      active: boolean;
    }>;
    webhooks?: Array<{
      url: string;
      events: string[];
      active: boolean;
      secret?: string;
    }>;
  };
  settings?: {
    security?: {
      twoFactorRequired?: boolean;
      passwordPolicy?: {
        minLength: number;
        requireUppercase: boolean;
        requireLowercase: boolean;
        requireNumbers: boolean;
        requireSymbols: boolean;
      };
      sessionTimeout?: number;
      ipWhitelist?: string[];
    };
    notifications?: {
      email?: {
        newMembers: boolean;
        projectUpdates: boolean;
        billing: boolean;
        security: boolean;
      };
      slack?: {
        webhook?: string;
        channel?: string;
        events?: string[];
      };
    };
  };
  metrics?: {
    health?: {
      score?: number;
      factors?: {
        usage?: number;
        engagement?: number;
        growth?: number;
        retention?: number;
      };
      lastCalculated?: string;
    };
    usage?: {
      dailyActiveUsers?: Array<{ date: string; count: number }>;
      monthlyActiveUsers?: number;
      totalLogins?: number;
      lastActivity?: string;
    };
    performance?: {
      avgResponseTime?: number;
      uptime?: number;
      errorRate?: number;
    };
  };
  status?: {
    active: boolean;
    verified: boolean;
    locked: boolean;
    archived: boolean;
    deletionRequested: boolean;
    deletionScheduledFor?: string;
  };
  metadata?: {
    source?: string;
    referrer?: string;
    campaign?: string;
    tags?: string[];
    customAttributes?: Record<string, any>;
    notes?: Array<{
      content: string;
      createdBy: string;
      createdAt: string;
    }>;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  updatedBy?: string;
}

export interface CreateOrganizationData {
  name: string;
  displayName?: string;
  legalName?: string;
  businessInfo?: {
    registrationNumber?: string;
    taxId?: string;
    vatNumber?: string;
    businessType?: string;
    industry?: {
      primary?: {
        code: string;
        name: string;
        category: string;
      };
    };
  };
  headquarters?: {
    address?: {
      street?: string;
      city?: string;
      state?: string;
      country?: string;
      zipCode?: string;
    };
    phone?: string;
    email?: string;
    timezone?: string;
  };
  website?: string;
  description?: {
    short?: string;
    mission?: string;
  };
  platformConfig?: {
    tier?: 'starter' | 'growth' | 'professional' | 'enterprise';
  };
  domains?: {
    subdomain?: string;
  };
}

export interface UpdateOrganizationData extends Partial<CreateOrganizationData> {
  branding?: {
    logo?: string;
    favicon?: string;
    primaryColor?: string;
    secondaryColor?: string;
    theme?: string;
  };
  settings?: {
    security?: {
      twoFactorRequired?: boolean;
      passwordPolicy?: {
        minLength?: number;
        requireUppercase?: boolean;
        requireLowercase?: boolean;
        requireNumbers?: boolean;
        requireSymbols?: boolean;
      };
      sessionTimeout?: number;
    };
    notifications?: {
      email?: {
        newMembers?: boolean;
        projectUpdates?: boolean;
        billing?: boolean;
        security?: boolean;
      };
    };
  };
}

export interface OrganizationInvitation {
  _id: string;
  organization: string;
  email: string;
  role: string;
  permissions?: string[];
  invitedBy: {
    _id: string;
    firstName: string;
    lastName: string;
    email: string;
  };
  invitedAt: string;
  expiresAt: string;
  status: 'pending' | 'accepted' | 'expired' | 'revoked';
  acceptedAt?: string;
  token: string;
}

export interface OrganizationMember {
  _id: string;
  user: {
    _id: string;
    firstName: string;
    lastName: string;
    email: string;
    profile?: {
      avatar?: string;
      title?: string;
    };
  };
  role: string;
  permissions: string[];
  addedAt: string;
  addedBy: {
    _id: string;
    firstName: string;
    lastName: string;
  };
  lastActivity?: string;
  status: 'active' | 'inactive' | 'suspended';
}

export interface OrganizationStats {
  totalUsers: number;
  activeUsers: number;
  totalProjects: number;
  activeProjects: number;
  storageUsed: number;
  storageLimit: number;
  apiCallsUsed: number;
  apiCallsLimit: number;
  subscriptionStatus: string;
  trialDaysRemaining?: number;
}

export interface OrganizationSearchFilters {
  status?: 'active' | 'inactive' | 'trial' | 'suspended';
  tier?: string;
  industry?: string;
  country?: string;
  createdAfter?: string;
  createdBefore?: string;
}

export interface OrganizationListResponse {
  organizations: Organization[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
  filters?: OrganizationSearchFilters;
}

export interface ApiError {
  message: string;
  code?: string;
  status: number;
  details?: Record<string, any>;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: ApiError;
  message?: string;
}