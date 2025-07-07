// src/lib/organizations.ts
import { 
  Organization, 
  CreateOrganizationData, 
  UpdateOrganizationData,
  OrganizationListResponse,
  OrganizationInvitation,
  OrganizationMember,
  OrganizationStats,
  OrganizationSearchFilters,
  ApiResponse,
  ApiError
} from '@/types/organization';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5001/api';

export class OrganizationApiClient {
  private static instance: OrganizationApiClient;
  private accessToken: string | null = null;

  private constructor() {}

  static getInstance(): OrganizationApiClient {
    if (!OrganizationApiClient.instance) {
      OrganizationApiClient.instance = new OrganizationApiClient();
    }
    return OrganizationApiClient.instance;
  }

  setAccessToken(token: string | null) {
    this.accessToken = token;
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
  ): Promise<ApiResponse<T>> {
    // Use the internal API routes for frontend requests
    const url = `/api/hosted-organizations${endpoint}`;
    
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
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: 'Network error' }));
        throw {
          message: errorData.error?.message || errorData.message || 'An error occurred',
          code: errorData.error?.code || errorData.code,
          status: response.status,
          details: errorData.error?.details || errorData.details
        } as ApiError;
      }

      const data = await response.json();

      // Handle different response structures from backend
      if (data.status === 'success') {
        return {
          success: true,
          data: data.data || data,
          message: data.message
        };
      }

      return {
        success: true,
        data: data,
        message: data.message
      };
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

  // Organization CRUD operations
  async createOrganization(organizationData: CreateOrganizationData): Promise<ApiResponse<Organization>> {
    return this.request<Organization>('/organizations', {
      method: 'POST',
      body: JSON.stringify(organizationData)
    });
  }

  async getOrganizations(
    page = 1, 
    limit = 10, 
    filters?: OrganizationSearchFilters
  ): Promise<ApiResponse<OrganizationListResponse>> {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString()
    });

    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
          params.append(key, value.toString());
        }
      });
    }

    return this.request<OrganizationListResponse>(`/organizations?${params.toString()}`);
  }

  async getOrganization(organizationId: string): Promise<ApiResponse<Organization>> {
    return this.request<Organization>(`/organizations/${organizationId}`);
  }

  async getOrganizationBySlug(slug: string): Promise<ApiResponse<Organization>> {
    return this.request<Organization>(`/organizations/slug/${slug}`);
  }

  async updateOrganization(
    organizationId: string, 
    updateData: UpdateOrganizationData
  ): Promise<ApiResponse<Organization>> {
    return this.request<Organization>(`/organizations/${organizationId}`, {
      method: 'PATCH',
      body: JSON.stringify(updateData)
    });
  }

  async deleteOrganization(organizationId: string): Promise<ApiResponse<void>> {
    return this.request<void>(`/organizations/${organizationId}`, {
      method: 'DELETE'
    });
  }

  async archiveOrganization(organizationId: string): Promise<ApiResponse<Organization>> {
    return this.request<Organization>(`/organizations/${organizationId}/archive`, {
      method: 'PATCH'
    });
  }

  async restoreOrganization(organizationId: string): Promise<ApiResponse<Organization>> {
    return this.request<Organization>(`/organizations/${organizationId}/restore`, {
      method: 'PATCH'
    });
  }

  // Team management
  async getOrganizationMembers(organizationId: string): Promise<ApiResponse<OrganizationMember[]>> {
    return this.request<OrganizationMember[]>(`/organizations/${organizationId}/members`);
  }

  async inviteMember(
    organizationId: string, 
    invitationData: { email: string; role: string; permissions?: string[] }
  ): Promise<ApiResponse<OrganizationInvitation>> {
    return this.request<OrganizationInvitation>(`/organizations/${organizationId}/invite`, {
      method: 'POST',
      body: JSON.stringify(invitationData)
    });
  }

  async getInvitations(organizationId: string): Promise<ApiResponse<OrganizationInvitation[]>> {
    return this.request<OrganizationInvitation[]>(`/organizations/${organizationId}/invitations`);
  }

  async resendInvitation(
    organizationId: string, 
    invitationId: string
  ): Promise<ApiResponse<OrganizationInvitation>> {
    return this.request<OrganizationInvitation>(`/organizations/${organizationId}/invitations/${invitationId}/resend`, {
      method: 'POST'
    });
  }

  async revokeInvitation(
    organizationId: string, 
    invitationId: string
  ): Promise<ApiResponse<void>> {
    return this.request<void>(`/organizations/${organizationId}/invitations/${invitationId}`, {
      method: 'DELETE'
    });
  }

  async acceptInvitation(token: string): Promise<ApiResponse<Organization>> {
    return this.request<Organization>('/organizations/invitations/accept', {
      method: 'POST',
      body: JSON.stringify({ token })
    });
  }

  async updateMemberRole(
    organizationId: string, 
    memberId: string, 
    roleData: { role: string; permissions?: string[] }
  ): Promise<ApiResponse<OrganizationMember>> {
    return this.request<OrganizationMember>(`/organizations/${organizationId}/members/${memberId}`, {
      method: 'PATCH',
      body: JSON.stringify(roleData)
    });
  }

  async removeMember(organizationId: string, memberId: string): Promise<ApiResponse<void>> {
    return this.request<void>(`/organizations/${organizationId}/members/${memberId}`, {
      method: 'DELETE'
    });
  }

  // Subscription management
  async updateSubscription(
    organizationId: string, 
    subscriptionData: { plan: string; interval?: 'monthly' | 'yearly' }
  ): Promise<ApiResponse<Organization>> {
    return this.request<Organization>(`/organizations/${organizationId}/subscription`, {
      method: 'PATCH',
      body: JSON.stringify(subscriptionData)
    });
  }

  async cancelSubscription(organizationId: string): Promise<ApiResponse<Organization>> {
    return this.request<Organization>(`/organizations/${organizationId}/subscription/cancel`, {
      method: 'PATCH'
    });
  }

  async reactivateSubscription(organizationId: string): Promise<ApiResponse<Organization>> {
    return this.request<Organization>(`/organizations/${organizationId}/subscription/reactivate`, {
      method: 'PATCH'
    });
  }

  // Domain management
  async addCustomDomain(
    organizationId: string, 
    domainData: { domain: string; isPrimary?: boolean }
  ): Promise<ApiResponse<Organization>> {
    return this.request<Organization>(`/organizations/${organizationId}/domains`, {
      method: 'POST',
      body: JSON.stringify(domainData)
    });
  }

  async verifyDomain(organizationId: string, domain: string): Promise<ApiResponse<Organization>> {
    return this.request<Organization>(`/organizations/${organizationId}/domains/${domain}/verify`, {
      method: 'POST'
    });
  }

  async removeDomain(organizationId: string, domain: string): Promise<ApiResponse<Organization>> {
    return this.request<Organization>(`/organizations/${organizationId}/domains/${domain}`, {
      method: 'DELETE'
    });
  }

  async setPrimaryDomain(organizationId: string, domain: string): Promise<ApiResponse<Organization>> {
    return this.request<Organization>(`/organizations/${organizationId}/domains/${domain}/primary`, {
      method: 'PATCH'
    });
  }

  // Analytics and statistics
  async getOrganizationStats(organizationId: string): Promise<ApiResponse<OrganizationStats>> {
    return this.request<OrganizationStats>(`/organizations/${organizationId}/stats`);
  }

  async getUsageMetrics(
    organizationId: string, 
    period = '30d'
  ): Promise<ApiResponse<any>> {
    return this.request<any>(`/organizations/${organizationId}/usage?period=${period}`);
  }

  async getActivityFeed(
    organizationId: string, 
    limit = 20
  ): Promise<ApiResponse<any[]>> {
    return this.request<any[]>(`/organizations/${organizationId}/activity?limit=${limit}`);
  }

  // Branding and customization
  async updateBranding(
    organizationId: string, 
    brandingData: {
      logo?: string;
      favicon?: string;
      primaryColor?: string;
      secondaryColor?: string;
      theme?: string;
    }
  ): Promise<ApiResponse<Organization>> {
    return this.request<Organization>(`/organizations/${organizationId}/branding`, {
      method: 'PATCH',
      body: JSON.stringify(brandingData)
    });
  }

  async uploadLogo(organizationId: string, file: File): Promise<ApiResponse<{ url: string }>> {
    const formData = new FormData();
    formData.append('logo', file);

    return this.request<{ url: string }>(`/organizations/${organizationId}/branding/logo`, {
      method: 'POST',
      body: formData,
      headers: {} // Remove Content-Type to let browser set it for FormData
    });
  }

  // Settings management
  async updateSettings(
    organizationId: string, 
    settings: {
      security?: any;
      notifications?: any;
      integrations?: any;
    }
  ): Promise<ApiResponse<Organization>> {
    return this.request<Organization>(`/organizations/${organizationId}/settings`, {
      method: 'PATCH',
      body: JSON.stringify(settings)
    });
  }

  async getIntegrations(organizationId: string): Promise<ApiResponse<any[]>> {
    return this.request<any[]>(`/organizations/${organizationId}/integrations`);
  }

  async enableIntegration(
    organizationId: string, 
    integration: string, 
    config: Record<string, any>
  ): Promise<ApiResponse<any>> {
    return this.request<any>(`/organizations/${organizationId}/integrations/${integration}`, {
      method: 'POST',
      body: JSON.stringify({ config })
    });
  }

  async disableIntegration(organizationId: string, integration: string): Promise<ApiResponse<void>> {
    return this.request<void>(`/organizations/${organizationId}/integrations/${integration}`, {
      method: 'DELETE'
    });
  }

  // Search and discovery
  async searchOrganizations(
    query: string, 
    filters?: OrganizationSearchFilters
  ): Promise<ApiResponse<OrganizationListResponse>> {
    const params = new URLSearchParams({ q: query });
    
    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
          params.append(key, value.toString());
        }
      });
    }

    return this.request<OrganizationListResponse>(`/organizations/search?${params.toString()}`);
  }

  // Health checks
  async checkOrganizationHealth(organizationId: string): Promise<ApiResponse<any>> {
    return this.request<any>(`/organizations/${organizationId}/health`);
  }
}

// Export singleton instance
export const organizationApiClient = OrganizationApiClient.getInstance();