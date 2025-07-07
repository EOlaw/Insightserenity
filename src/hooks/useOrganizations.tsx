// src/hooks/useOrganizations.tsx
'use client';

import { useEffect, useState, useCallback, createContext, useContext, ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import { 
  Organization, 
  CreateOrganizationData, 
  UpdateOrganizationData,
  OrganizationListResponse,
  OrganizationInvitation,
  OrganizationMember,
  OrganizationStats,
  OrganizationSearchFilters
} from '@/types/organization';
import { organizationApiClient } from '@/lib/organizations';

interface OrganizationsContextType {
  // State
  organizations: Organization[];
  currentOrganization: Organization | null;
  members: OrganizationMember[];
  invitations: OrganizationInvitation[];
  stats: OrganizationStats | null;
  isLoading: boolean;
  isCreating: boolean;
  isUpdating: boolean;
  error: string | null;
  
  // Pagination
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
    hasNext: boolean;
    hasPrev: boolean;
  } | null;

  // Organization CRUD
  createOrganization: (data: CreateOrganizationData) => Promise<Organization>;
  getOrganizations: (page?: number, limit?: number, filters?: OrganizationSearchFilters) => Promise<void>;
  getOrganization: (organizationId: string) => Promise<Organization>;
  getOrganizationBySlug: (slug: string) => Promise<Organization>;
  updateOrganization: (organizationId: string, data: UpdateOrganizationData) => Promise<Organization>;
  deleteOrganization: (organizationId: string) => Promise<void>;
  setCurrentOrganization: (organization: Organization | null) => void;
  
  // Team management
  getMembers: (organizationId: string) => Promise<void>;
  inviteMember: (organizationId: string, invitationData: { email: string; role: string; permissions?: string[] }) => Promise<OrganizationInvitation>;
  getInvitations: (organizationId: string) => Promise<void>;
  resendInvitation: (organizationId: string, invitationId: string) => Promise<void>;
  revokeInvitation: (organizationId: string, invitationId: string) => Promise<void>;
  acceptInvitation: (token: string) => Promise<Organization>;
  updateMemberRole: (organizationId: string, memberId: string, roleData: { role: string; permissions?: string[] }) => Promise<void>;
  removeMember: (organizationId: string, memberId: string) => Promise<void>;
  
  // Statistics and metrics
  getStats: (organizationId: string) => Promise<void>;
  refreshStats: () => Promise<void>;
  
  // Utilities
  clearError: () => void;
  refreshOrganizations: () => Promise<void>;
  searchOrganizations: (query: string, filters?: OrganizationSearchFilters) => Promise<Organization[]>;
}

const OrganizationsContext = createContext<OrganizationsContextType | undefined>(undefined);

export function OrganizationsProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  
  // State management
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [currentOrganization, setCurrentOrganization] = useState<Organization | null>(null);
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [invitations, setInvitations] = useState<OrganizationInvitation[]>([]);
  const [stats, setStats] = useState<OrganizationStats | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [isUpdating, setIsUpdating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pagination, setPagination] = useState<{
    page: number;
    limit: number;
    total: number;
    pages: number;
    hasNext: boolean;
    hasPrev: boolean;
  } | null>(null);

  // Helper function to handle errors
  const handleError = useCallback((error: any, operation: string) => {
    const errorMessage = error?.message || `Failed to ${operation}`;
    setError(errorMessage);
    console.error(`Organization ${operation} error:`, error);
  }, []);

  // Organization CRUD operations
  const createOrganization = useCallback(async (data: CreateOrganizationData): Promise<Organization> => {
    setIsCreating(true);
    setError(null);
    try {
      const response = await organizationApiClient.createOrganization(data);
      if (response.success && response.data) {
        const newOrganization = response.data;
        setOrganizations(prev => [newOrganization, ...prev]);
        setCurrentOrganization(newOrganization);
        return newOrganization;
      }
      throw new Error(response.error?.message || 'Failed to create organization');
    } catch (error: any) {
      handleError(error, 'create organization');
      throw error;
    } finally {
      setIsCreating(false);
    }
  }, [handleError]);

  const getOrganizations = useCallback(async (
    page = 1, 
    limit = 10, 
    filters?: OrganizationSearchFilters
  ) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await organizationApiClient.getOrganizations(page, limit, filters);
      if (response.success && response.data) {
        // Handle different response structures from backend
        if (Array.isArray(response.data)) {
          // Direct array response
          setOrganizations(response.data);
          setPagination(null);
        } else if (response.data.organizations && Array.isArray(response.data.organizations)) {
          // Structured response with organizations array
          setOrganizations(response.data.organizations);
          setPagination(response.data.pagination || null);
        } else if (response.data.data && Array.isArray(response.data.data)) {
          // Nested data structure
          setOrganizations(response.data.data);
          setPagination(response.data.pagination || null);
        } else {
          // Fallback: treat as empty array
          console.warn('Unexpected response structure:', response.data);
          setOrganizations([]);
          setPagination(null);
        }
      } else {
        setOrganizations([]);
        setPagination(null);
      }
    } catch (error: any) {
      handleError(error, 'fetch organizations');
      setOrganizations([]); // Ensure organizations is always an array
      setPagination(null);
    } finally {
      setIsLoading(false);
    }
  }, [handleError]);

  const getOrganization = useCallback(async (organizationId: string): Promise<Organization> => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await organizationApiClient.getOrganization(organizationId);
      if (response.success && response.data) {
        const organization = response.data;
        setCurrentOrganization(organization);
        
        // Update in the list if it exists
        setOrganizations(prev => 
          prev.map(org => org._id === organizationId ? organization : org)
        );
        
        return organization;
      }
      throw new Error(response.error?.message || 'Failed to fetch organization');
    } catch (error: any) {
      handleError(error, 'fetch organization');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [handleError]);

  const getOrganizationBySlug = useCallback(async (slug: string): Promise<Organization> => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await organizationApiClient.getOrganizationBySlug(slug);
      if (response.success && response.data) {
        const organization = response.data;
        setCurrentOrganization(organization);
        return organization;
      }
      throw new Error(response.error?.message || 'Failed to fetch organization');
    } catch (error: any) {
      handleError(error, 'fetch organization by slug');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [handleError]);

  const updateOrganization = useCallback(async (
    organizationId: string, 
    data: UpdateOrganizationData
  ): Promise<Organization> => {
    setIsUpdating(true);
    setError(null);
    try {
      const response = await organizationApiClient.updateOrganization(organizationId, data);
      if (response.success && response.data) {
        const updatedOrganization = response.data;
        
        // Update current organization if it's the one being updated
        if (currentOrganization?._id === organizationId) {
          setCurrentOrganization(updatedOrganization);
        }
        
        // Update in the list
        setOrganizations(prev => 
          prev.map(org => org._id === organizationId ? updatedOrganization : org)
        );
        
        return updatedOrganization;
      }
      throw new Error(response.error?.message || 'Failed to update organization');
    } catch (error: any) {
      handleError(error, 'update organization');
      throw error;
    } finally {
      setIsUpdating(false);
    }
  }, [currentOrganization, handleError]);

  const deleteOrganization = useCallback(async (organizationId: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await organizationApiClient.deleteOrganization(organizationId);
      if (response.success) {
        // Remove from list
        setOrganizations(prev => prev.filter(org => org._id !== organizationId));
        
        // Clear current organization if it was deleted
        if (currentOrganization?._id === organizationId) {
          setCurrentOrganization(null);
        }
      }
    } catch (error: any) {
      handleError(error, 'delete organization');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [currentOrganization, handleError]);

  // Team management
  const getMembers = useCallback(async (organizationId: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await organizationApiClient.getOrganizationMembers(organizationId);
      if (response.success && response.data) {
        setMembers(response.data);
      }
    } catch (error: any) {
      handleError(error, 'fetch members');
    } finally {
      setIsLoading(false);
    }
  }, [handleError]);

  const inviteMember = useCallback(async (
    organizationId: string, 
    invitationData: { email: string; role: string; permissions?: string[] }
  ): Promise<OrganizationInvitation> => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await organizationApiClient.inviteMember(organizationId, invitationData);
      if (response.success && response.data) {
        const invitation = response.data;
        setInvitations(prev => [invitation, ...prev]);
        return invitation;
      }
      throw new Error(response.error?.message || 'Failed to send invitation');
    } catch (error: any) {
      handleError(error, 'send invitation');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [handleError]);

  const getInvitations = useCallback(async (organizationId: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await organizationApiClient.getInvitations(organizationId);
      if (response.success && response.data) {
        setInvitations(response.data);
      }
    } catch (error: any) {
      handleError(error, 'fetch invitations');
    } finally {
      setIsLoading(false);
    }
  }, [handleError]);

  const resendInvitation = useCallback(async (organizationId: string, invitationId: string) => {
    setError(null);
    try {
      const response = await organizationApiClient.resendInvitation(organizationId, invitationId);
      if (response.success && response.data) {
        setInvitations(prev => 
          prev.map(inv => inv._id === invitationId ? response.data! : inv)
        );
      }
    } catch (error: any) {
      handleError(error, 'resend invitation');
    }
  }, [handleError]);

  const revokeInvitation = useCallback(async (organizationId: string, invitationId: string) => {
    setError(null);
    try {
      const response = await organizationApiClient.revokeInvitation(organizationId, invitationId);
      if (response.success) {
        setInvitations(prev => prev.filter(inv => inv._id !== invitationId));
      }
    } catch (error: any) {
      handleError(error, 'revoke invitation');
    }
  }, [handleError]);

  const acceptInvitation = useCallback(async (token: string): Promise<Organization> => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await organizationApiClient.acceptInvitation(token);
      if (response.success && response.data) {
        const organization = response.data;
        setCurrentOrganization(organization);
        
        // Add to organizations list if not already there
        setOrganizations(prev => {
          const exists = prev.find(org => org._id === organization._id);
          return exists ? prev : [organization, ...prev];
        });
        
        return organization;
      }
      throw new Error(response.error?.message || 'Failed to accept invitation');
    } catch (error: any) {
      handleError(error, 'accept invitation');
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [handleError]);

  const updateMemberRole = useCallback(async (
    organizationId: string, 
    memberId: string, 
    roleData: { role: string; permissions?: string[] }
  ) => {
    setError(null);
    try {
      const response = await organizationApiClient.updateMemberRole(organizationId, memberId, roleData);
      if (response.success && response.data) {
        setMembers(prev => 
          prev.map(member => member._id === memberId ? response.data! : member)
        );
      }
    } catch (error: any) {
      handleError(error, 'update member role');
    }
  }, [handleError]);

  const removeMember = useCallback(async (organizationId: string, memberId: string) => {
    setError(null);
    try {
      const response = await organizationApiClient.removeMember(organizationId, memberId);
      if (response.success) {
        setMembers(prev => prev.filter(member => member._id !== memberId));
      }
    } catch (error: any) {
      handleError(error, 'remove member');
    }
  }, [handleError]);

  // Statistics
  const getStats = useCallback(async (organizationId: string) => {
    setError(null);
    try {
      const response = await organizationApiClient.getOrganizationStats(organizationId);
      if (response.success && response.data) {
        setStats(response.data);
      }
    } catch (error: any) {
      handleError(error, 'fetch statistics');
    }
  }, [handleError]);

  const refreshStats = useCallback(async () => {
    if (currentOrganization) {
      await getStats(currentOrganization._id);
    }
  }, [currentOrganization, getStats]);

  // Utilities
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const refreshOrganizations = useCallback(async () => {
    if (pagination) {
      await getOrganizations(pagination.page, pagination.limit);
    } else {
      await getOrganizations();
    }
  }, [pagination, getOrganizations]);

  const searchOrganizations = useCallback(async (
    query: string, 
    filters?: OrganizationSearchFilters
  ): Promise<Organization[]> => {
    setError(null);
    try {
      const response = await organizationApiClient.searchOrganizations(query, filters);
      if (response.success && response.data) {
        return response.data.organizations;
      }
      return [];
    } catch (error: any) {
      handleError(error, 'search organizations');
      return [];
    }
  }, [handleError]);

  const value = {
    // State
    organizations,
    currentOrganization,
    members,
    invitations,
    stats,
    isLoading,
    isCreating,
    isUpdating,
    error,
    pagination,

    // Organization CRUD
    createOrganization,
    getOrganizations,
    getOrganization,
    getOrganizationBySlug,
    updateOrganization,
    deleteOrganization,
    setCurrentOrganization,

    // Team management
    getMembers,
    inviteMember,
    getInvitations,
    resendInvitation,
    revokeInvitation,
    acceptInvitation,
    updateMemberRole,
    removeMember,

    // Statistics
    getStats,
    refreshStats,

    // Utilities
    clearError,
    refreshOrganizations,
    searchOrganizations,
  };

  return (
    <OrganizationsContext.Provider value={value}>
      {children}
    </OrganizationsContext.Provider>
  );
}

export function useOrganizations() {
  const context = useContext(OrganizationsContext);
  if (context === undefined) {
    throw new Error('useOrganizations must be used within an OrganizationsProvider');
  }
  return context;
}