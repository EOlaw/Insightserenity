// src/components/organizations/OrganizationList.tsx
'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useOrganizations } from '@/hooks/useOrganizations';
import { Organization, OrganizationSearchFilters } from '@/types/organization';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

interface OrganizationListProps {
  showCreateButton?: boolean;
  onSelectOrganization?: (organization: Organization) => void;
  filters?: OrganizationSearchFilters;
  limit?: number;
}

export function OrganizationList({ 
  showCreateButton = true,
  onSelectOrganization,
  filters,
  limit = 10
}: OrganizationListProps) {
  const router = useRouter();
  const {
    organizations,
    pagination,
    isLoading,
    error,
    getOrganizations,
    searchOrganizations,
    clearError
  } = useOrganizations();

  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<Organization[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [currentFilters, setCurrentFilters] = useState<OrganizationSearchFilters>(filters || {});
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    loadOrganizations();
  }, [currentPage, currentFilters, limit]);

  const loadOrganizations = async () => {
    try {
      await getOrganizations(currentPage, limit, currentFilters);
    } catch (error) {
      console.error('Failed to load organizations:', error);
    }
  };

  const handleSearch = async (query: string) => {
    setSearchQuery(query);
    
    if (!query.trim()) {
      setSearchResults([]);
      setIsSearching(false);
      return;
    }

    setIsSearching(true);
    try {
      const results = await searchOrganizations(query, currentFilters);
      setSearchResults(results);
    } catch (error) {
      console.error('Search failed:', error);
    } finally {
      setIsSearching(false);
    }
  };

  const handleFilterChange = (filterKey: keyof OrganizationSearchFilters, value: string) => {
    const newFilters = {
      ...currentFilters,
      [filterKey]: value || undefined
    };
    setCurrentFilters(newFilters);
    setCurrentPage(1);
  };

  const handleOrganizationClick = (organization: Organization) => {
    if (onSelectOrganization) {
      onSelectOrganization(organization);
    } else {
      router.push(`/organizations/${organization._id}`);
    }
  };

  const handlePageChange = (page: number) => {
    setCurrentPage(page);
  };

  const displayOrganizations = searchQuery ? searchResults : (organizations || []);

  const formatStatus = (organization: Organization) => {
    if (!organization.status?.active) return 'Inactive';
    if (organization.subscription?.status === 'trial') return 'Trial';
    if (organization.subscription?.status === 'active') return 'Active';
    if (organization.subscription?.status === 'past_due') return 'Past Due';
    if (organization.subscription?.status === 'canceled') return 'Canceled';
    return 'Unknown';
  };

  const getStatusColor = (organization: Organization) => {
    const status = formatStatus(organization);
    switch (status) {
      case 'Active': return 'text-green-600 bg-green-100';
      case 'Trial': return 'text-blue-600 bg-blue-100';
      case 'Past Due': return 'text-yellow-600 bg-yellow-100';
      case 'Canceled': 
      case 'Inactive': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const formatTier = (tier: string) => {
    return tier.charAt(0).toUpperCase() + tier.slice(1);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Organizations</h1>
          <p className="text-gray-600">Manage your organizations and their settings</p>
        </div>
        {showCreateButton && (
          <Button
            onClick={() => router.push('/organizations/create')}
            className="flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Create Organization
          </Button>
        )}
      </div>

      {/* Search and Filters */}
      <Card>
        <CardContent className="p-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-2">
              <Input
                type="text"
                placeholder="Search organizations..."
                value={searchQuery}
                onChange={(e) => handleSearch(e.target.value)}
                className="w-full"
              />
            </div>
            <div>
              <select
                value={currentFilters.status || ''}
                onChange={(e) => handleFilterChange('status', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">All Statuses</option>
                <option value="active">Active</option>
                <option value="trial">Trial</option>
                <option value="inactive">Inactive</option>
                <option value="suspended">Suspended</option>
              </select>
            </div>
            <div>
              <select
                value={currentFilters.tier || ''}
                onChange={(e) => handleFilterChange('tier', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">All Tiers</option>
                <option value="starter">Starter</option>
                <option value="growth">Growth</option>
                <option value="professional">Professional</option>
                <option value="enterprise">Enterprise</option>
              </select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Error Alert */}
      {error && (
        <Alert type="error" onClose={clearError}>
          {error}
        </Alert>
      )}

      {/* Loading State */}
      {(isLoading || isSearching) && (
        <div className="flex justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        </div>
      )}

      {/* Empty State */}
      {!isLoading && !isSearching && displayOrganizations.length === 0 && (
        <Card>
          <CardContent className="text-center py-12">
            <div className="text-gray-400 mb-4">
              <svg className="w-16 h-16 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
              </svg>
            </div>
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              {searchQuery ? 'No organizations found' : 'No organizations yet'}
            </h3>
            <p className="text-gray-600 mb-6">
              {searchQuery 
                ? 'Try adjusting your search terms or filters'
                : 'Get started by creating your first organization'
              }
            </p>
            {showCreateButton && !searchQuery && (
              <Button onClick={() => router.push('/organizations/create')}>
                Create Your First Organization
              </Button>
            )}
          </CardContent>
        </Card>
      )}

      {/* Organizations Grid */}
      {!isLoading && !isSearching && displayOrganizations.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {displayOrganizations.map((organization) => (
            <Card 
              key={organization._id} 
              className="cursor-pointer hover:shadow-lg transition-shadow duration-200"
              onClick={() => handleOrganizationClick(organization)}
            >
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <CardTitle className="text-lg truncate">
                      {organization.displayName || organization.name}
                    </CardTitle>
                    <CardDescription className="text-sm">
                      {organization.description?.short || 'No description available'}
                    </CardDescription>
                  </div>
                  {organization.branding?.logo && (
                    <img 
                      src={organization.branding.logo} 
                      alt={`${organization.name} logo`}
                      className="w-10 h-10 rounded-lg object-cover flex-shrink-0 ml-3"
                    />
                  )}
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {/* Status and Tier */}
                  <div className="flex flex-wrap gap-2">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(organization)}`}>
                      {formatStatus(organization)}
                    </span>
                    <span className="px-2 py-1 rounded-full text-xs font-medium text-purple-600 bg-purple-100">
                      {formatTier(organization.platformConfig?.tier || 'starter')}
                    </span>
                  </div>

                  {/* Organization Info */}
                  <div className="space-y-1 text-sm text-gray-600">
                    {organization.businessInfo?.industry?.primary && (
                      <div className="flex items-center gap-2">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 13.255A23.931 23.931 0 0112 15c-3.183 0-6.22-.62-9-1.745M16 6V4a2 2 0 00-2-2h-4a2 2 0 00-2-2v2m8 0V6a2 2 0 012 2v6M8 8v6a2 2 0 002 2h4a2 2 0 002-2V8" />
                        </svg>
                        <span>{organization.businessInfo.industry.primary.name}</span>
                      </div>
                    )}
                    {organization.headquarters?.address?.city && (
                      <div className="flex items-center gap-2">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
                        </svg>
                        <span>
                          {organization.headquarters.address.city}
                          {organization.headquarters.address.country && 
                            `, ${organization.headquarters.address.country}`
                          }
                        </span>
                      </div>
                    )}
                    {organization.team && (
                      <div className="flex items-center gap-2">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-.5a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
                        </svg>
                        <span>
                          {((organization.team.members?.length || 0) + (organization.team.admins?.length || 0) + 1)} members
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Domain */}
                  {organization.domains?.subdomain && (
                    <div className="text-xs text-gray-500 font-mono bg-gray-50 px-2 py-1 rounded">
                      {organization.domains.subdomain}.platform.com
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Pagination */}
      {!searchQuery && pagination && pagination.pages > 1 && (
        <div className="flex justify-center items-center space-x-2">
          <Button
            variant="outline"
            onClick={() => handlePageChange(currentPage - 1)}
            disabled={!pagination.hasPrev}
          >
            Previous
          </Button>
          
          <div className="flex space-x-1">
            {Array.from({ length: Math.min(5, pagination.pages) }, (_, i) => {
              const page = i + 1;
              const isCurrentPage = page === currentPage;
              
              return (
                <Button
                  key={page}
                  variant={isCurrentPage ? "default" : "outline"}
                  onClick={() => handlePageChange(page)}
                  className="w-10"
                >
                  {page}
                </Button>
              );
            })}
          </div>

          <Button
            variant="outline"
            onClick={() => handlePageChange(currentPage + 1)}
            disabled={!pagination.hasNext}
          >
            Next
          </Button>
        </div>
      )}
    </div>
  );
}