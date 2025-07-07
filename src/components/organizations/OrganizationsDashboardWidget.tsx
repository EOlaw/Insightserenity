// src/components/organizations/OrganizationsDashboardWidget.tsx
'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useOrganizations } from '@/hooks/useOrganizations';
import { Organization } from '@/types/organization';
import { Button } from '@/components/ui/Button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/Card';

interface OrganizationsDashboardWidgetProps {
  maxItems?: number;
  showCreateButton?: boolean;
}

export function OrganizationsDashboardWidget({ 
  maxItems = 5,
  showCreateButton = true
}: OrganizationsDashboardWidgetProps) {
  const router = useRouter();
  const {
    organizations,
    getOrganizations,
    isLoading,
    error
  } = useOrganizations();

  const [recentOrganizations, setRecentOrganizations] = useState<Organization[]>([]);

  useEffect(() => {
    loadRecentOrganizations();
  }, []);

  const loadRecentOrganizations = async () => {
    try {
      await getOrganizations(1, maxItems, { 
        status: 'active' 
      });
    } catch (error) {
      console.error('Failed to load organizations:', error);
    }
  };

  useEffect(() => {
    if (organizations.length > 0) {
      // Sort by last activity or creation date and take the most recent
      const sorted = [...organizations]
        .sort((a, b) => {
          const aDate = new Date(a.metrics?.usage?.lastActivity || a.updatedAt || a.createdAt);
          const bDate = new Date(b.metrics?.usage?.lastActivity || b.updatedAt || b.createdAt);
          return bDate.getTime() - aDate.getTime();
        })
        .slice(0, maxItems);
      setRecentOrganizations(sorted);
    }
  }, [organizations, maxItems]);

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

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Your Organizations</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex justify-center py-8">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>Your Organizations</CardTitle>
          <CardDescription>
            Recent organizations and quick access
          </CardDescription>
        </div>
        <div className="flex gap-2">
          {showCreateButton && (
            <Button
              size="sm"
              onClick={() => router.push('/organizations/create')}
            >
              Create
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => router.push('/organizations')}
          >
            View All
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {error && (
          <div className="text-sm text-red-600 mb-4 p-3 bg-red-50 rounded-lg">
            {error}
          </div>
        )}

        {recentOrganizations.length === 0 ? (
          <div className="text-center py-8">
            <div className="text-gray-400 mb-4">
              <svg className="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
              </svg>
            </div>
            <h3 className="text-sm font-medium text-gray-900 mb-2">No organizations yet</h3>
            <p className="text-sm text-gray-600 mb-4">Create your first organization to get started</p>
            {showCreateButton && (
              <Button size="sm" onClick={() => router.push('/organizations/create')}>
                Create Organization
              </Button>
            )}
          </div>
        ) : (
          <div className="space-y-3">
            {recentOrganizations.map((organization) => (
              <Link
                key={organization._id}
                href={`/organizations/${organization._id}`}
                className="block"
              >
                <div className="p-3 rounded-lg border border-gray-200 hover:border-gray-300 hover:bg-gray-50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      {organization.branding?.logo && (
                        <img 
                          src={organization.branding.logo} 
                          alt={`${organization.name} logo`}
                          className="w-8 h-8 rounded object-cover flex-shrink-0"
                        />
                      )}
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium text-gray-900 truncate">
                          {organization.displayName || organization.name}
                        </p>
                        <div className="flex items-center gap-2 mt-1">
                          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${getStatusColor(organization)}`}>
                            {formatStatus(organization)}
                          </span>
                          <span className="text-xs text-gray-500">
                            {formatTier(organization.platformConfig?.tier || 'starter')}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex-shrink-0 text-right">
                      {organization.team && (
                        <p className="text-xs text-gray-500">
                          {((organization.team.members?.length || 0) + (organization.team.admins?.length || 0) + 1)} members
                        </p>
                      )}
                      {organization.domains?.subdomain && (
                        <p className="text-xs text-gray-400 font-mono mt-1">
                          {organization.domains.subdomain}.platform.com
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              </Link>
            ))}
            
            {organizations.length > maxItems && (
              <div className="pt-2 border-t border-gray-100">
                <Link
                  href="/organizations"
                  className="block text-center text-sm text-blue-600 hover:text-blue-700 py-2"
                >
                  View all {organizations.length} organizations →
                </Link>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}