// src/components/organizations/OrganizationSelector.tsx
'use client';

import { useEffect, useState, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { useOrganizations } from '@/hooks/useOrganizations';
import { Organization } from '@/types/organization';
import { Button } from '@/components/ui/Button';

interface OrganizationSelectorProps {
  currentOrganizationId?: string;
  onOrganizationChange?: (organization: Organization) => void;
  showCreateOption?: boolean;
  className?: string;
}

export function OrganizationSelector({
  currentOrganizationId,
  onOrganizationChange,
  showCreateOption = true,
  className = ''
}: OrganizationSelectorProps) {
  const router = useRouter();
  const {
    organizations,
    currentOrganization,
    getOrganizations,
    setCurrentOrganization,
    isLoading
  } = useOrganizations();

  const [isOpen, setIsOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (organizations.length === 0) {
      loadOrganizations();
    }
  }, []);

  useEffect(() => {
    // Set current organization if provided via props
    if (currentOrganizationId && organizations.length > 0) {
      const org = organizations.find(o => o._id === currentOrganizationId);
      if (org && org._id !== currentOrganization?._id) {
        setCurrentOrganization(org);
      }
    }
  }, [currentOrganizationId, organizations, currentOrganization]);

  useEffect(() => {
    // Close dropdown when clicking outside
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const loadOrganizations = async () => {
    try {
      await getOrganizations(1, 50); // Load up to 50 organizations
    } catch (error) {
      console.error('Failed to load organizations:', error);
    }
  };

  const handleOrganizationSelect = (organization: Organization) => {
    setCurrentOrganization(organization);
    setIsOpen(false);
    setSearchQuery('');
    
    if (onOrganizationChange) {
      onOrganizationChange(organization);
    }
  };

  const handleCreateNew = () => {
    setIsOpen(false);
    router.push('/organizations/create');
  };

  const filteredOrganizations = organizations.filter(org =>
    org.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (org.displayName && org.displayName.toLowerCase().includes(searchQuery.toLowerCase()))
  );

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
      case 'Active': return 'text-green-500';
      case 'Trial': return 'text-blue-500';
      case 'Past Due': return 'text-yellow-500';
      case 'Canceled': 
      case 'Inactive': return 'text-red-500';
      default: return 'text-gray-500';
    }
  };

  return (
    <div className={`relative ${className}`} ref={dropdownRef}>
      {/* Trigger Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 w-full text-left"
      >
        <div className="flex items-center gap-2 min-w-0 flex-1">
          {currentOrganization?.branding?.logo ? (
            <img 
              src={currentOrganization.branding.logo} 
              alt={`${currentOrganization.name} logo`}
              className="w-5 h-5 rounded object-cover flex-shrink-0"
            />
          ) : (
            <div className="w-5 h-5 bg-gray-200 rounded flex-shrink-0 flex items-center justify-center">
              <svg className="w-3 h-3 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
              </svg>
            </div>
          )}
          <span className="truncate">
            {currentOrganization?.displayName || currentOrganization?.name || 'Select Organization'}
          </span>
        </div>
        <svg 
          className={`w-4 h-4 text-gray-400 transition-transform ${isOpen ? 'rotate-180' : ''}`} 
          fill="none" 
          stroke="currentColor" 
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Dropdown Menu */}
      {isOpen && (
        <div className="absolute z-50 w-full mt-1 bg-white border border-gray-200 rounded-md shadow-lg max-h-80 overflow-hidden">
          {/* Search Input */}
          {organizations.length > 5 && (
            <div className="p-2 border-b border-gray-100">
              <input
                type="text"
                placeholder="Search organizations..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                autoFocus
              />
            </div>
          )}

          {/* Organizations List */}
          <div className="py-1 max-h-60 overflow-y-auto">
            {isLoading ? (
              <div className="px-4 py-8 text-center">
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600 mx-auto"></div>
                <p className="text-sm text-gray-500 mt-2">Loading organizations...</p>
              </div>
            ) : filteredOrganizations.length === 0 ? (
              <div className="px-4 py-6 text-center">
                <div className="text-gray-400 mb-2">
                  <svg className="w-8 h-8 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
                  </svg>
                </div>
                <p className="text-sm text-gray-500 mb-3">
                  {searchQuery ? 'No organizations found' : 'No organizations available'}
                </p>
                {showCreateOption && !searchQuery && (
                  <Button size="sm" onClick={handleCreateNew}>
                    Create Organization
                  </Button>
                )}
              </div>
            ) : (
              <>
                {filteredOrganizations.map((organization) => (
                  <button
                    key={organization._id}
                    onClick={() => handleOrganizationSelect(organization)}
                    className={`w-full px-4 py-3 text-left hover:bg-gray-50 focus:outline-none focus:bg-gray-50 transition-colors ${
                      currentOrganization?._id === organization._id ? 'bg-blue-50 border-r-2 border-blue-500' : ''
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      {organization.branding?.logo ? (
                        <img 
                          src={organization.branding.logo} 
                          alt={`${organization.name} logo`}
                          className="w-8 h-8 rounded object-cover flex-shrink-0"
                        />
                      ) : (
                        <div className="w-8 h-8 bg-gray-100 rounded flex-shrink-0 flex items-center justify-center">
                          <span className="text-xs font-medium text-gray-600">
                            {organization.name.charAt(0).toUpperCase()}
                          </span>
                        </div>
                      )}
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium text-gray-900 truncate">
                          {organization.displayName || organization.name}
                        </p>
                        <div className="flex items-center gap-2 mt-1">
                          <div className={`w-2 h-2 rounded-full ${getStatusColor(organization).replace('text-', 'bg-')}`} />
                          <span className="text-xs text-gray-500">
                            {formatStatus(organization)}
                          </span>
                          {organization.platformConfig?.tier && (
                            <>
                              <span className="text-xs text-gray-400">•</span>
                              <span className="text-xs text-gray-500 capitalize">
                                {organization.platformConfig.tier}
                              </span>
                            </>
                          )}
                        </div>
                      </div>
                      {currentOrganization?._id === organization._id && (
                        <svg className="w-4 h-4 text-blue-500" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                        </svg>
                      )}
                    </div>
                  </button>
                ))}
              </>
            )}
          </div>

          {/* Action Buttons */}
          {(showCreateOption || organizations.length > 0) && (
            <div className="border-t border-gray-100 py-1">
              {showCreateOption && (
                <button
                  onClick={handleCreateNew}
                  className="w-full px-4 py-2 text-left text-sm text-blue-600 hover:bg-blue-50 focus:outline-none focus:bg-blue-50 flex items-center gap-2"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                  </svg>
                  Create New Organization
                </button>
              )}
              {organizations.length > 0 && (
                <button
                  onClick={() => {
                    setIsOpen(false);
                    router.push('/organizations');
                  }}
                  className="w-full px-4 py-2 text-left text-sm text-gray-600 hover:bg-gray-50 focus:outline-none focus:bg-gray-50 flex items-center gap-2"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  </svg>
                  Manage Organizations
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}