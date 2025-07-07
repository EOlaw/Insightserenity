// src/components/organizations/OrganizationDetail.tsx
'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useOrganizations } from '@/hooks/useOrganizations';
import { Organization, UpdateOrganizationData } from '@/types/organization';
import { validateEmail } from '@/lib/utils';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

interface OrganizationDetailProps {
  organizationId: string;
  onUpdate?: (organization: Organization) => void;
}

export function OrganizationDetail({ organizationId, onUpdate }: OrganizationDetailProps) {
  const router = useRouter();
  const {
    currentOrganization,
    getOrganization,
    updateOrganization,
    isLoading,
    isUpdating,
    error,
    clearError
  } = useOrganizations();

  const [activeTab, setActiveTab] = useState('overview');
  const [editMode, setEditMode] = useState(false);
  const [formData, setFormData] = useState<UpdateOrganizationData>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [alertMessage, setAlertMessage] = useState<{ type: 'error' | 'success'; message: string } | null>(null);

  useEffect(() => {
    loadOrganization();
  }, [organizationId]);

  useEffect(() => {
    if (currentOrganization) {
      setFormData({
        name: currentOrganization.name,
        displayName: currentOrganization.displayName,
        legalName: currentOrganization.legalName,
        website: currentOrganization.website,
        description: currentOrganization.description,
        businessInfo: currentOrganization.businessInfo,
        headquarters: currentOrganization.headquarters,
        branding: currentOrganization.branding,
        settings: currentOrganization.settings
      });
    }
  }, [currentOrganization]);

  const loadOrganization = async () => {
    try {
      await getOrganization(organizationId);
    } catch (error: any) {
      console.error('Failed to load organization:', error);
    }
  };

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!formData.name?.trim()) {
      newErrors.name = 'Organization name is required';
    } else if (formData.name.length < 2) {
      newErrors.name = 'Organization name must be at least 2 characters';
    } else if (formData.name.length > 100) {
      newErrors.name = 'Organization name cannot exceed 100 characters';
    }

    if (formData.headquarters?.email && !validateEmail(formData.headquarters.email)) {
      newErrors.email = 'Invalid email format';
    }

    if (formData.website && !formData.website.match(/^https?:\/\/.+/)) {
      newErrors.website = 'Website must include http:// or https://';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleInputChange = (field: string, value: any) => {
    setFormData(prev => {
      const keys = field.split('.');
      const newData = { ...prev };
      
      let current: any = newData;
      for (let i = 0; i < keys.length - 1; i++) {
        if (!current[keys[i]]) {
          current[keys[i]] = {};
        }
        current = current[keys[i]];
      }
      
      current[keys[keys.length - 1]] = value;
      return newData;
    });

    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }));
    }
  };

  const handleSave = async () => {
    setAlertMessage(null);
    clearError();

    if (!validateForm()) return;

    try {
      const updatedOrganization = await updateOrganization(organizationId, formData);
      
      setAlertMessage({
        type: 'success',
        message: 'Organization updated successfully!'
      });

      setEditMode(false);

      if (onUpdate) {
        onUpdate(updatedOrganization);
      }
    } catch (error: any) {
      setAlertMessage({
        type: 'error',
        message: error.message || 'Failed to update organization'
      });
    }
  };

  const handleCancel = () => {
    if (currentOrganization) {
      setFormData({
        name: currentOrganization.name,
        displayName: currentOrganization.displayName,
        legalName: currentOrganization.legalName,
        website: currentOrganization.website,
        description: currentOrganization.description,
        businessInfo: currentOrganization.businessInfo,
        headquarters: currentOrganization.headquarters,
        branding: currentOrganization.branding,
        settings: currentOrganization.settings
      });
    }
    setErrors({});
    setEditMode(false);
    setAlertMessage(null);
    clearError();
  };

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

  const tabs = [
    { id: 'overview', label: 'Overview', icon: '🏢' },
    { id: 'team', label: 'Team', icon: '👥' },
    { id: 'settings', label: 'Settings', icon: '⚙️' },
    { id: 'billing', label: 'Billing', icon: '💳' },
    { id: 'integrations', label: 'Integrations', icon: '🔌' }
  ];

  if (isLoading) {
    return (
      <div className="flex justify-center py-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!currentOrganization) {
    return (
      <Card>
        <CardContent className="text-center py-12">
          <div className="text-gray-400 mb-4">
            <svg className="w-16 h-16 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
            </svg>
          </div>
          <h3 className="text-lg font-medium text-gray-900 mb-2">Organization not found</h3>
          <p className="text-gray-600 mb-6">The organization you're looking for doesn't exist or you don't have access to it.</p>
          <Button onClick={() => router.push('/organizations')}>
            Back to Organizations
          </Button>
        </CardContent>
      </Card>
    );
  }

  const renderOverviewTab = () => (
    <div className="space-y-6">
      {/* Basic Information */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Basic Information</CardTitle>
            <CardDescription>Organization details and description</CardDescription>
          </div>
          <Button
            variant="outline"
            onClick={() => setEditMode(!editMode)}
            disabled={isUpdating}
          >
            {editMode ? 'Cancel' : 'Edit'}
          </Button>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Organization Name
              </label>
              {editMode ? (
                <Input
                  type="text"
                  value={formData.name || ''}
                  onChange={(e) => handleInputChange('name', e.target.value)}
                  error={errors.name}
                  className="w-full"
                />
              ) : (
                <p className="text-gray-900">{currentOrganization.name}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Display Name
              </label>
              {editMode ? (
                <Input
                  type="text"
                  value={formData.displayName || ''}
                  onChange={(e) => handleInputChange('displayName', e.target.value)}
                  className="w-full"
                />
              ) : (
                <p className="text-gray-900">{currentOrganization.displayName || 'Not set'}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Legal Name
              </label>
              {editMode ? (
                <Input
                  type="text"
                  value={formData.legalName || ''}
                  onChange={(e) => handleInputChange('legalName', e.target.value)}
                  className="w-full"
                />
              ) : (
                <p className="text-gray-900">{currentOrganization.legalName || 'Not set'}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Website
              </label>
              {editMode ? (
                <Input
                  type="url"
                  value={formData.website || ''}
                  onChange={(e) => handleInputChange('website', e.target.value)}
                  error={errors.website}
                  className="w-full"
                />
              ) : (
                currentOrganization.website ? (
                  <a
                    href={currentOrganization.website}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-600 hover:text-blue-800"
                  >
                    {currentOrganization.website}
                  </a>
                ) : (
                  <p className="text-gray-900">Not set</p>
                )
              )}
            </div>
          </div>

          <div className="mt-6">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Description
            </label>
            {editMode ? (
              <textarea
                value={formData.description?.short || ''}
                onChange={(e) => handleInputChange('description.short', e.target.value)}
                rows={3}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            ) : (
              <p className="text-gray-900">{currentOrganization.description?.short || 'No description available'}</p>
            )}
          </div>

          {editMode && (
            <div className="mt-6 flex gap-2">
              <Button onClick={handleSave} disabled={isUpdating}>
                {isUpdating ? 'Saving...' : 'Save Changes'}
              </Button>
              <Button variant="outline" onClick={handleCancel}>
                Cancel
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Organization Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
                  <svg className="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-.5a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
                  </svg>
                </div>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Team Members</p>
                <p className="text-2xl font-semibold text-gray-900">
                  {((currentOrganization.team?.members?.length || 0) + (currentOrganization.team?.admins?.length || 0) + 1)}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-green-100 rounded-lg flex items-center justify-center">
                  <svg className="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Status</p>
                <p className="text-sm font-semibold">
                  <span className={`px-2 py-1 rounded-full ${getStatusColor(currentOrganization)}`}>
                    {formatStatus(currentOrganization)}
                  </span>
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-purple-100 rounded-lg flex items-center justify-center">
                  <svg className="w-4 h-4 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </div>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Plan Tier</p>
                <p className="text-sm font-semibold text-gray-900">
                  {formatTier(currentOrganization.platformConfig?.tier || 'starter')}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-yellow-100 rounded-lg flex items-center justify-center">
                  <svg className="w-4 h-4 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                  </svg>
                </div>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Created</p>
                <p className="text-sm font-semibold text-gray-900">
                  {new Date(currentOrganization.createdAt).toLocaleDateString()}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Contact Information */}
      <Card>
        <CardHeader>
          <CardTitle>Contact Information</CardTitle>
          <CardDescription>Organization contact details and location</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-medium text-gray-900 mb-3">Contact Details</h4>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                  </svg>
                  <span className="text-sm text-gray-600">
                    {currentOrganization.headquarters?.email || 'No email set'}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
                  </svg>
                  <span className="text-sm text-gray-600">
                    {currentOrganization.headquarters?.phone || 'No phone set'}
                  </span>
                </div>
              </div>
            </div>

            <div>
              <h4 className="font-medium text-gray-900 mb-3">Address</h4>
              <div className="text-sm text-gray-600">
                {currentOrganization.headquarters?.address ? (
                  <div className="space-y-1">
                    {currentOrganization.headquarters.address.street && (
                      <div>{currentOrganization.headquarters.address.street}</div>
                    )}
                    <div>
                      {[
                        currentOrganization.headquarters.address.city,
                        currentOrganization.headquarters.address.state,
                        currentOrganization.headquarters.address.zipCode
                      ].filter(Boolean).join(', ')}
                    </div>
                    {currentOrganization.headquarters.address.country && (
                      <div>{currentOrganization.headquarters.address.country}</div>
                    )}
                  </div>
                ) : (
                  'No address set'
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );

  const renderTeamTab = () => (
    <Card>
      <CardContent className="text-center py-12">
        <div className="text-gray-400 mb-4">
          <svg className="w-16 h-16 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-.5a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
          </svg>
        </div>
        <h3 className="text-lg font-medium text-gray-900 mb-2">Team Management</h3>
        <p className="text-gray-600">Team management features will be available soon.</p>
      </CardContent>
    </Card>
  );

  const renderSettingsTab = () => (
    <Card>
      <CardContent className="text-center py-12">
        <div className="text-gray-400 mb-4">
          <svg className="w-16 h-16 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
        </div>
        <h3 className="text-lg font-medium text-gray-900 mb-2">Organization Settings</h3>
        <p className="text-gray-600">Advanced settings and configuration options will be available soon.</p>
      </CardContent>
    </Card>
  );

  const renderBillingTab = () => (
    <Card>
      <CardContent className="text-center py-12">
        <div className="text-gray-400 mb-4">
          <svg className="w-16 h-16 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
          </svg>
        </div>
        <h3 className="text-lg font-medium text-gray-900 mb-2">Billing & Subscription</h3>
        <p className="text-gray-600">Billing management and subscription details will be available soon.</p>
      </CardContent>
    </Card>
  );

  const renderIntegrationsTab = () => (
    <Card>
      <CardContent className="text-center py-12">
        <div className="text-gray-400 mb-4">
          <svg className="w-16 h-16 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
          </svg>
        </div>
        <h3 className="text-lg font-medium text-gray-900 mb-2">Integrations</h3>
        <p className="text-gray-600">Third-party integrations and API management will be available soon.</p>
      </CardContent>
    </Card>
  );

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return renderOverviewTab();
      case 'team':
        return renderTeamTab();
      case 'settings':
        return renderSettingsTab();
      case 'billing':
        return renderBillingTab();
      case 'integrations':
        return renderIntegrationsTab();
      default:
        return renderOverviewTab();
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div className="flex items-center gap-4">
          {currentOrganization.branding?.logo && (
            <img 
              src={currentOrganization.branding.logo} 
              alt={`${currentOrganization.name} logo`}
              className="w-12 h-12 rounded-lg object-cover"
            />
          )}
          <div>
            <h1 className="text-2xl font-bold text-gray-900">
              {currentOrganization.displayName || currentOrganization.name}
            </h1>
            <p className="text-gray-600">
              {currentOrganization.description?.short || 'Organization details and management'}
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => router.push(`/organizations/${organizationId}/team`)}
          >
            Manage Team
          </Button>
          <Button
            variant="outline"
            onClick={() => router.push('/organizations')}
          >
            Back to Organizations
          </Button>
        </div>
      </div>

      {/* Alert Messages */}
      {(alertMessage || error) && (
        <Alert 
          type={(alertMessage?.type || 'error') as 'error' | 'success'} 
          onClose={() => {
            setAlertMessage(null);
            clearError();
          }}
        >
          {alertMessage?.message || error}
        </Alert>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <span className="flex items-center gap-2">
                <span>{tab.icon}</span>
                {tab.label}
              </span>
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {renderTabContent()}
    </div>
  );
}