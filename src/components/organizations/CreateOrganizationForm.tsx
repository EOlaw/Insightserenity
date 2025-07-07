// src/components/organizations/CreateOrganizationForm.tsx
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useOrganizations } from '@/hooks/useOrganizations';
import { CreateOrganizationData } from '@/types/organization';
import { validateEmail } from '@/lib/utils';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/Card';
import { Alert } from '@/components/ui/Alert';

interface CreateOrganizationFormProps {
  onSuccess?: (organizationId: string) => void;
  onCancel?: () => void;
}

export function CreateOrganizationForm({ onSuccess, onCancel }: CreateOrganizationFormProps) {
  const router = useRouter();
  const { createOrganization, isCreating, error, clearError } = useOrganizations();

  const [formData, setFormData] = useState<CreateOrganizationData>({
    name: '',
    displayName: '',
    legalName: '',
    website: '',
    description: {
      short: '',
      mission: ''
    },
    businessInfo: {
      businessType: '',
      industry: {
        primary: {
          code: '',
          name: '',
          category: ''
        }
      }
    },
    headquarters: {
      address: {
        street: '',
        city: '',
        state: '',
        country: '',
        zipCode: ''
      },
      phone: '',
      email: '',
      timezone: ''
    },
    platformConfig: {
      tier: 'starter'
    },
    domains: {
      subdomain: ''
    }
  });

  const [errors, setErrors] = useState<Record<string, string>>({});
  const [currentStep, setCurrentStep] = useState(1);
  const [alertMessage, setAlertMessage] = useState<{ type: 'error' | 'success'; message: string } | null>(null);

  const steps = [
    { id: 1, title: 'Basic Information', description: 'Organization name and description' },
    { id: 2, title: 'Business Details', description: 'Industry and business information' },
    { id: 3, title: 'Contact Information', description: 'Address and contact details' },
    { id: 4, title: 'Platform Settings', description: 'Subdomain and tier selection' }
  ];

  const validateStep = (step: number): boolean => {
    const newErrors: Record<string, string> = {};

    switch (step) {
      case 1:
        if (!formData.name?.trim()) {
          newErrors.name = 'Organization name is required';
        } else if (formData.name.length < 2) {
          newErrors.name = 'Organization name must be at least 2 characters';
        } else if (formData.name.length > 100) {
          newErrors.name = 'Organization name cannot exceed 100 characters';
        }

        if (formData.description?.short && formData.description.short.length > 200) {
          newErrors.shortDescription = 'Short description cannot exceed 200 characters';
        }
        break;

      case 2:
        if (!formData.businessInfo?.businessType) {
          newErrors.businessType = 'Business type is required';
        }

        if (!formData.businessInfo?.industry?.primary?.name) {
          newErrors.industry = 'Primary industry is required';
        }
        break;

      case 3:
        if (formData.headquarters?.email && !validateEmail(formData.headquarters.email)) {
          newErrors.email = 'Invalid email format';
        }

        if (!formData.headquarters?.address?.country) {
          newErrors.country = 'Country is required';
        }
        break;

      case 4:
        if (!formData.domains?.subdomain?.trim()) {
          newErrors.subdomain = 'Subdomain is required';
        } else if (!/^[a-z0-9-]+$/.test(formData.domains.subdomain)) {
          newErrors.subdomain = 'Subdomain can only contain lowercase letters, numbers, and hyphens';
        } else if (formData.domains.subdomain.length < 3) {
          newErrors.subdomain = 'Subdomain must be at least 3 characters';
        } else if (formData.domains.subdomain.length > 50) {
          newErrors.subdomain = 'Subdomain cannot exceed 50 characters';
        }
        break;
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

    // Clear specific error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }));
    }
  };

  const handleNext = () => {
    if (validateStep(currentStep)) {
      setCurrentStep(prev => Math.min(prev + 1, steps.length));
    }
  };

  const handlePrevious = () => {
    setCurrentStep(prev => Math.max(prev - 1, 1));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAlertMessage(null);
    clearError();

    // Validate all steps
    let allValid = true;
    for (let i = 1; i <= steps.length; i++) {
      if (!validateStep(i)) {
        allValid = false;
        setCurrentStep(i);
        break;
      }
    }

    if (!allValid) return;

    try {
      const organization = await createOrganization(formData);
      
      setAlertMessage({
        type: 'success',
        message: 'Organization created successfully!'
      });

      if (onSuccess) {
        onSuccess(organization._id);
      } else {
        router.push(`/organizations/${organization._id}`);
      }
    } catch (error: any) {
      setAlertMessage({
        type: 'error',
        message: error.message || 'Failed to create organization'
      });
    }
  };

  const renderStepContent = () => {
    switch (currentStep) {
      case 1:
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Organization Name *
              </label>
              <Input
                type="text"
                value={formData.name}
                onChange={(e) => handleInputChange('name', e.target.value)}
                error={errors.name}
                placeholder="Enter organization name"
                className="w-full"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Display Name
              </label>
              <Input
                type="text"
                value={formData.displayName || ''}
                onChange={(e) => handleInputChange('displayName', e.target.value)}
                placeholder="Public display name (optional)"
                className="w-full"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Legal Name
              </label>
              <Input
                type="text"
                value={formData.legalName || ''}
                onChange={(e) => handleInputChange('legalName', e.target.value)}
                placeholder="Official legal name (optional)"
                className="w-full"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Short Description
              </label>
              <textarea
                value={formData.description?.short || ''}
                onChange={(e) => handleInputChange('description.short', e.target.value)}
                placeholder="Brief description of your organization"
                rows={3}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              {errors.shortDescription && (
                <p className="text-sm text-red-600 mt-1">{errors.shortDescription}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Mission Statement
              </label>
              <textarea
                value={formData.description?.mission || ''}
                onChange={(e) => handleInputChange('description.mission', e.target.value)}
                placeholder="Organization mission and purpose"
                rows={3}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>
        );

      case 2:
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Business Type *
              </label>
              <select
                value={formData.businessInfo?.businessType || ''}
                onChange={(e) => handleInputChange('businessInfo.businessType', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">Select business type</option>
                <option value="corporation">Corporation</option>
                <option value="llc">LLC</option>
                <option value="partnership">Partnership</option>
                <option value="sole_proprietorship">Sole Proprietorship</option>
                <option value="nonprofit">Non-Profit</option>
                <option value="government">Government</option>
                <option value="other">Other</option>
              </select>
              {errors.businessType && (
                <p className="text-sm text-red-600 mt-1">{errors.businessType}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Primary Industry *
              </label>
              <select
                value={formData.businessInfo?.industry?.primary?.category || ''}
                onChange={(e) => {
                  const category = e.target.value;
                  handleInputChange('businessInfo.industry.primary.category', category);
                  handleInputChange('businessInfo.industry.primary.name', category);
                  handleInputChange('businessInfo.industry.primary.code', category.toLowerCase().replace(/\s+/g, '_'));
                }}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">Select industry</option>
                <option value="Technology">Technology</option>
                <option value="Healthcare">Healthcare</option>
                <option value="Finance">Finance</option>
                <option value="Education">Education</option>
                <option value="Manufacturing">Manufacturing</option>
                <option value="Retail">Retail</option>
                <option value="Real Estate">Real Estate</option>
                <option value="Consulting">Consulting</option>
                <option value="Media">Media</option>
                <option value="Transportation">Transportation</option>
                <option value="Energy">Energy</option>
                <option value="Agriculture">Agriculture</option>
                <option value="Other">Other</option>
              </select>
              {errors.industry && (
                <p className="text-sm text-red-600 mt-1">{errors.industry}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Website
              </label>
              <Input
                type="url"
                value={formData.website || ''}
                onChange={(e) => handleInputChange('website', e.target.value)}
                placeholder="https://www.example.com"
                className="w-full"
              />
            </div>
          </div>
        );

      case 3:
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Street Address
                </label>
                <Input
                  type="text"
                  value={formData.headquarters?.address?.street || ''}
                  onChange={(e) => handleInputChange('headquarters.address.street', e.target.value)}
                  placeholder="Street address"
                  className="w-full"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  City
                </label>
                <Input
                  type="text"
                  value={formData.headquarters?.address?.city || ''}
                  onChange={(e) => handleInputChange('headquarters.address.city', e.target.value)}
                  placeholder="City"
                  className="w-full"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  State/Province
                </label>
                <Input
                  type="text"
                  value={formData.headquarters?.address?.state || ''}
                  onChange={(e) => handleInputChange('headquarters.address.state', e.target.value)}
                  placeholder="State or province"
                  className="w-full"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Country *
                </label>
                <select
                  value={formData.headquarters?.address?.country || ''}
                  onChange={(e) => handleInputChange('headquarters.address.country', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">Select country</option>
                  <option value="US">United States</option>
                  <option value="CA">Canada</option>
                  <option value="GB">United Kingdom</option>
                  <option value="DE">Germany</option>
                  <option value="FR">France</option>
                  <option value="AU">Australia</option>
                  <option value="JP">Japan</option>
                  <option value="Other">Other</option>
                </select>
                {errors.country && (
                  <p className="text-sm text-red-600 mt-1">{errors.country}</p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  ZIP/Postal Code
                </label>
                <Input
                  type="text"
                  value={formData.headquarters?.address?.zipCode || ''}
                  onChange={(e) => handleInputChange('headquarters.address.zipCode', e.target.value)}
                  placeholder="ZIP or postal code"
                  className="w-full"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Timezone
                </label>
                <select
                  value={formData.headquarters?.timezone || ''}
                  onChange={(e) => handleInputChange('headquarters.timezone', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">Select timezone</option>
                  <option value="America/New_York">Eastern Time (ET)</option>
                  <option value="America/Chicago">Central Time (CT)</option>
                  <option value="America/Denver">Mountain Time (MT)</option>
                  <option value="America/Los_Angeles">Pacific Time (PT)</option>
                  <option value="Europe/London">London (GMT)</option>
                  <option value="Europe/Paris">Paris (CET)</option>
                  <option value="Asia/Tokyo">Tokyo (JST)</option>
                  <option value="Australia/Sydney">Sydney (AEST)</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Contact Email
                </label>
                <Input
                  type="email"
                  value={formData.headquarters?.email || ''}
                  onChange={(e) => handleInputChange('headquarters.email', e.target.value)}
                  error={errors.email}
                  placeholder="contact@organization.com"
                  className="w-full"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Phone Number
                </label>
                <Input
                  type="tel"
                  value={formData.headquarters?.phone || ''}
                  onChange={(e) => handleInputChange('headquarters.phone', e.target.value)}
                  placeholder="+1 (555) 123-4567"
                  className="w-full"
                />
              </div>
            </div>
          </div>
        );

      case 4:
        return (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Subdomain *
              </label>
              <div className="flex">
                <Input
                  type="text"
                  value={formData.domains?.subdomain || ''}
                  onChange={(e) => handleInputChange('domains.subdomain', e.target.value.toLowerCase())}
                  error={errors.subdomain}
                  placeholder="myorganization"
                  className="flex-1"
                />
                <span className="inline-flex items-center px-3 rounded-r-md border border-l-0 border-gray-300 bg-gray-50 text-gray-500 text-sm">
                  .platform.com
                </span>
              </div>
              <p className="text-xs text-gray-500 mt-1">
                This will be your organization's web address
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Platform Tier
              </label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[
                  { id: 'starter', name: 'Starter', price: 'Free', features: ['Up to 5 users', 'Basic features', '1GB storage'] },
                  { id: 'growth', name: 'Growth', price: '$29/month', features: ['Up to 25 users', 'Advanced features', '10GB storage'] },
                  { id: 'professional', name: 'Professional', price: '$99/month', features: ['Up to 100 users', 'All features', '100GB storage'] },
                  { id: 'enterprise', name: 'Enterprise', price: 'Custom', features: ['Unlimited users', 'Custom features', 'Unlimited storage'] }
                ].map((tier) => (
                  <div
                    key={tier.id}
                    className={`border rounded-lg p-4 cursor-pointer transition-colors ${
                      formData.platformConfig?.tier === tier.id
                        ? 'border-blue-500 bg-blue-50'
                        : 'border-gray-200 hover:border-gray-300'
                    }`}
                    onClick={() => handleInputChange('platformConfig.tier', tier.id)}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-medium">{tier.name}</h4>
                      <span className="text-sm font-medium text-blue-600">{tier.price}</span>
                    </div>
                    <ul className="text-sm text-gray-600 space-y-1">
                      {tier.features.map((feature, index) => (
                        <li key={index} className="flex items-center gap-2">
                          <svg className="w-3 h-3 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                          </svg>
                          {feature}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <Card className="max-w-4xl mx-auto">
      <CardHeader>
        <CardTitle>Create New Organization</CardTitle>
        <CardDescription>
          Set up your organization to start collaborating with your team
        </CardDescription>
      </CardHeader>
      <CardContent>
        {/* Progress Steps */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            {steps.map((step, index) => (
              <div key={step.id} className="flex items-center">
                <div
                  className={`flex items-center justify-center w-8 h-8 rounded-full ${
                    currentStep >= step.id
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-200 text-gray-600'
                  }`}
                >
                  {currentStep > step.id ? (
                    <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                  ) : (
                    step.id
                  )}
                </div>
                {index < steps.length - 1 && (
                  <div
                    className={`flex-1 h-1 mx-4 ${
                      currentStep > step.id ? 'bg-blue-600' : 'bg-gray-200'
                    }`}
                  />
                )}
              </div>
            ))}
          </div>
          <div className="mt-4">
            <h3 className="text-lg font-medium">{steps[currentStep - 1].title}</h3>
            <p className="text-sm text-gray-600">{steps[currentStep - 1].description}</p>
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
            className="mb-6"
          >
            {alertMessage?.message || error}
          </Alert>
        )}

        {/* Form Content */}
        <form onSubmit={handleSubmit}>
          <div className="mb-8">
            {renderStepContent()}
          </div>

          {/* Navigation Buttons */}
          <div className="flex justify-between">
            <div>
              {currentStep > 1 && (
                <Button
                  type="button"
                  variant="outline"
                  onClick={handlePrevious}
                  disabled={isCreating}
                >
                  Previous
                </Button>
              )}
            </div>

            <div className="flex gap-2">
              {onCancel && (
                <Button
                  type="button"
                  variant="outline"
                  onClick={onCancel}
                  disabled={isCreating}
                >
                  Cancel
                </Button>
              )}

              {currentStep < steps.length ? (
                <Button
                  type="button"
                  onClick={handleNext}
                  disabled={isCreating}
                >
                  Next
                </Button>
              ) : (
                <Button
                  type="submit"
                  disabled={isCreating}
                  className="flex items-center gap-2"
                >
                  {isCreating ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                      Creating...
                    </>
                  ) : (
                    'Create Organization'
                  )}
                </Button>
              )}
            </div>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}