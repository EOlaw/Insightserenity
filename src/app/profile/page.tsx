// src/app/profile/page.tsx
'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AuthService } from '@/lib/auth';
import { Button } from '@/components/ui/Button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/Card';
import { apiClient } from '@/lib/api';

interface User {
  _id: string;
  email: string;
  firstName: string;
  lastName: string;
  middleName?: string;
  username?: string;
  role: {
    primary: string;
    secondary?: string[];
  };
  userType: string;
  status: string;
  isEmailVerified: boolean;
  profile?: {
    displayName?: string;
    bio?: {
      short?: string;
      full?: string;
    };
    title?: string;
    department?: string;
    avatar?: string;
  };
  contact?: {
    phone?: {
      number: string;
      verified: boolean;
    };
    address?: {
      street: string;
      city: string;
      state: string;
      country: string;
      zipCode: string;
    };
  };
  organization?: {
    current?: {
      name: string;
      slug: string;
      type: string;
    };
  };
  preferences?: {
    language?: string;
    timezone?: string;
    theme?: string;
    dateFormat?: string;
    timeFormat?: string;
  };
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
}

const ProfilePage = () => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [editMode, setEditMode] = useState(false);
  const [formData, setFormData] = useState<Partial<User>>({});
  const router = useRouter();

  useEffect(() => {
    const checkAuthAndLoadProfile = async () => {
      try {
        const isLoggedIn = await AuthService.isAuthenticated();
        if (!isLoggedIn) {
          router.push('/login');
          return;
        }

        await loadUserProfile();
      } catch (err) {
        console.error('Authentication check failed:', err);
        router.push('/login');
      }
    };

    checkAuthAndLoadProfile();
  }, [router]);

  const loadUserProfile = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await apiClient.getCurrentUser();
      
      if (response.success) {
        const userData = response.data?.user || response.user;
        setUser(userData);
        setFormData(userData);
      } else {
        setError('Failed to load user profile');
      }
    } catch (err: any) {
      console.error('Profile fetch error:', err);
      setError(err.message || 'Failed to load user profile');
      
      if (err.status === 401) {
        router.push('/login');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (field: string, value: any) => {
    setFormData(prev => {
      const keys = field.split('.');
      const result = { ...prev };
      let current = result;
      
      for (let i = 0; i < keys.length - 1; i++) {
        if (!current[keys[i]]) {
          current[keys[i]] = {};
        }
        current = current[keys[i]];
      }
      
      current[keys[keys.length - 1]] = value;
      return result;
    });
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      setError(null);
      setSuccess(null);

      const response = await apiClient.updateCurrentUser(formData);
      
      if (response.success) {
        const updatedUser = response.data?.user || response.user;
        setUser(updatedUser);
        setFormData(updatedUser);
        setEditMode(false);
        setSuccess('Profile updated successfully');
      } else {
        setError('Failed to update profile');
      }
    } catch (err: any) {
      console.error('Profile update error:', err);
      setError(err.message || 'Failed to update profile');
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    setFormData(user || {});
    setEditMode(false);
    setError(null);
    setSuccess(null);
  };

  const formatDate = (dateString: string): string => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading profile...</p>
        </div>
      </div>
    );
  }

  if (error && !user) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="text-red-600 text-xl mb-4">⚠️ Error</div>
          <p className="text-gray-600 mb-4">{error}</p>
          <Button onClick={loadUserProfile}>Retry</Button>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <p className="text-gray-600">No user data available</p>
          <Button onClick={loadUserProfile} className="mt-4">Refresh</Button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <Button
                onClick={() => router.push('/dashboard')}
                variant="outline"
                size="sm"
                className="mr-4"
              >
                ← Back to Dashboard
              </Button>
              <h1 className="text-2xl font-bold text-gray-900">Profile</h1>
            </div>
            <div className="flex items-center space-x-4">
              {!editMode ? (
                <Button onClick={() => setEditMode(true)}>
                  Edit Profile
                </Button>
              ) : (
                <div className="flex space-x-2">
                  <Button
                    onClick={handleCancel}
                    variant="outline"
                    disabled={saving}
                  >
                    Cancel
                  </Button>
                  <Button
                    onClick={handleSave}
                    disabled={saving}
                  >
                    {saving ? 'Saving...' : 'Save Changes'}
                  </Button>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Alerts */}
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-md">
            <p className="text-red-600 text-sm">{error}</p>
          </div>
        )}
        
        {success && (
          <div className="mb-6 p-4 bg-green-50 border border-green-200 rounded-md">
            <p className="text-green-600 text-sm">{success}</p>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Profile Header Card */}
          <div className="lg:col-span-1">
            <Card>
              <CardContent className="p-6 text-center">
                <div className="w-24 h-24 bg-blue-500 rounded-full mx-auto mb-4 flex items-center justify-center">
                  <span className="text-2xl font-bold text-white">
                    {user.firstName.charAt(0)}{user.lastName.charAt(0)}
                  </span>
                </div>
                <h2 className="text-xl font-bold text-gray-900 mb-1">
                  {user.firstName} {user.lastName}
                </h2>
                <p className="text-gray-600 mb-2">{user.profile?.title || user.role.primary}</p>
                <p className="text-sm text-gray-500">{user.email}</p>
                
                <div className="mt-6 space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-600">Status:</span>
                    <span className={`font-medium ${user.status === 'active' ? 'text-green-600' : 'text-gray-600'}`}>
                      {user.status}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Role:</span>
                    <span className="font-medium">{user.role.primary}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Type:</span>
                    <span className="font-medium">{user.userType}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Member since:</span>
                    <span className="font-medium">{formatDate(user.createdAt)}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Profile Details */}
          <div className="lg:col-span-2 space-y-6">
            {/* Basic Information */}
            <Card>
              <CardHeader>
                <CardTitle>Basic Information</CardTitle>
                <CardDescription>Your personal and professional details</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      First Name
                    </label>
                    {editMode ? (
                      <input
                        type="text"
                        value={formData.firstName || ''}
                        onChange={(e) => handleInputChange('firstName', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    ) : (
                      <p className="text-gray-900">{user.firstName}</p>
                    )}
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Last Name
                    </label>
                    {editMode ? (
                      <input
                        type="text"
                        value={formData.lastName || ''}
                        onChange={(e) => handleInputChange('lastName', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    ) : (
                      <p className="text-gray-900">{user.lastName}</p>
                    )}
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Email Address
                  </label>
                  <p className="text-gray-900">{user.email}</p>
                  <p className="text-xs text-gray-500">Email address cannot be changed</p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Job Title
                  </label>
                  {editMode ? (
                    <input
                      type="text"
                      value={formData.profile?.title || ''}
                      onChange={(e) => handleInputChange('profile.title', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="Your job title"
                    />
                  ) : (
                    <p className="text-gray-900">{user.profile?.title || 'Not specified'}</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Department
                  </label>
                  {editMode ? (
                    <input
                      type="text"
                      value={formData.profile?.department || ''}
                      onChange={(e) => handleInputChange('profile.department', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="Your department"
                    />
                  ) : (
                    <p className="text-gray-900">{user.profile?.department || 'Not specified'}</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Bio
                  </label>
                  {editMode ? (
                    <textarea
                      value={formData.profile?.bio?.short || ''}
                      onChange={(e) => handleInputChange('profile.bio.short', e.target.value)}
                      rows={3}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="Tell us about yourself"
                    />
                  ) : (
                    <p className="text-gray-900">{user.profile?.bio?.short || 'No bio provided'}</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Contact Information */}
            <Card>
              <CardHeader>
                <CardTitle>Contact Information</CardTitle>
                <CardDescription>How can people reach you</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Phone Number
                  </label>
                  {editMode ? (
                    <input
                      type="tel"
                      value={formData.contact?.phone?.number || ''}
                      onChange={(e) => handleInputChange('contact.phone.number', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="Your phone number"
                    />
                  ) : (
                    <p className="text-gray-900">{user.contact?.phone?.number || 'Not provided'}</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Organization */}
            {user.organization?.current && (
              <Card>
                <CardHeader>
                  <CardTitle>Organization</CardTitle>
                  <CardDescription>Your current organization details</CardDescription>
                </CardHeader>
                <CardContent>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Organization Name
                    </label>
                    <p className="text-gray-900">{user.organization.current.name}</p>
                  </div>
                  <div className="mt-4">
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Organization Type
                    </label>
                    <p className="text-gray-900">{user.organization.current.type}</p>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Account Information */}
            <Card>
              <CardHeader>
                <CardTitle>Account Information</CardTitle>
                <CardDescription>Account status and verification details</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium text-gray-700">Email Verified</span>
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                    user.isEmailVerified 
                      ? 'bg-green-100 text-green-800' 
                      : 'bg-red-100 text-red-800'
                  }`}>
                    {user.isEmailVerified ? 'Verified' : 'Not Verified'}
                  </span>
                </div>
                
                <div className="flex justify-between">
                  <span className="text-sm text-gray-700">Account Created</span>
                  <span className="text-sm text-gray-900">{formatDate(user.createdAt)}</span>
                </div>
                
                <div className="flex justify-between">
                  <span className="text-sm text-gray-700">Last Updated</span>
                  <span className="text-sm text-gray-900">{formatDate(user.updatedAt)}</span>
                </div>
                
                {user.lastLoginAt && (
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-700">Last Login</span>
                    <span className="text-sm text-gray-900">{formatDate(user.lastLoginAt)}</span>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
};

export default ProfilePage;