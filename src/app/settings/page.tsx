// src/app/settings/page.tsx
'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AuthService } from '@/lib/auth';
import { Button } from '@/components/ui/Button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/Card';
import { apiClient } from '@/lib/api';

interface UserPreferences {
  language: string;
  timezone: string;
  theme: string;
  dateFormat: string;
  timeFormat: string;
  currency: string;
  emailNotifications: {
    projectUpdates: boolean;
    clientNotifications: boolean;
    systemAlerts: boolean;
    weeklyReports: boolean;
    marketingEmails: boolean;
  };
  pushNotifications: {
    enabled: boolean;
    projectDeadlines: boolean;
    teamMentions: boolean;
    clientMessages: boolean;
  };
  privacy: {
    profileVisibility: string;
    showOnlineStatus: boolean;
    allowDirectMessages: boolean;
  };
  accessibility: {
    highContrast: boolean;
    largeText: boolean;
    reducedMotion: boolean;
    screenReader: boolean;
  };
}

interface User {
  _id: string;
  email: string;
  firstName: string;
  lastName: string;
  preferences?: UserPreferences;
}

const SettingsPage = () => {
  const [user, setUser] = useState<User | null>(null);
  const [preferences, setPreferences] = useState<UserPreferences>({
    language: 'en',
    timezone: 'America/New_York',
    theme: 'light',
    dateFormat: 'MM/DD/YYYY',
    timeFormat: '12h',
    currency: 'USD',
    emailNotifications: {
      projectUpdates: true,
      clientNotifications: true,
      systemAlerts: true,
      weeklyReports: false,
      marketingEmails: false,
    },
    pushNotifications: {
      enabled: true,
      projectDeadlines: true,
      teamMentions: true,
      clientMessages: true,
    },
    privacy: {
      profileVisibility: 'team',
      showOnlineStatus: true,
      allowDirectMessages: true,
    },
    accessibility: {
      highContrast: false,
      largeText: false,
      reducedMotion: false,
      screenReader: false,
    },
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('general');
  const router = useRouter();

  useEffect(() => {
    const checkAuthAndLoadSettings = async () => {
      try {
        const isLoggedIn = await AuthService.isAuthenticated();
        if (!isLoggedIn) {
          router.push('/login');
          return;
        }

        await loadUserSettings();
      } catch (err) {
        console.error('Authentication check failed:', err);
        router.push('/login');
      }
    };

    checkAuthAndLoadSettings();
  }, [router]);

  const loadUserSettings = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await apiClient.getCurrentUser();
      
      if (response.success) {
        const userData = response.data?.user || response.user;
        setUser(userData);
        
        if (userData.preferences) {
          setPreferences(prev => ({
            ...prev,
            ...userData.preferences,
          }));
        }
      } else {
        setError('Failed to load user settings');
      }
    } catch (err: any) {
      console.error('Settings fetch error:', err);
      setError(err.message || 'Failed to load user settings');
      
      if (err.status === 401) {
        router.push('/login');
      }
    } finally {
      setLoading(false);
    }
  };

  const handlePreferenceChange = (category: string, key: string, value: any) => {
    setPreferences(prev => ({
      ...prev,
      [category]: {
        ...prev[category as keyof UserPreferences],
        [key]: value,
      },
    }));
  };

  const handleSimplePreferenceChange = (key: string, value: any) => {
    setPreferences(prev => ({
      ...prev,
      [key]: value,
    }));
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      setError(null);
      setSuccess(null);

      const response = await apiClient.updateCurrentUser({
        preferences,
      });
      
      if (response.success) {
        setSuccess('Settings updated successfully');
      } else {
        setError('Failed to update settings');
      }
    } catch (err: any) {
      console.error('Settings update error:', err);
      setError(err.message || 'Failed to update settings');
    } finally {
      setSaving(false);
    }
  };

  const tabs = [
    { id: 'general', label: 'General', icon: '⚙️' },
    { id: 'notifications', label: 'Notifications', icon: '🔔' },
    { id: 'privacy', label: 'Privacy', icon: '🔒' },
    { id: 'accessibility', label: 'Accessibility', icon: '♿' },
  ];

  const timezones = [
    'America/New_York',
    'America/Chicago',
    'America/Denver',
    'America/Los_Angeles',
    'Europe/London',
    'Europe/Paris',
    'Asia/Tokyo',
    'Asia/Shanghai',
    'Australia/Sydney',
  ];

  const languages = [
    { code: 'en', name: 'English' },
    { code: 'es', name: 'Spanish' },
    { code: 'fr', name: 'French' },
    { code: 'de', name: 'German' },
    { code: 'it', name: 'Italian' },
    { code: 'pt', name: 'Portuguese' },
    { code: 'ja', name: 'Japanese' },
    { code: 'zh', name: 'Chinese' },
  ];

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading settings...</p>
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
          <Button onClick={loadUserSettings}>Retry</Button>
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
              <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
            </div>
            <div className="flex items-center space-x-4">
              <Button
                onClick={handleSave}
                disabled={saving}
              >
                {saving ? 'Saving...' : 'Save Changes'}
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
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

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Navigation */}
          <div className="lg:col-span-1">
            <Card>
              <CardContent className="p-4">
                <nav className="space-y-1">
                  {tabs.map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`w-full flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                        activeTab === tab.id
                          ? 'bg-blue-100 text-blue-700'
                          : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                      }`}
                    >
                      <span className="mr-3">{tab.icon}</span>
                      {tab.label}
                    </button>
                  ))}
                </nav>
              </CardContent>
            </Card>
          </div>

          {/* Content */}
          <div className="lg:col-span-3">
            {/* General Settings */}
            {activeTab === 'general' && (
              <Card>
                <CardHeader>
                  <CardTitle>General Settings</CardTitle>
                  <CardDescription>Manage your account preferences and regional settings</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Language
                      </label>
                      <select
                        value={preferences.language}
                        onChange={(e) => handleSimplePreferenceChange('language', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        {languages.map((lang) => (
                          <option key={lang.code} value={lang.code}>
                            {lang.name}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Timezone
                      </label>
                      <select
                        value={preferences.timezone}
                        onChange={(e) => handleSimplePreferenceChange('timezone', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        {timezones.map((tz) => (
                          <option key={tz} value={tz}>
                            {tz.replace('_', ' ')}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Theme
                      </label>
                      <select
                        value={preferences.theme}
                        onChange={(e) => handleSimplePreferenceChange('theme', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        <option value="light">Light</option>
                        <option value="dark">Dark</option>
                        <option value="auto">Auto</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Date Format
                      </label>
                      <select
                        value={preferences.dateFormat}
                        onChange={(e) => handleSimplePreferenceChange('dateFormat', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        <option value="MM/DD/YYYY">MM/DD/YYYY</option>
                        <option value="DD/MM/YYYY">DD/MM/YYYY</option>
                        <option value="YYYY-MM-DD">YYYY-MM-DD</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Time Format
                      </label>
                      <select
                        value={preferences.timeFormat}
                        onChange={(e) => handleSimplePreferenceChange('timeFormat', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        <option value="12h">12 Hour</option>
                        <option value="24h">24 Hour</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Currency
                      </label>
                      <select
                        value={preferences.currency}
                        onChange={(e) => handleSimplePreferenceChange('currency', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        <option value="USD">USD - US Dollar</option>
                        <option value="EUR">EUR - Euro</option>
                        <option value="GBP">GBP - British Pound</option>
                        <option value="CAD">CAD - Canadian Dollar</option>
                        <option value="AUD">AUD - Australian Dollar</option>
                        <option value="JPY">JPY - Japanese Yen</option>
                      </select>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Notifications Settings */}
            {activeTab === 'notifications' && (
              <div className="space-y-6">
                <Card>
                  <CardHeader>
                    <CardTitle>Email Notifications</CardTitle>
                    <CardDescription>Choose which email notifications you want to receive</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {Object.entries(preferences.emailNotifications).map(([key, value]) => (
                      <div key={key} className="flex items-center justify-between">
                        <div>
                          <h4 className="text-sm font-medium text-gray-900">
                            {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                          </h4>
                          <p className="text-sm text-gray-600">
                            {getNotificationDescription(key)}
                          </p>
                        </div>
                        <label className="relative inline-flex items-center cursor-pointer">
                          <input
                            type="checkbox"
                            checked={value}
                            onChange={(e) => handlePreferenceChange('emailNotifications', key, e.target.checked)}
                            className="sr-only peer"
                          />
                          <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                        </label>
                      </div>
                    ))}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>Push Notifications</CardTitle>
                    <CardDescription>Manage your browser and mobile push notifications</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {Object.entries(preferences.pushNotifications).map(([key, value]) => (
                      <div key={key} className="flex items-center justify-between">
                        <div>
                          <h4 className="text-sm font-medium text-gray-900">
                            {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                          </h4>
                          <p className="text-sm text-gray-600">
                            {getPushNotificationDescription(key)}
                          </p>
                        </div>
                        <label className="relative inline-flex items-center cursor-pointer">
                          <input
                            type="checkbox"
                            checked={value}
                            onChange={(e) => handlePreferenceChange('pushNotifications', key, e.target.checked)}
                            className="sr-only peer"
                          />
                          <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                        </label>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              </div>
            )}

            {/* Privacy Settings */}
            {activeTab === 'privacy' && (
              <Card>
                <CardHeader>
                  <CardTitle>Privacy Settings</CardTitle>
                  <CardDescription>Control your privacy and visibility preferences</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Profile Visibility
                    </label>
                    <select
                      value={preferences.privacy.profileVisibility}
                      onChange={(e) => handlePreferenceChange('privacy', 'profileVisibility', e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="public">Public - Visible to everyone</option>
                      <option value="team">Team - Visible to team members only</option>
                      <option value="private">Private - Visible to you only</option>
                    </select>
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-sm font-medium text-gray-900">Show Online Status</h4>
                      <p className="text-sm text-gray-600">
                        Let others see when you are online and active
                      </p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={preferences.privacy.showOnlineStatus}
                        onChange={(e) => handlePreferenceChange('privacy', 'showOnlineStatus', e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                    </label>
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-sm font-medium text-gray-900">Allow Direct Messages</h4>
                      <p className="text-sm text-gray-600">
                        Allow team members to send you direct messages
                      </p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={preferences.privacy.allowDirectMessages}
                        onChange={(e) => handlePreferenceChange('privacy', 'allowDirectMessages', e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                    </label>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Accessibility Settings */}
            {activeTab === 'accessibility' && (
              <Card>
                <CardHeader>
                  <CardTitle>Accessibility Settings</CardTitle>
                  <CardDescription>Customize the interface to meet your accessibility needs</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {Object.entries(preferences.accessibility).map(([key, value]) => (
                    <div key={key} className="flex items-center justify-between">
                      <div>
                        <h4 className="text-sm font-medium text-gray-900">
                          {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                        </h4>
                        <p className="text-sm text-gray-600">
                          {getAccessibilityDescription(key)}
                        </p>
                      </div>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={value}
                          onChange={(e) => handlePreferenceChange('accessibility', key, e.target.checked)}
                          className="sr-only peer"
                        />
                        <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                      </label>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </main>
    </div>
  );

  function getNotificationDescription(key: string): string {
    const descriptions: Record<string, string> = {
      projectUpdates: 'Receive updates when projects you are involved in change status',
      clientNotifications: 'Get notified about new client communications and requests',
      systemAlerts: 'Important system notifications and maintenance updates',
      weeklyReports: 'Weekly summary of your projects and activities',
      marketingEmails: 'Product updates and company news',
    };
    return descriptions[key] || '';
  }

  function getPushNotificationDescription(key: string): string {
    const descriptions: Record<string, string> = {
      enabled: 'Enable push notifications in your browser',
      projectDeadlines: 'Get notified about upcoming project deadlines',
      teamMentions: 'Receive notifications when team members mention you',
      clientMessages: 'Immediate notifications for urgent client messages',
    };
    return descriptions[key] || '';
  }

  function getAccessibilityDescription(key: string): string {
    const descriptions: Record<string, string> = {
      highContrast: 'Use high contrast colors for better visibility',
      largeText: 'Increase text size throughout the application',
      reducedMotion: 'Reduce animations and motion effects',
      screenReader: 'Optimize the interface for screen reader compatibility',
    };
    return descriptions[key] || '';
  }
};

export default SettingsPage;