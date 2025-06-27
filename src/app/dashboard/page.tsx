// src/app/dashboard/page.tsx
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
  };
  createdAt: string;
  updatedAt: string;
}

interface DashboardMetrics {
  activeProjects: number;
  totalRevenue: number;
  monthlyRevenue: number;
  clientSatisfaction: number;
  hoursLogged: number;
  upcomingMeetings: number;
}

interface RecentActivity {
  id: string;
  type: 'project' | 'client' | 'meeting' | 'document';
  title: string;
  description: string;
  timestamp: string;
  status?: string;
}

interface UpcomingTask {
  id: string;
  title: string;
  description: string;
  dueDate: string;
  priority: 'high' | 'medium' | 'low';
  project?: string;
}

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingLogout, setIsLoadingLogout] = useState(false);

  // Mock data for demonstration - in production, these would come from your backend
  const [metrics] = useState<DashboardMetrics>({
    activeProjects: 7,
    totalRevenue: 245000,
    monthlyRevenue: 32000,
    clientSatisfaction: 4.8,
    hoursLogged: 156,
    upcomingMeetings: 3
  });

  const [recentActivities] = useState<RecentActivity[]>([
    {
      id: '1',
      type: 'project',
      title: 'Digital Transformation Strategy',
      description: 'Updated project milestone for Phase 2 completion',
      timestamp: '2 hours ago',
      status: 'completed'
    },
    {
      id: '2',
      type: 'meeting',
      title: 'Client Review - TechCorp',
      description: 'Quarterly business review scheduled',
      timestamp: '4 hours ago',
      status: 'scheduled'
    },
    {
      id: '3',
      type: 'document',
      title: 'Market Analysis Report',
      description: 'Final report submitted to client',
      timestamp: '1 day ago',
      status: 'submitted'
    },
    {
      id: '4',
      type: 'client',
      title: 'New Client Onboarding',
      description: 'InnovateStartup added to client portfolio',
      timestamp: '2 days ago',
      status: 'active'
    }
  ]);

  const [upcomingTasks] = useState<UpcomingTask[]>([
    {
      id: '1',
      title: 'Prepare Q4 Strategy Presentation',
      description: 'Create executive summary for quarterly review',
      dueDate: '2025-06-28',
      priority: 'high',
      project: 'Strategic Planning Initiative'
    },
    {
      id: '2',
      title: 'Client Feedback Analysis',
      description: 'Analyze survey responses and prepare action items',
      dueDate: '2025-06-30',
      priority: 'medium',
      project: 'Customer Experience Project'
    },
    {
      id: '3',
      title: 'Team Performance Review',
      description: 'Complete mid-year performance evaluations',
      dueDate: '2025-07-02',
      priority: 'medium'
    },
    {
      id: '4',
      title: 'Invoice Processing',
      description: 'Submit invoices for completed project milestones',
      dueDate: '2025-06-27',
      priority: 'high'
    }
  ]);

  useEffect(() => {
    const initializeDashboard = async () => {
      try {
        if (!AuthService.isAuthenticated()) {
          router.push('/auth/login');
          return;
        }

        const storedUser = AuthService.getUser();
        if (storedUser) {
          setUser(storedUser);
        }

        const validatedUser = await AuthService.validateSession();
        if (!validatedUser) {
          router.push('/auth/login');
          return;
        }
        
        setUser(validatedUser);
      } catch (error) {
        console.error('Dashboard initialization error:', error);
        router.push('/auth/login');
      } finally {
        setIsLoading(false);
      }
    };

    initializeDashboard();
  }, [router]);

  const handleLogout = async () => {
    setIsLoadingLogout(true);
    try {
      await apiClient.logout();
      AuthService.clearAuth();
      router.push('/auth/login');
    } catch (error) {
      console.error('Logout error:', error);
      AuthService.clearAuth();
      router.push('/auth/login');
    } finally {
      setIsLoadingLogout(false);
    }
  };

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0,
    }).format(amount);
  };

  const getTimeFromNow = (timestamp: string) => {
    return timestamp; // In production, use a proper date library like date-fns
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'high': return 'bg-red-100 text-red-800';
      case 'medium': return 'bg-yellow-100 text-yellow-800';
      case 'low': return 'bg-green-100 text-green-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'project': return '📋';
      case 'client': return '👥';
      case 'meeting': return '📅';
      case 'document': return '📄';
      default: return '📌';
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="flex flex-col items-center space-y-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          <p className="text-gray-600">Loading your dashboard...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <p className="text-gray-600 mb-4">Unable to load user data</p>
          <Button onClick={() => router.push('/auth/login')}>
            Go to Login
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-8">
              <h1 className="text-xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                InsightSerenity
              </h1>
              <nav className="hidden md:flex space-x-6">
                <a href="#" className="text-gray-700 hover:text-blue-600 px-3 py-2 text-sm font-medium border-b-2 border-blue-600">
                  Dashboard
                </a>
                <a href="#" className="text-gray-500 hover:text-gray-700 px-3 py-2 text-sm font-medium">
                  Projects
                </a>
                <a href="#" className="text-gray-500 hover:text-gray-700 px-3 py-2 text-sm font-medium">
                  Clients
                </a>
                <a href="#" className="text-gray-500 hover:text-gray-700 px-3 py-2 text-sm font-medium">
                  Reports
                </a>
              </nav>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <p className="text-sm font-medium text-gray-900">{user.firstName} {user.lastName}</p>
                <p className="text-xs text-gray-500 capitalize">{user.role.primary.replace(/_/g, ' ')}</p>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={handleLogout}
                isLoading={isLoadingLogout}
                disabled={isLoadingLogout}
              >
                {isLoadingLogout ? 'Signing out...' : 'Sign Out'}
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Welcome Section */}
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-gray-900 mb-2">
            Welcome back, {user.firstName}
          </h2>
          <p className="text-gray-600">
            Here's an overview of your consulting practice and current projects
          </p>
        </div>

        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-6 mb-8">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
                    <span className="text-blue-600 font-semibold">📊</span>
                  </div>
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Active Projects</p>
                  <p className="text-2xl font-bold text-gray-900">{metrics.activeProjects}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-8 h-8 bg-green-100 rounded-lg flex items-center justify-center">
                    <span className="text-green-600 font-semibold">💰</span>
                  </div>
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Total Revenue</p>
                  <p className="text-2xl font-bold text-gray-900">{formatCurrency(metrics.totalRevenue)}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-8 h-8 bg-purple-100 rounded-lg flex items-center justify-center">
                    <span className="text-purple-600 font-semibold">📈</span>
                  </div>
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Monthly Revenue</p>
                  <p className="text-2xl font-bold text-gray-900">{formatCurrency(metrics.monthlyRevenue)}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-8 h-8 bg-yellow-100 rounded-lg flex items-center justify-center">
                    <span className="text-yellow-600 font-semibold">⭐</span>
                  </div>
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Client Rating</p>
                  <p className="text-2xl font-bold text-gray-900">{metrics.clientSatisfaction}/5.0</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-8 h-8 bg-indigo-100 rounded-lg flex items-center justify-center">
                    <span className="text-indigo-600 font-semibold">⏱️</span>
                  </div>
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Hours This Month</p>
                  <p className="text-2xl font-bold text-gray-900">{metrics.hoursLogged}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="w-8 h-8 bg-red-100 rounded-lg flex items-center justify-center">
                    <span className="text-red-600 font-semibold">📅</span>
                  </div>
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Upcoming Meetings</p>
                  <p className="text-2xl font-bold text-gray-900">{metrics.upcomingMeetings}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Main Dashboard Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Left Column - Tasks and Activities */}
          <div className="lg:col-span-2 space-y-8">
            
            {/* Recent Activity */}
            <Card>
              <CardHeader>
                <CardTitle>Recent Activity</CardTitle>
                <CardDescription>Your latest project updates and activities</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {recentActivities.map((activity) => (
                    <div key={activity.id} className="flex items-start space-x-4 p-4 rounded-lg bg-gray-50 hover:bg-gray-100 transition-colors">
                      <div className="flex-shrink-0">
                        <span className="text-2xl">{getActivityIcon(activity.type)}</span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-gray-900 truncate">
                          {activity.title}
                        </p>
                        <p className="text-sm text-gray-500">
                          {activity.description}
                        </p>
                        <div className="flex items-center mt-2 space-x-2">
                          <span className="text-xs text-gray-400">{getTimeFromNow(activity.timestamp)}</span>
                          {activity.status && (
                            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
                              activity.status === 'completed' ? 'bg-green-100 text-green-800' :
                              activity.status === 'scheduled' ? 'bg-blue-100 text-blue-800' :
                              activity.status === 'submitted' ? 'bg-purple-100 text-purple-800' :
                              'bg-gray-100 text-gray-800'
                            }`}>
                              {activity.status}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="mt-6">
                  <Button variant="outline" className="w-full">
                    View All Activities
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Upcoming Tasks */}
            <Card>
              <CardHeader>
                <CardTitle>Upcoming Tasks</CardTitle>
                <CardDescription>Tasks and deliverables requiring your attention</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {upcomingTasks.map((task) => (
                    <div key={task.id} className="flex items-start space-x-4 p-4 rounded-lg border border-gray-200 hover:border-gray-300 transition-colors">
                      <div className="flex-shrink-0 mt-1">
                        <input type="checkbox" className="h-4 w-4 text-blue-600 rounded border-gray-300 focus:ring-blue-500" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <p className="text-sm font-medium text-gray-900">
                            {task.title}
                          </p>
                          <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getPriorityColor(task.priority)}`}>
                            {task.priority}
                          </span>
                        </div>
                        <p className="text-sm text-gray-500 mt-1">
                          {task.description}
                        </p>
                        <div className="flex items-center mt-2 space-x-4 text-xs text-gray-400">
                          <span>Due: {task.dueDate}</span>
                          {task.project && <span>Project: {task.project}</span>}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="mt-6">
                  <Button className="w-full">
                    View All Tasks
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Right Column - Quick Actions and Summary */}
          <div className="space-y-8">
            
            {/* Quick Actions */}
            <Card>
              <CardHeader>
                <CardTitle>Quick Actions</CardTitle>
                <CardDescription>Frequently used tools and shortcuts</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-3">
                  <Button className="h-20 flex flex-col items-center justify-center space-y-2">
                    <span className="text-2xl">📝</span>
                    <span className="text-xs">New Project</span>
                  </Button>
                  <Button variant="outline" className="h-20 flex flex-col items-center justify-center space-y-2">
                    <span className="text-2xl">👥</span>
                    <span className="text-xs">Add Client</span>
                  </Button>
                  <Button variant="outline" className="h-20 flex flex-col items-center justify-center space-y-2">
                    <span className="text-2xl">📊</span>
                    <span className="text-xs">Generate Report</span>
                  </Button>
                  <Button variant="outline" className="h-20 flex flex-col items-center justify-center space-y-2">
                    <span className="text-2xl">🕐</span>
                    <span className="text-xs">Log Time</span>
                  </Button>
                  <Button variant="outline" className="h-20 flex flex-col items-center justify-center space-y-2">
                    <span className="text-2xl">💼</span>
                    <span className="text-xs">Create Proposal</span>
                  </Button>
                  <Button variant="outline" className="h-20 flex flex-col items-center justify-center space-y-2">
                    <span className="text-2xl">📋</span>
                    <span className="text-xs">Schedule Meeting</span>
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Account Status */}
            <Card>
              <CardHeader>
                <CardTitle>Account Status</CardTitle>
                <CardDescription>Your account information and settings</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">Profile Completion</span>
                    <div className="flex items-center space-x-2">
                      <div className="w-20 bg-gray-200 rounded-full h-2">
                        <div className="bg-blue-600 h-2 rounded-full" style={{ width: '85%' }}></div>
                      </div>
                      <span className="text-sm text-gray-500">85%</span>
                    </div>
                  </div>
                  
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Email Verification</span>
                      <span className={`text-sm ${user.isEmailVerified ? 'text-green-600' : 'text-red-600'}`}>
                        {user.isEmailVerified ? '✓ Verified' : '✗ Pending'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Two-Factor Auth</span>
                      <span className="text-sm text-yellow-600">⚠ Not Enabled</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Billing Status</span>
                      <span className="text-sm text-green-600">✓ Active</span>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-gray-200">
                    <Button variant="outline" size="sm" className="w-full">
                      Account Settings
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Performance Summary */}
            <Card>
              <CardHeader>
                <CardTitle>This Month's Performance</CardTitle>
                <CardDescription>Key performance indicators for June 2025</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Revenue Target</span>
                    <div className="flex items-center space-x-2">
                      <div className="w-16 bg-gray-200 rounded-full h-2">
                        <div className="bg-green-500 h-2 rounded-full" style={{ width: '80%' }}></div>
                      </div>
                      <span className="text-sm text-gray-500">80%</span>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Hours Target</span>
                    <div className="flex items-center space-x-2">
                      <div className="w-16 bg-gray-200 rounded-full h-2">
                        <div className="bg-blue-500 h-2 rounded-full" style={{ width: '95%' }}></div>
                      </div>
                      <span className="text-sm text-gray-500">95%</span>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Client Satisfaction</span>
                    <div className="flex items-center space-x-2">
                      <div className="w-16 bg-gray-200 rounded-full h-2">
                        <div className="bg-yellow-500 h-2 rounded-full" style={{ width: '96%' }}></div>
                      </div>
                      <span className="text-sm text-gray-500">96%</span>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-gray-200">
                    <p className="text-xs text-gray-500 mb-3">Compared to last month:</p>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs">Revenue</span>
                        <span className="text-xs text-green-600">↗ +12%</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs">New Clients</span>
                        <span className="text-xs text-green-600">↗ +3</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs">Project Completion</span>
                        <span className="text-xs text-green-600">↗ +8%</span>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="mt-12 bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-medium text-gray-900">Need assistance with your consulting practice?</h3>
              <p className="text-sm text-gray-500 mt-1">Our support team is available to help you maximize your productivity and success.</p>
            </div>
            <div className="flex space-x-3">
              <Button variant="outline">
                Contact Support
              </Button>
              <Button>
                Schedule Demo
              </Button>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}