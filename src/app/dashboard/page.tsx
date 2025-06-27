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
  teamMembers: number;
  completedProjects: number;
}

interface RecentActivity {
  id: string;
  type: 'project' | 'client' | 'meeting' | 'document' | 'financial' | 'team';
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
  assignee?: string;
}

interface Notification {
  id: string;
  type: 'info' | 'warning' | 'success' | 'urgent';
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
}

interface QuickAction {
  id: string;
  title: string;
  description: string;
  icon: string;
  action: string;
  color: string;
}

interface RecentDocument {
  id: string;
  name: string;
  type: string;
  lastModified: string;
  project: string;
  size: string;
}

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [recentActivity, setRecentActivity] = useState<RecentActivity[]>([]);
  const [upcomingTasks, setUpcomingTasks] = useState<UpcomingTask[]>([]);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [quickActions, setQuickActions] = useState<QuickAction[]>([]);
  const [recentDocuments, setRecentDocuments] = useState<RecentDocument[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingLogout, setIsLoadingLogout] = useState(false);

  useEffect(() => {
    const loadDashboard = async () => {
      try {
        if (!AuthService.isAuthenticated()) {
          router.push('/auth/login');
          return;
        }

        const userData = AuthService.getUser();
        setUser(userData);

        // Enhanced mock data for demonstration
        setMetrics({
          activeProjects: 12,
          totalRevenue: 284750,
          monthlyRevenue: 47200,
          clientSatisfaction: 4.8,
          hoursLogged: 156,
          upcomingMeetings: 8,
          teamMembers: 6,
          completedProjects: 34
        });

        setRecentActivity([
          {
            id: '1',
            type: 'project',
            title: 'Q4 Strategy Review Completed',
            description: 'Finished comprehensive financial analysis for Fortune 500 client',
            timestamp: '2 hours ago',
            status: 'completed'
          },
          {
            id: '2',
            type: 'meeting',
            title: 'Client Presentation Delivered',
            description: 'Successfully presented quarterly business review to board members',
            timestamp: '4 hours ago',
            status: 'completed'
          },
          {
            id: '3',
            type: 'document',
            title: 'Market Research Report Published',
            description: 'Released comprehensive industry trend analysis report',
            timestamp: '1 day ago',
            status: 'published'
          },
          {
            id: '4',
            type: 'financial',
            title: 'Invoice Payment Received',
            description: 'Payment of $25,000 received from TechCorp Inc.',
            timestamp: '2 days ago',
            status: 'completed'
          },
          {
            id: '5',
            type: 'team',
            title: 'New Team Member Onboarded',
            description: 'Sarah Johnson joined as Senior Analyst',
            timestamp: '3 days ago',
            status: 'active'
          }
        ]);

        setUpcomingTasks([
          {
            id: '1',
            title: 'Prepare Board Meeting Materials',
            description: 'Compile financial reports and strategic recommendations for Q1 review',
            dueDate: 'Tomorrow',
            priority: 'high',
            project: 'Corporate Strategy',
            assignee: 'You'
          },
          {
            id: '2',
            title: 'Client Contract Review',
            description: 'Review and finalize new service agreement terms with GlobalTech',
            dueDate: 'Friday',
            priority: 'medium',
            project: 'Legal Affairs',
            assignee: 'Legal Team'
          },
          {
            id: '3',
            title: 'Team Performance Review',
            description: 'Conduct quarterly performance evaluations for consulting team',
            dueDate: 'Next Week',
            priority: 'medium',
            project: 'Human Resources',
            assignee: 'You'
          },
          {
            id: '4',
            title: 'Financial Audit Preparation',
            description: 'Prepare documentation for annual financial audit requirements',
            dueDate: 'Next Week',
            priority: 'high',
            project: 'Finance',
            assignee: 'Finance Team'
          }
        ]);

        setNotifications([
          {
            id: '1',
            type: 'urgent',
            title: 'Payment Overdue',
            message: 'Invoice #INV-2024-001 is 15 days overdue from DataCorp Inc.',
            timestamp: '1 hour ago',
            read: false
          },
          {
            id: '2',
            type: 'success',
            title: 'Project Milestone Achieved',
            message: 'TechFlow Implementation project reached 75% completion',
            timestamp: '3 hours ago',
            read: false
          },
          {
            id: '3',
            type: 'info',
            title: 'System Maintenance Scheduled',
            message: 'Platform maintenance scheduled for Sunday 2:00 AM - 4:00 AM EST',
            timestamp: '1 day ago',
            read: true
          },
          {
            id: '4',
            type: 'warning',
            title: 'Contract Expiring Soon',
            message: 'Service agreement with InnovateCorp expires in 30 days',
            timestamp: '2 days ago',
            read: true
          }
        ]);

        setQuickActions([
          {
            id: '1',
            title: 'Create New Project',
            description: 'Start a new consulting project',
            icon: 'plus',
            action: '/projects/new',
            color: 'primary'
          },
          {
            id: '2',
            title: 'Schedule Meeting',
            description: 'Book client consultation',
            icon: 'calendar',
            action: '/calendar/new',
            color: 'blue'
          },
          {
            id: '3',
            title: 'Generate Report',
            description: 'Create analytics report',
            icon: 'chart',
            action: '/reports/generate',
            color: 'emerald'
          },
          {
            id: '4',
            title: 'Manage Team',
            description: 'View team members',
            icon: 'users',
            action: '/team',
            color: 'purple'
          },
          {
            id: '5',
            title: 'Send Invoice',
            description: 'Create client invoice',
            icon: 'invoice',
            action: '/invoices/new',
            color: 'orange'
          },
          {
            id: '6',
            title: 'Client Portal',
            description: 'Access client resources',
            icon: 'globe',
            action: '/clients',
            color: 'indigo'
          }
        ]);

        setRecentDocuments([
          {
            id: '1',
            name: 'Q4_Financial_Analysis.pdf',
            type: 'PDF',
            lastModified: '2 hours ago',
            project: 'TechCorp Strategy',
            size: '2.4 MB'
          },
          {
            id: '2',
            name: 'Market_Research_Report_2024.docx',
            type: 'Document',
            lastModified: '1 day ago',
            project: 'Industry Analysis',
            size: '1.8 MB'
          },
          {
            id: '3',
            name: 'Client_Presentation_Dec2024.pptx',
            type: 'Presentation',
            lastModified: '2 days ago',
            project: 'GlobalTech Review',
            size: '5.2 MB'
          },
          {
            id: '4',
            name: 'Team_Performance_Metrics.xlsx',
            type: 'Spreadsheet',
            lastModified: '3 days ago',
            project: 'HR Analytics',
            size: '892 KB'
          }
        ]);

      } catch (error) {
        console.error('Dashboard loading error:', error);
      } finally {
        setIsLoading(false);
      }
    };

    loadDashboard();
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

  const getNotificationColor = (type: string) => {
    switch (type) {
      case 'urgent': return 'text-red-600 bg-red-50 border-red-200';
      case 'warning': return 'text-amber-600 bg-amber-50 border-amber-200';
      case 'success': return 'text-emerald-600 bg-emerald-50 border-emerald-200';
      case 'info': return 'text-blue-600 bg-blue-50 border-blue-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getQuickActionColor = (color: string) => {
    switch (color) {
      case 'primary': return 'from-primary to-accent';
      case 'blue': return 'from-blue-500 to-blue-600';
      case 'emerald': return 'from-emerald-500 to-emerald-600';
      case 'purple': return 'from-purple-500 to-purple-600';
      case 'orange': return 'from-orange-500 to-orange-600';
      case 'indigo': return 'from-indigo-500 to-indigo-600';
      default: return 'from-gray-500 to-gray-600';
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-background to-surface flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-4 border-primary border-t-transparent mx-auto"></div>
          <p className="mt-4 text-text-secondary font-medium">Loading your comprehensive dashboard...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-surface to-gold-50/20">
      {/* Navigation Header */}
      <header className="bg-surface shadow-business-lg border-b-2 border-primary/20 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-18">
            <div className="flex items-center space-x-8">
              <h1 className="text-2xl font-bold text-gradient-gold">
                InsightSerenity
              </h1>
              <nav className="hidden md:flex space-x-6">
                <a href="#" className="text-text-primary hover:text-primary px-4 py-3 text-sm font-semibold border-b-3 border-primary transition-all duration-300">
                  Dashboard
                </a>
                <a href="#" className="text-text-secondary hover:text-text-primary px-4 py-3 text-sm font-medium transition-colors duration-300">
                  Projects
                </a>
                <a href="#" className="text-text-secondary hover:text-text-primary px-4 py-3 text-sm font-medium transition-colors duration-300">
                  Clients
                </a>
                <a href="#" className="text-text-secondary hover:text-text-primary px-4 py-3 text-sm font-medium transition-colors duration-300">
                  Reports
                </a>
                <a href="#" className="text-text-secondary hover:text-text-primary px-4 py-3 text-sm font-medium transition-colors duration-300">
                  Team
                </a>
              </nav>
            </div>
            <div className="flex items-center space-x-6">
              {/* Notifications */}
              <div className="relative">
                <button className="p-2 text-text-secondary hover:text-text-primary transition-colors duration-300">
                  <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-5 5v-5zM9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  {notifications.filter(n => !n.read).length > 0 && (
                    <span className="absolute -top-1 -right-1 h-4 w-4 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
                      {notifications.filter(n => !n.read).length}
                    </span>
                  )}
                </button>
              </div>
              
              {/* User Profile */}
              <div className="flex items-center space-x-3">
                <div className="text-right">
                  <p className="text-sm font-bold text-text-primary">{user.firstName} {user.lastName}</p>
                  <p className="text-xs text-text-secondary font-medium capitalize">{user.role.primary.replace(/_/g, ' ')}</p>
                </div>
                <div className="h-10 w-10 bg-gradient-to-r from-primary to-accent rounded-full flex items-center justify-center text-secondary font-bold">
                  {user.firstName.charAt(0)}{user.lastName.charAt(0)}
                </div>
              </div>
              
              <Button
                variant="outline"
                size="sm"
                onClick={handleLogout}
                isLoading={isLoadingLogout}
                disabled={isLoadingLogout}
              >
                {isLoadingLogout ? 'Signing Out...' : 'Sign Out'}
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Welcome Section with Account Status */}
        <div className="mb-8 animate-fade-up">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between">
            <div>
              <h2 className="text-3xl font-bold text-text-primary mb-2">
                Welcome back, {user.firstName}
              </h2>
              <p className="text-text-secondary font-medium">
                Your consulting practice is performing exceptionally well. Here is your comprehensive business overview.
              </p>
            </div>
            <div className="mt-4 lg:mt-0">
              <Card variant="premium" className="min-w-80">
                <CardContent>
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-text-secondary">Account Status</p>
                      <div className="flex items-center space-x-2 mt-1">
                        <div className="h-2 w-2 bg-emerald-500 rounded-full animate-pulse"></div>
                        <span className="text-sm font-semibold text-emerald-600">Professional Plan</span>
                      </div>
                      <p className="text-xs text-text-muted mt-1">
                        {user.isEmailVerified ? 'Verified Account' : 'Pending Verification'} • Active since {new Date(user.createdAt).getFullYear()}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-text-muted">Next Billing</p>
                      <p className="text-sm font-semibold text-text-primary">Jan 15, 2025</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="mb-8 animate-fade-up">
          <h3 className="text-xl font-bold text-text-primary mb-4">Quick Actions</h3>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            {quickActions.map((action) => (
              <button
                key={action.id}
                className="p-4 bg-surface border border-border rounded-xl hover:border-primary/30 transition-all duration-300 group hover:shadow-business text-left"
              >
                <div className={`h-10 w-10 bg-gradient-to-r ${getQuickActionColor(action.color)} rounded-lg flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300`}>
                  <svg className="h-5 w-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                  </svg>
                </div>
                <h4 className="font-semibold text-text-primary text-sm mb-1">{action.title}</h4>
                <p className="text-xs text-text-muted">{action.description}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Key Metrics Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <Card variant="premium" className="animate-fade-up">
            <CardContent>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-text-secondary mb-1">Active Projects</p>
                  <p className="text-3xl font-bold text-text-primary">{metrics?.activeProjects}</p>
                  <p className="text-xs text-emerald-600 font-medium">↗ +2 this month</p>
                </div>
                <div className="h-12 w-12 bg-gradient-to-r from-primary to-accent rounded-xl flex items-center justify-center">
                  <svg className="h-6 w-6 text-secondary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card variant="premium" className="animate-fade-up" style={{ animationDelay: '0.1s' }}>
            <CardContent>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-text-secondary mb-1">Total Revenue</p>
                  <p className="text-3xl font-bold text-text-primary">${metrics?.totalRevenue?.toLocaleString()}</p>
                  <p className="text-xs text-emerald-600 font-medium">↗ +12% YoY</p>
                </div>
                <div className="h-12 w-12 bg-gradient-to-r from-secondary to-secondary-light rounded-xl flex items-center justify-center">
                  <svg className="h-6 w-6 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1" />
                  </svg>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card variant="premium" className="animate-fade-up" style={{ animationDelay: '0.2s' }}>
            <CardContent>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-text-secondary mb-1">Team Members</p>
                  <p className="text-3xl font-bold text-text-primary">{metrics?.teamMembers}</p>
                  <p className="text-xs text-blue-600 font-medium">↗ +1 this quarter</p>
                </div>
                <div className="h-12 w-12 bg-gradient-to-r from-blue-500 to-blue-600 rounded-xl flex items-center justify-center">
                  <svg className="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                  </svg>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card variant="premium" className="animate-fade-up" style={{ animationDelay: '0.3s' }}>
            <CardContent>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-text-secondary mb-1">Client Satisfaction</p>
                  <p className="text-3xl font-bold text-text-primary">{metrics?.clientSatisfaction}/5.0</p>
                  <p className="text-xs text-emerald-600 font-medium">↗ +0.2 this quarter</p>
                </div>
                <div className="h-12 w-12 bg-gradient-to-r from-primary to-accent rounded-xl flex items-center justify-center">
                  <svg className="h-6 w-6 text-secondary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
                  </svg>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
          {/* Recent Activity */}
          <Card variant="elevated" className="lg:col-span-2 animate-fade-up" style={{ animationDelay: '0.4s' }}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Recent Activity</CardTitle>
                  <CardDescription>Your latest business activities and achievements</CardDescription>
                </div>
                <Button variant="ghost" size="sm">View All</Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {recentActivity.map((activity) => (
                  <div key={activity.id} className="flex items-start space-x-4 p-4 bg-muted rounded-lg hover:bg-gold-50/30 transition-colors duration-300">
                    <div className={`h-10 w-10 rounded-lg flex items-center justify-center flex-shrink-0 ${
                      activity.type === 'project' ? 'bg-gradient-to-r from-primary to-accent' :
                      activity.type === 'meeting' ? 'bg-gradient-to-r from-blue-500 to-blue-600' :
                      activity.type === 'document' ? 'bg-gradient-to-r from-emerald-500 to-emerald-600' :
                      activity.type === 'financial' ? 'bg-gradient-to-r from-orange-500 to-orange-600' :
                      'bg-gradient-to-r from-purple-500 to-purple-600'
                    }`}>
                      <svg className="h-5 w-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </div>
                    <div className="flex-1">
                      <h4 className="font-semibold text-text-primary">{activity.title}</h4>
                      <p className="text-sm text-text-secondary mb-1">{activity.description}</p>
                      <p className="text-xs text-text-muted font-medium">{activity.timestamp}</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Notifications */}
          <Card variant="elevated" className="animate-fade-up" style={{ animationDelay: '0.5s' }}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Notifications</CardTitle>
                  <CardDescription>Important updates and alerts</CardDescription>
                </div>
                <span className="text-xs text-text-muted">{notifications.filter(n => !n.read).length} unread</span>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {notifications.slice(0, 4).map((notification) => (
                  <div key={notification.id} className={`p-3 rounded-lg border ${getNotificationColor(notification.type)} ${!notification.read ? 'ring-2 ring-offset-1 ring-primary/20' : ''}`}>
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <h5 className="font-semibold text-sm">{notification.title}</h5>
                        <p className="text-xs mt-1">{notification.message}</p>
                        <p className="text-xs mt-2 opacity-75">{notification.timestamp}</p>
                      </div>
                      {!notification.read && (
                        <div className="h-2 w-2 bg-primary rounded-full ml-2 mt-1"></div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-4">
                <Button variant="ghost" size="sm" className="w-full">View All Notifications</Button>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Additional Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          {/* Upcoming Tasks */}
          <Card variant="elevated" className="animate-fade-up" style={{ animationDelay: '0.6s' }}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Upcoming Tasks</CardTitle>
                  <CardDescription>Priority items requiring your attention</CardDescription>
                </div>
                <Button variant="outline" size="sm">Add Task</Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {upcomingTasks.map((task) => (
                  <div key={task.id} className="p-4 border border-border rounded-lg hover:border-primary/30 transition-colors duration-300">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <h4 className="font-semibold text-text-primary mb-1">{task.title}</h4>
                        <p className="text-sm text-text-secondary mb-2">{task.description}</p>
                        <div className="flex items-center space-x-3">
                          <span className="text-xs bg-gold-100 text-gold-800 px-2 py-1 rounded-full font-medium">
                            {task.project}
                          </span>
                          <span className="text-xs text-text-muted font-medium">Due: {task.dueDate}</span>
                          <span className="text-xs text-text-muted font-medium">Assigned: {task.assignee}</span>
                        </div>
                      </div>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                        task.priority === 'high' 
                          ? 'bg-red-100 text-red-700' 
                          : task.priority === 'medium'
                          ? 'bg-yellow-100 text-yellow-700'
                          : 'bg-green-100 text-green-700'
                      }`}>
                        {task.priority}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Recent Documents */}
          <Card variant="elevated" className="animate-fade-up" style={{ animationDelay: '0.7s' }}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Recent Documents</CardTitle>
                  <CardDescription>Recently accessed files and reports</CardDescription>
                </div>
                <Button variant="outline" size="sm">View All</Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {recentDocuments.map((doc) => (
                  <div key={doc.id} className="flex items-center space-x-4 p-3 bg-muted rounded-lg hover:bg-gold-50/30 transition-colors duration-300 cursor-pointer">
                    <div className={`h-10 w-10 rounded-lg flex items-center justify-center flex-shrink-0 ${
                      doc.type === 'PDF' ? 'bg-red-100 text-red-600' :
                      doc.type === 'Document' ? 'bg-blue-100 text-blue-600' :
                      doc.type === 'Presentation' ? 'bg-orange-100 text-orange-600' :
                      'bg-green-100 text-green-600'
                    }`}>
                      <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                    </div>
                    <div className="flex-1 min-w-0">
                      <h5 className="font-medium text-text-primary truncate">{doc.name}</h5>
                      <div className="flex items-center space-x-2 mt-1">
                        <span className="text-xs text-text-muted">{doc.project}</span>
                        <span className="text-xs text-text-muted">•</span>
                        <span className="text-xs text-text-muted">{doc.size}</span>
                      </div>
                      <p className="text-xs text-text-muted mt-1">{doc.lastModified}</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Performance Summary */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <Card variant="premium" className="animate-fade-up" style={{ animationDelay: '0.8s' }}>
            <CardContent>
              <div className="text-center">
                <div className="h-16 w-16 bg-gradient-to-r from-emerald-500 to-emerald-600 rounded-full flex items-center justify-center mx-auto mb-4">
                  <svg className="h-8 w-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-text-primary mb-2">Projects Completed</h3>
                <p className="text-3xl font-bold text-emerald-600 mb-2">{metrics?.completedProjects}</p>
                <p className="text-sm text-text-secondary">This fiscal year</p>
              </div>
            </CardContent>
          </Card>

          <Card variant="premium" className="animate-fade-up" style={{ animationDelay: '0.9s' }}>
            <CardContent>
              <div className="text-center">
                <div className="h-16 w-16 bg-gradient-to-r from-blue-500 to-blue-600 rounded-full flex items-center justify-center mx-auto mb-4">
                  <svg className="h-8 w-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-text-primary mb-2">Hours Logged</h3>
                <p className="text-3xl font-bold text-blue-600 mb-2">{metrics?.hoursLogged}</p>
                <p className="text-sm text-text-secondary">This month</p>
              </div>
            </CardContent>
          </Card>

          <Card variant="premium" className="animate-fade-up" style={{ animationDelay: '1s' }}>
            <CardContent>
              <div className="text-center">
                <div className="h-16 w-16 bg-gradient-to-r from-purple-500 to-purple-600 rounded-full flex items-center justify-center mx-auto mb-4">
                  <svg className="h-8 w-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                  </svg>
                </div>
                <h3 className="text-xl font-bold text-text-primary mb-2">Upcoming Meetings</h3>
                <p className="text-3xl font-bold text-purple-600 mb-2">{metrics?.upcomingMeetings}</p>
                <p className="text-sm text-text-secondary">Next 7 days</p>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Footer Actions */}
        <Card variant="glass" className="bg-gradient-to-r from-secondary/5 to-primary/10 animate-fade-up" style={{ animationDelay: '1.1s' }}>
          <CardContent>
            <div className="flex flex-col lg:flex-row items-center justify-between">
              <div className="text-center lg:text-left mb-6 lg:mb-0">
                <h3 className="text-xl font-bold text-text-primary mb-2">Accelerate Your Consulting Excellence</h3>
                <p className="text-text-secondary font-medium max-w-2xl">
                  Our expert support team is ready to help you maximize productivity and drive exceptional results for your consulting practice. Access premium resources and dedicated assistance.
                </p>
              </div>
              <div className="flex flex-col sm:flex-row space-y-3 sm:space-y-0 sm:space-x-4">
                <Button variant="outline" size="lg" className="min-w-48">
                  Contact Support
                </Button>
                <Button variant="primary" size="lg" className="min-w-48">
                  Schedule Consultation
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}