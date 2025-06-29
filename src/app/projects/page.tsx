// src/app/projects/page.tsx
'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AuthService } from '@/lib/auth';
import { Button } from '@/components/ui/Button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/Card';
import { apiClient } from '@/lib/api';

interface Project {
  _id: string;
  projectId: string;
  name: string;
  code: string;
  description: string;
  status: 'draft' | 'pending_approval' | 'approved' | 'active' | 'on_hold' | 'completed' | 'cancelled' | 'archived';
  priority: 'low' | 'medium' | 'high' | 'critical';
  complexity: 'simple' | 'moderate' | 'complex' | 'highly_complex';
  phase: {
    current: 'initiation' | 'planning' | 'execution' | 'monitoring' | 'closure';
  };
  client: {
    _id: string;
    name: string;
    code: string;
  };
  timeline: {
    estimatedStartDate: string;
    estimatedEndDate: string;
    actualStartDate?: string;
    actualEndDate?: string;
  };
  financial: {
    budget: {
      total: {
        amount: number;
        currency: string;
      };
    };
  };
  team: {
    projectManager: {
      _id: string;
      firstName: string;
      lastName: string;
    };
    members: Array<{
      consultant: {
        _id: string;
        firstName: string;
        lastName: string;
      };
      role: string;
    }>;
  };
  progress: number;
  healthScore: number;
  createdAt: string;
  updatedAt: string;
}

interface ProjectsResponse {
  success: boolean;
  results: number;
  pagination: {
    total: number;
    page: number;
    pages: number;
    limit: number;
  };
  data: {
    projects: Project[];
  };
}

const ProjectsPage = () => {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState({
    status: '',
    priority: '',
    search: '',
    client: '',
  });
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 20,
    total: 0,
    pages: 0,
  });
  const router = useRouter();

  useEffect(() => {
    const checkAuthAndLoadProjects = async () => {
      try {
        const isLoggedIn = await AuthService.isAuthenticated();
        if (!isLoggedIn) {
          router.push('/login');
          return;
        }

        await loadProjects();
      } catch (err) {
        console.error('Authentication check failed:', err);
        router.push('/login');
      }
    };

    checkAuthAndLoadProjects();
  }, [router, pagination.page, filters]);

  const loadProjects = async () => {
    try {
      setLoading(true);
      setError(null);

      const params = new URLSearchParams({
        page: pagination.page.toString(),
        limit: pagination.limit.toString(),
        ...(filters.status && { status: filters.status }),
        ...(filters.priority && { priority: filters.priority }),
        ...(filters.search && { search: filters.search }),
        ...(filters.client && { client: filters.client }),
      });

      const response: ProjectsResponse = await apiClient.getProjects(Object.fromEntries(params));

      if (response.success) {
        setProjects(response.data.projects);
        setPagination(prev => ({
          ...prev,
          total: response.pagination.total,
          pages: response.pagination.pages,
        }));
      } else {
        setError('Failed to load projects');
      }
    } catch (err: any) {
      console.error('Projects fetch error:', err);
      setError(err.message || 'Failed to load projects');

      if (err.status === 401) {
        router.push('/login');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (key: string, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  const handlePageChange = (newPage: number) => {
    setPagination(prev => ({ ...prev, page: newPage }));
  };

  const getStatusColor = (status: string): string => {
    const colors: Record<string, string> = {
      draft: 'bg-gray-100 text-gray-800',
      pending_approval: 'bg-yellow-100 text-yellow-800',
      approved: 'bg-blue-100 text-blue-800',
      active: 'bg-green-100 text-green-800',
      on_hold: 'bg-orange-100 text-orange-800',
      completed: 'bg-purple-100 text-purple-800',
      cancelled: 'bg-red-100 text-red-800',
      archived: 'bg-gray-100 text-gray-600',
    };
    return colors[status] || 'bg-gray-100 text-gray-800';
  };

  const getPriorityColor = (priority: string): string => {
    const colors: Record<string, string> = {
      low: 'text-green-600',
      medium: 'text-yellow-600',
      high: 'text-orange-600',
      critical: 'text-red-600',
    };
    return colors[priority] || 'text-gray-600';
  };

  const formatCurrency = (amount: number, currency: string = 'USD'): string => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency,
      minimumFractionDigits: 0,
      maximumFractionDigits: 0,
    }).format(amount);
  };

  const formatDate = (dateString: string): string => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  const renderPagination = () => {
    if (pagination.pages <= 1) return null;

    const pages = [];
    const currentPage = pagination.page;
    const totalPages = pagination.pages;

    // Previous button
    pages.push(
      <Button
        key="prev"
        onClick={() => handlePageChange(currentPage - 1)}
        disabled={currentPage === 1}
        variant="outline"
        size="sm"
      >
        Previous
      </Button>
    );

    // Page numbers
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);

    for (let i = startPage; i <= endPage; i++) {
      pages.push(
        <Button
          key={i}
          onClick={() => handlePageChange(i)}
          variant={i === currentPage ? 'default' : 'outline'}
          size="sm"
        >
          {i}
        </Button>
      );
    }

    // Next button
    pages.push(
      <Button
        key="next"
        onClick={() => handlePageChange(currentPage + 1)}
        disabled={currentPage === totalPages}
        variant="outline"
        size="sm"
      >
        Next
      </Button>
    );

    return (
      <div className="flex items-center justify-center space-x-2 mt-6">
        {pages}
      </div>
    );
  };

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
              <h1 className="text-2xl font-bold text-gray-900">Projects</h1>
            </div>
            <div className="flex items-center space-x-4">
              <Button onClick={() => router.push('/projects/new')}>
                New Project
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Filters */}
        <Card className="mb-6">
          <CardContent className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Search
                </label>
                <input
                  type="text"
                  placeholder="Search projects..."
                  value={filters.search}
                  onChange={(e) => handleFilterChange('search', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Status
                </label>
                <select
                  value={filters.status}
                  onChange={(e) => handleFilterChange('status', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">All Statuses</option>
                  <option value="draft">Draft</option>
                  <option value="active">Active</option>
                  <option value="completed">Completed</option>
                  <option value="on_hold">On Hold</option>
                  <option value="cancelled">Cancelled</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Priority
                </label>
                <select
                  value={filters.priority}
                  onChange={(e) => handleFilterChange('priority', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">All Priorities</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>

              <div className="flex items-end">
                <Button
                  onClick={() => {
                    setFilters({ status: '', priority: '', search: '', client: '' });
                    setPagination(prev => ({ ...prev, page: 1 }));
                  }}
                  variant="outline"
                  className="w-full"
                >
                  Clear Filters
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Results Summary */}
        <div className="mb-6">
          <p className="text-sm text-gray-600">
            Showing {projects.length} of {pagination.total} projects
          </p>
        </div>

        {/* Error State */}
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-md">
            <p className="text-red-600 text-sm">{error}</p>
            <Button onClick={loadProjects} className="mt-2" size="sm">
              Retry
            </Button>
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
            <p className="mt-4 text-gray-600">Loading projects...</p>
          </div>
        )}

        {/* Projects Grid */}
        {!loading && projects.length > 0 && (
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
            {projects.map((project) => (
              <Card
                key={project._id}
                className="cursor-pointer hover:shadow-md transition-shadow"
                onClick={() => router.push(`/projects/${project._id}`)}
              >
                <CardHeader>
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <CardTitle className="text-lg mb-1">{project.name}</CardTitle>
                      <CardDescription className="text-sm">
                        {project.code} • {project.client.name}
                      </CardDescription>
                    </div>
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(project.status)}`}>
                      {project.status.replace('_', ' ')}
                    </span>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {/* Project Details */}
                    <div className="text-sm text-gray-600">
                      <p className="truncate">{project.description}</p>
                    </div>

                    {/* Progress Bar */}
                    <div>
                      <div className="flex justify-between text-sm mb-1">
                        <span>Progress</span>
                        <span>{project.progress}%</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div
                          className="bg-blue-600 h-2 rounded-full transition-all"
                          style={{ width: `${project.progress}%` }}
                        ></div>
                      </div>
                    </div>

                    {/* Key Metrics */}
                    <div className="grid grid-cols-2 gap-3 text-sm">
                      <div>
                        <span className="text-gray-600">Budget:</span>
                        <p className="font-medium">
                          {formatCurrency(project.financial.budget.total.amount)}
                        </p>
                      </div>
                      <div>
                        <span className="text-gray-600">Health:</span>
                        <p className="font-medium">{project.healthScore}/10</p>
                      </div>
                    </div>

                    {/* Timeline */}
                    <div className="text-sm">
                      <span className="text-gray-600">Timeline:</span>
                      <p className="font-medium">
                        {formatDate(project.timeline.estimatedStartDate)} - {formatDate(project.timeline.estimatedEndDate)}
                      </p>
                    </div>

                    {/* Priority and Phase */}
                    <div className="flex justify-between items-center text-sm">
                      <div>
                        <span className="text-gray-600">Priority:</span>
                        <span className={`ml-1 font-medium ${getPriorityColor(project.priority)}`}>
                          {project.priority}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-600">Phase:</span>
                        <span className="ml-1 font-medium">{project.phase.current}</span>
                      </div>
                    </div>

                    {/* Team */}
                    <div className="text-sm">
                      <span className="text-gray-600">PM:</span>
                      <span className="ml-1 font-medium">
                        {project.team.projectManager.firstName} {project.team.projectManager.lastName}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Empty State */}
        {!loading && projects.length === 0 && !error && (
          <div className="text-center py-12">
            <div className="text-6xl mb-4">📊</div>
            <h3 className="text-lg font-medium text-gray-900 mb-2">No projects found</h3>
            <p className="text-gray-600 mb-4">
              {Object.values(filters).some(f => f) 
                ? 'Try adjusting your filters to see more projects.'
                : 'Get started by creating your first project.'}
            </p>
            {!Object.values(filters).some(f => f) && (
              <Button onClick={() => router.push('/projects/new')}>
                Create New Project
              </Button>
            )}
          </div>
        )}

        {/* Pagination */}
        {renderPagination()}
      </main>
    </div>
  );
};

export default ProjectsPage;