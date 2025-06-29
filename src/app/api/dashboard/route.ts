// src/app/api/dashboard/route.ts
import { NextRequest, NextResponse } from 'next/server';

const API_BASE_URL = process.env.BACKEND_API_URL || 'http://localhost:5001/api';

export async function GET(request: NextRequest) {
  try {
    const accessToken = request.cookies.get('accessToken')?.value;

    if (!accessToken) {
      return NextResponse.json(
        {
          success: false,
          error: { message: 'Authentication required' },
        },
        { status: 401 }
      );
    }

    // Fetch data from multiple backend endpoints in parallel
    const [projectStatsResponse, clientStatsResponse, userResponse] = await Promise.all([
      fetch(`${API_BASE_URL}/projects/stats`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
      }),
      fetch(`${API_BASE_URL}/clients/stats`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
      }),
      fetch(`${API_BASE_URL}/users/me`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
      })
    ]);

    // Check if all requests were successful
    if (!projectStatsResponse.ok || !clientStatsResponse.ok || !userResponse.ok) {
      return NextResponse.json(
        {
          success: false,
          error: { message: 'Failed to fetch dashboard data' },
        },
        { status: 500 }
      );
    }

    const [projectStats, clientStats, user] = await Promise.all([
      projectStatsResponse.json(),
      clientStatsResponse.json(),
      userResponse.json()
    ]);

    // Aggregate dashboard metrics
    const dashboardData = {
      user: user.data?.user || user.user,
      metrics: {
        activeProjects: projectStats.data?.stats?.byStatus?.active || 0,
        totalRevenue: clientStats.data?.stats?.totalLifetimeValue || 0,
        monthlyRevenue: calculateMonthlyRevenue(projectStats.data?.stats),
        clientSatisfaction: clientStats.data?.stats?.averageHealthScore || 0,
        hoursLogged: calculateHoursLogged(projectStats.data?.stats),
        upcomingMeetings: 0, // You'll need to implement meetings API
        teamMembers: projectStats.data?.stats?.totalTeamMembers || 0,
        completedProjects: projectStats.data?.stats?.byStatus?.completed || 0,
      },
      recentActivity: generateRecentActivity(projectStats.data?.stats, clientStats.data?.stats),
      upcomingTasks: generateUpcomingTasks(projectStats.data?.stats),
      projects: {
        active: projectStats.data?.stats?.byStatus?.active || 0,
        completed: projectStats.data?.stats?.byStatus?.completed || 0,
        onHold: projectStats.data?.stats?.byStatus?.on_hold || 0,
        overdue: projectStats.data?.stats?.overdueCount || 0,
      },
      clients: {
        total: clientStats.data?.stats?.totalClients || 0,
        highRisk: clientStats.data?.stats?.highRiskCount || 0,
        active: clientStats.data?.stats?.statusBreakdown?.active || 0,
        satisfaction: clientStats.data?.stats?.averageHealthScore || 0,
      }
    };

    return NextResponse.json({
      success: true,
      data: dashboardData
    });
  } catch (error) {
    console.error('Dashboard API error:', error);
    return NextResponse.json(
      {
        success: false,
        error: { message: 'Internal server error' },
      },
      { status: 500 }
    );
  }
}

// Helper functions
function calculateMonthlyRevenue(projectStats: any): number {
  // Calculate based on active projects and their budgets
  // This is a simplified calculation - adjust based on your business logic
  const activeProjects = projectStats?.byStatus?.active || 0;
  const avgProjectValue = projectStats?.averageBudget || 50000;
  return Math.round((activeProjects * avgProjectValue) / 12);
}

function calculateHoursLogged(projectStats: any): number {
  // Calculate total hours logged across all projects
  // This would need to be implemented in your backend project stats
  return projectStats?.totalHoursLogged || 0;
}

function generateRecentActivity(projectStats: any, clientStats: any): any[] {
  // Generate mock recent activity - replace with actual backend data
  const activities = [];
  
  if (projectStats?.recentProjects) {
    projectStats.recentProjects.forEach((project: any, index: number) => {
      activities.push({
        id: `project-${index}`,
        type: 'project',
        title: `Project ${project.name || 'Updated'}`,
        description: `Status changed to ${project.status}`,
        timestamp: new Date(Date.now() - index * 24 * 60 * 60 * 1000).toISOString(),
        status: project.status
      });
    });
  }

  return activities.slice(0, 10);
}

function generateUpcomingTasks(projectStats: any): any[] {
  // Generate upcoming tasks from project data
  const tasks = [];
  
  if (projectStats?.upcomingMilestones) {
    projectStats.upcomingMilestones.forEach((milestone: any, index: number) => {
      tasks.push({
        id: `task-${index}`,
        title: milestone.name || `Milestone ${index + 1}`,
        description: milestone.description || 'Project milestone',
        dueDate: milestone.plannedDate || new Date(Date.now() + (index + 1) * 7 * 24 * 60 * 60 * 1000).toISOString(),
        priority: milestone.priority || 'medium',
        project: milestone.projectName || 'Unknown Project'
      });
    });
  }

  return tasks.slice(0, 5);
}