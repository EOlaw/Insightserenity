// src/app/api/users/team/route.ts
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

    // Get query parameters
    const { searchParams } = new URL(request.url);
    const queryString = searchParams.toString();

    // Forward request to backend users endpoint with team filter
    const response = await fetch(
      `${API_BASE_URL}/users${queryString ? `?${queryString}` : '?role=consultant,manager,admin,analyst'}`,
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return NextResponse.json(
        {
          success: false,
          error: data.error || { message: 'Failed to fetch team members' },
        },
        { status: response.status }
      );
    }

    return NextResponse.json({
      success: true,
      results: data.results,
      data: data.data
    });
  } catch (error) {
    console.error('Team API error:', error);
    return NextResponse.json(
      {
        success: false,
        error: { message: 'Internal server error' },
      },
      { status: 500 }
    );
  }
}