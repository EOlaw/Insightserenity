// src/app/api/projects/[id]/dashboard/route.ts
import { NextRequest, NextResponse } from 'next/server';

const API_BASE_URL = process.env.BACKEND_API_URL || 'http://localhost:5001/api';

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
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

    // Forward request to backend
    const response = await fetch(`${API_BASE_URL}/projects/${params.id}/dashboard`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
      },
    });

    const data = await response.json();

    if (!response.ok) {
      return NextResponse.json(
        {
          success: false,
          error: data.error || { message: 'Failed to fetch project dashboard' },
        },
        { status: response.status }
      );
    }

    return NextResponse.json({
      success: true,
      data: data.data
    });
  } catch (error) {
    console.error('Project dashboard API error:', error);
    return NextResponse.json(
      {
        success: false,
        error: { message: 'Internal server error' },
      },
      { status: 500 }
    );
  }
}