// src/app/api/clients/route.ts
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

    // Forward request to backend
    const response = await fetch(
      `${API_BASE_URL}/clients${queryString ? `?${queryString}` : ''}`,
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
          error: data.error || { message: 'Failed to fetch clients' },
        },
        { status: response.status }
      );
    }

    return NextResponse.json({
      success: true,
      results: data.results,
      pagination: data.pagination,
      data: data.data
    });
  } catch (error) {
    console.error('Clients API error:', error);
    return NextResponse.json(
      {
        success: false,
        error: { message: 'Internal server error' },
      },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const accessToken = request.cookies.get('accessToken')?.value;
    const body = await request.json();

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
    const response = await fetch(`${API_BASE_URL}/clients`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
      },
      body: JSON.stringify(body),
    });

    const data = await response.json();

    if (!response.ok) {
      return NextResponse.json(
        {
          success: false,
          error: data.error || { message: 'Failed to create client' },
        },
        { status: response.status }
      );
    }

    return NextResponse.json({
      success: true,
      data: data.data
    });
  } catch (error) {
    console.error('Create client API error:', error);
    return NextResponse.json(
      {
        success: false,
        error: { message: 'Internal server error' },
      },
      { status: 500 }
    );
  }
}