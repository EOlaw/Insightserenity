// src/app/api/auth/refresh/route.ts
import { NextRequest, NextResponse } from 'next/server';

const API_BASE_URL = process.env.BACKEND_API_URL || 'http://localhost:5001/api';

export async function POST(request: NextRequest) {
  try {
    const refreshToken = request.cookies.get('refreshToken')?.value;

    if (!refreshToken) {
      return NextResponse.json(
        {
          success: false,
          error: { message: 'No refresh token provided' },
        },
        { status: 401 }
      );
    }

    // Forward request to backend
    const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refreshToken }),
    });

    const data = await response.json();

    if (!response.ok) {
      const res = NextResponse.json(
        {
          success: false,
          error: data.error || { message: 'Token refresh failed' },
        },
        { status: response.status }
      );
      
      // Clear cookies if refresh fails
      res.cookies.delete('accessToken');
      res.cookies.delete('refreshToken');
      
      return res;
    }

    // Create response with new tokens
    const res = NextResponse.json(data);

    // Update cookies with new tokens
    if (data.data?.tokens) {
      res.cookies.set('accessToken', data.data.tokens.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60, // 15 minutes
        path: '/',
      });

      res.cookies.set('refreshToken', data.data.tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60, // 7 days
        path: '/',
      });
    }

    return res;
  } catch (error) {
    console.error('Refresh API error:', error);
    return NextResponse.json(
      {
        success: false,
        error: { message: 'Internal server error' },
      },
      { status: 500 }
    );
  }
}