// src/app/api/auth/logout/route.ts
import { NextRequest, NextResponse } from 'next/server';

const API_BASE_URL = process.env.BACKEND_API_URL || 'http://localhost:5001/api';

export async function POST(request: NextRequest) {
  try {
    const accessToken = request.cookies.get('accessToken')?.value;

    // Forward logout request to backend
    if (accessToken) {
      await fetch(`${API_BASE_URL}/auth/logout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
      });
    }

    // Clear cookies regardless of backend response
    const res = NextResponse.json({ success: true });
    
    res.cookies.delete('accessToken');
    res.cookies.delete('refreshToken');
    
    return res;
  } catch (error) {
    console.error('Logout API error:', error);
    // Still clear cookies even if backend fails
    const res = NextResponse.json({ success: true });
    res.cookies.delete('accessToken');
    res.cookies.delete('refreshToken');
    return res;
  }
}