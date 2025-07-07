// src/app/api/hosted-organizations/organizations/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';

const API_BASE_URL = process.env.BACKEND_API_URL || 'http://localhost:5001/api';

// Helper function to forward requests to backend
async function forwardToBackend(
  request: NextRequest,
  endpoint: string,
  options: RequestInit = {}
) {
  const cookieStore = await cookies();
  const accessToken = cookieStore.get('accessToken')?.value;
  const refreshToken = cookieStore.get('refreshToken')?.value;

  // Prepare headers
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  // Add authorization if available
  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }

  // Add tenant context headers if available
  const tenantId = request.headers.get('x-tenant-id');
  const organizationId = request.headers.get('x-organization-id');
  
  if (tenantId) {
    headers['x-tenant-id'] = tenantId;
  }
  if (organizationId) {
    headers['x-organization-id'] = organizationId;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/hosted-organizations${endpoint}`, {
      ...options,
      headers,
    });

    const data = await response.json();

    // If the backend returns a 401, we might need to refresh the token
    if (response.status === 401 && refreshToken) {
      // Try to refresh the token
      try {
        const refreshResponse = await fetch(`${API_BASE_URL}/auth/refresh`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Cookie': `refreshToken=${refreshToken}`
          },
        });

        if (refreshResponse.ok) {
          const refreshData = await refreshResponse.json();
          
          // Retry the original request with new token
          const retryResponse = await fetch(`${API_BASE_URL}/hosted-organizations${endpoint}`, {
            ...options,
            headers: {
              ...headers,
              Authorization: `Bearer ${refreshData.data.tokens.accessToken}`,
            },
          });

          const retryData = await retryResponse.json();
          
          // Create response with new cookies
          const nextResponse = NextResponse.json(retryData, { status: retryResponse.status });
          
          // Set new cookies
          nextResponse.cookies.set('accessToken', refreshData.data.tokens.accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 15 * 60 // 15 minutes
          });

          if (refreshData.data.tokens.refreshToken !== refreshToken) {
            nextResponse.cookies.set('refreshToken', refreshData.data.tokens.refreshToken, {
              httpOnly: true,
              secure: process.env.NODE_ENV === 'production',
              sameSite: 'strict',
              maxAge: 7 * 24 * 60 * 60 // 7 days
            });
          }

          return nextResponse;
        }
      } catch (refreshError) {
        console.error('Token refresh failed:', refreshError);
      }
    }

    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('API request failed:', error);
    return NextResponse.json(
      { success: false, error: { message: 'Internal server error' } },
      { status: 500 }
    );
  }
}

// GET /api/hosted-organizations/organizations
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const queryString = searchParams.toString();
  const endpoint = queryString ? `/organizations?${queryString}` : '/organizations';
  
  return forwardToBackend(request, endpoint, {
    method: 'GET',
  });
}

// POST /api/hosted-organizations/organizations
export async function POST(request: NextRequest) {
  const body = await request.json();
  
  return forwardToBackend(request, '/organizations', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}