// src/middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Define public routes that don't require authentication
const publicRoutes = [
  '/',
  '/auth/login',
  '/auth/register',
  '/auth/forgot-password',
  '/auth/reset-password',
  '/auth/verify-email',
  '/terms',
  '/privacy',
  '/about',
  '/features',
  '/pricing',
  '/contact',
];

// Define API routes that don't require authentication
const publicApiRoutes = [
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/refresh',
  '/api/auth/forgot-password',
  '/api/auth/reset-password',
  '/api/auth/verify-email',
  '/api/auth/resend-verification',
];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  
  // Check if the route is public
  const isPublicRoute = publicRoutes.includes(pathname) || 
                       publicApiRoutes.includes(pathname) ||
                       pathname.startsWith('/api/auth/');
  
  // Check if it's a static file or Next.js internal route
  const isStaticFile = pathname.startsWith('/_next') || 
                      pathname.startsWith('/static') ||
                      pathname.includes('.') ||
                      pathname.startsWith('/api/placeholder');
  
  if (isPublicRoute || isStaticFile) {
    return NextResponse.next();
  }
  
  // Check for authentication
  const accessToken = request.cookies.get('accessToken')?.value;
  const refreshToken = request.cookies.get('refreshToken')?.value;
  
  // Protected routes
  if (pathname.startsWith('/dashboard') || pathname.startsWith('/api/')) {
    if (!accessToken && !refreshToken) {
      // Redirect to login for web routes
      if (!pathname.startsWith('/api/')) {
        const url = request.nextUrl.clone();
        url.pathname = '/auth/login';  // Fixed: Use correct login path
        url.searchParams.set('redirect', pathname);
        return NextResponse.redirect(url);
      }
      
      // Return 401 for API routes
      return NextResponse.json(
        { success: false, error: { message: 'Authentication required' } },
        { status: 401 }
      );
    }
    
    // If only refresh token exists, we could trigger a refresh here
    // but for simplicity, we'll handle it in the client
  }
  
  // Add auth headers for API requests
  if (pathname.startsWith('/api/') && accessToken) {
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('Authorization', `Bearer ${accessToken}`);
    
    return NextResponse.next({
      request: {
        headers: requestHeaders,
      },
    });
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};