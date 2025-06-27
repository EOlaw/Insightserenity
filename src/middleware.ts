// src/middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/request';

// Define auth routes that authenticated users should not access
const authRoutes = [
  '/auth/login',
  '/auth/register',
  '/auth/forgot-password',
  '/auth/reset-password',
  '/auth/verify-email',
];

// Define public routes that don't require authentication
const publicRoutes = [
  '/',
  '/terms',
  '/privacy',
  '/about',
  '/features',
  '/pricing',
  '/contact',
  ...authRoutes, // Auth routes are still public for unauthenticated users
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
  
  // Check for authentication tokens
  const accessToken = request.cookies.get('accessToken')?.value;
  const refreshToken = request.cookies.get('refreshToken')?.value;
  const hasAuthTokens = accessToken || refreshToken;
  
  // Check if it's a static file or Next.js internal route
  const isStaticFile = pathname.startsWith('/_next') || 
                      pathname.startsWith('/static') ||
                      pathname.includes('.') ||
                      pathname.startsWith('/api/placeholder');
  
  if (isStaticFile) {
    return NextResponse.next();
  }
  
  // PREVENT AUTHENTICATED USERS FROM ACCESSING AUTH PAGES
  if (authRoutes.includes(pathname) && hasAuthTokens) {
    const url = request.nextUrl.clone();
    url.pathname = '/dashboard';
    return NextResponse.redirect(url);
  }
  
  // Check if the route is public
  const isPublicRoute = publicRoutes.includes(pathname) || 
                       publicApiRoutes.includes(pathname) ||
                       pathname.startsWith('/api/auth/');
  
  if (isPublicRoute) {
    return NextResponse.next();
  }
  
  // PROTECT PRIVATE ROUTES - Require authentication
  if (pathname.startsWith('/dashboard') || pathname.startsWith('/api/')) {
    if (!hasAuthTokens) {
      // Redirect to login for web routes
      if (!pathname.startsWith('/api/')) {
        const url = request.nextUrl.clone();
        url.pathname = '/auth/login';
        url.searchParams.set('redirect', pathname);
        return NextResponse.redirect(url);
      }
      
      // Return 401 for API routes
      return NextResponse.json(
        { success: false, error: { message: 'Authentication required' } },
        { status: 401 }
      );
    }
  }
  
  // Add auth headers for authenticated API requests
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