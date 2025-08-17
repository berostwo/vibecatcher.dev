import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { getSecurityConfig } from '@/lib/security-config';

export function middleware(request: NextRequest) {
  const response = NextResponse.next();
  const securityConfig = getSecurityConfig();

  // Apply security headers to all responses
  Object.entries(securityConfig.SECURITY_HEADERS).forEach(([header, value]) => {
    response.headers.set(header, value);
  });

  // CORS handling for API routes
  if (request.nextUrl.pathname.startsWith('/api/')) {
    const origin = request.headers.get('origin');
    
    if (origin && securityConfig.CORS.ALLOWED_ORIGINS.includes(origin)) {
      response.headers.set('Access-Control-Allow-Origin', origin);
    } else if (securityConfig.CORS.ALLOWED_ORIGINS.includes('*')) {
      response.headers.set('Access-Control-Allow-Origin', '*');
    } else {
      response.headers.set('Access-Control-Allow-Origin', securityConfig.CORS.ALLOWED_ORIGINS[0]);
    }
    
    response.headers.set('Access-Control-Allow-Methods', securityConfig.CORS.ALLOWED_METHODS.join(', '));
    response.headers.set('Access-Control-Allow-Headers', securityConfig.CORS.ALLOWED_HEADERS.join(', '));
    response.headers.set('Access-Control-Max-Age', securityConfig.CORS.MAX_AGE.toString());
    
    // Handle preflight requests
    if (request.method === 'OPTIONS') {
      return new NextResponse(null, { status: 200, headers: response.headers });
    }
  }

  // Additional security measures for sensitive routes
  if (request.nextUrl.pathname.startsWith('/api/create-payment-intent')) {
    response.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    response.headers.set('Pragma', 'no-cache');
  }

  if (request.nextUrl.pathname.startsWith('/api/github/oauth')) {
    response.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    response.headers.set('Pragma', 'no-cache');
  }

  // Security logging for suspicious activity
  const userAgent = request.headers.get('user-agent') || '';
  const suspiciousPatterns = [
    /sqlmap/i,
    /nikto/i,
    /nmap/i,
    /dirb/i,
    /gobuster/i,
    /wfuzz/i,
    /burp/i,
    /zap/i,
    /acunetix/i,
    /nessus/i,
  ];

  if (suspiciousPatterns.some(pattern => pattern.test(userAgent))) {
    console.warn('🚨 SUSPICIOUS USER AGENT DETECTED:', {
      userAgent,
      ip: request.ip || request.headers.get('x-forwarded-for'),
      path: request.nextUrl.pathname,
      timestamp: new Date().toISOString(),
    });
  }

  return response;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder
     */
    '/((?!_next/static|_next/image|favicon.ico|public).*)',
  ],
};
