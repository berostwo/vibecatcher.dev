import { NextRequest, NextResponse } from 'next/server';
import { FirebaseRateLimitService } from './firebase-rate-limit';

interface RateLimitConfig {
  limit: number;
  windowMs: number;
  message?: string;
}

export function getClientIdentifier(request: NextRequest): string {
  // Use IP address from headers as primary identifier
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 
             request.headers.get('x-real-ip') || 
             request.headers.get('x-client-ip') ||
             'unknown';
  
  // Add user ID if authenticated
  const authHeader = request.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    // Extract user ID from token (simplified - in production, decode the JWT)
    return `${ip}:authenticated`;
  }
  
  return `${ip}:anonymous`;
}

export function createRateLimitMiddleware(config: RateLimitConfig) {
  return async (request: NextRequest) => {
    try {
      const identifier = getClientIdentifier(request);
      const rateLimitResult = await FirebaseRateLimitService.checkRateLimit(identifier, config);

      if (!rateLimitResult.allowed) {
        return NextResponse.json(
          {
            error: config.message || 'Rate limit exceeded',
            retryAfter: Math.ceil((rateLimitResult.resetTime - Date.now()) / 1000),
          },
          { 
            status: 429,
            headers: {
              'X-RateLimit-Limit': config.limit.toString(),
              'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
              'X-RateLimit-Reset': rateLimitResult.resetTime.toString(),
              'Retry-After': Math.ceil((rateLimitResult.resetTime - Date.now()) / 1000).toString(),
            }
          }
        );
      }

      return null; // Continue to next middleware/handler
    } catch (error) {
      console.error('Rate limiting failed, allowing request:', error);
      return null; // Allow request if rate limiting fails
    }
  };
}

// Predefined rate limit configurations
export const RATE_LIMITS = {
  STRICT: { limit: 10, windowMs: 60000, message: 'Too many requests' }, // 10 per minute
  NORMAL: { limit: 100, windowMs: 900000, message: 'Rate limit exceeded' }, // 100 per 15 minutes
  LOOSE: { limit: 1000, windowMs: 3600000, message: 'Rate limit exceeded' }, // 1000 per hour
} as const;
