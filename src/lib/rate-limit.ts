import { NextRequest, NextResponse } from 'next/server';

interface RateLimitConfig {
  limit: number;
  windowMs: number;
  message?: string;
}

interface RateLimitData {
  count: number;
  resetTime: number;
}

// In-memory rate limit store (use Redis in production)
const rateLimitStore = new Map<string, RateLimitData>();

export function checkRateLimit(
  identifier: string,
  config: RateLimitConfig = { limit: 100, windowMs: 900000 }
): { allowed: boolean; remaining: number; resetTime: number } {
  const now = Date.now();
  const key = identifier;
  const userData = rateLimitStore.get(key);

  // Clean up expired entries
  if (userData && now > userData.resetTime) {
    rateLimitStore.delete(key);
  }

  if (!userData || now > userData.resetTime) {
    // First request or reset window
    rateLimitStore.set(key, {
      count: 1,
      resetTime: now + config.windowMs,
    });
    return { allowed: true, remaining: config.limit - 1, resetTime: now + config.windowMs };
  }

  if (userData.count >= config.limit) {
    // Rate limit exceeded
    return { allowed: false, remaining: 0, resetTime: userData.resetTime };
  }

  // Increment counter
  userData.count++;
  return { allowed: true, remaining: config.limit - userData.count, resetTime: userData.resetTime };
}

export function getClientIdentifier(request: NextRequest): string {
  // Use IP address as primary identifier
  const ip = request.ip || 
             request.headers.get('x-forwarded-for')?.split(',')[0] || 
             request.headers.get('x-real-ip') || 
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
  return (request: NextRequest) => {
    const identifier = getClientIdentifier(request);
    const rateLimitResult = checkRateLimit(identifier, config);

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
  };
}

// Predefined rate limit configurations
export const RATE_LIMITS = {
  STRICT: { limit: 10, windowMs: 60000, message: 'Too many requests' }, // 10 per minute
  NORMAL: { limit: 100, windowMs: 900000, message: 'Rate limit exceeded' }, // 100 per 15 minutes
  LOOSE: { limit: 1000, windowMs: 3600000, message: 'Rate limit exceeded' }, // 1000 per hour
} as const;
