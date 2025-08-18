import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

// Shared helpers
const safeAlnumDash = /^[A-Za-z0-9_-]+$/;

// Payment intent validation schema (strict)
export const PaymentIntentSchema = z.object({
  priceId: z
    .string()
    .trim()
    .min(1)
    .max(100)
    .regex(/^price_[a-zA-Z0-9]{5,}$/),
  quantity: z.coerce.number().int().min(1).max(1000),
}).strict();

// GitHub OAuth validation schema (strict)
export const GitHubOAuthSchema = z.object({
  code: z
    .string()
    .trim()
    .min(20)
    .max(2000)
    .regex(safeAlnumDash, { message: 'Invalid code format' }),
  state: z
    .string()
    .trim()
    .min(32)
    .max(128)
    .regex(/^[a-f0-9]{32,}$/i, { message: 'Invalid state format' }),
}).strict();

// Server-side GitHub OAuth state storage schema (strict)
export const GitHubOAuthStateSchema = z.object({
  state: z.string().trim().min(32).max(128).regex(/^[a-f0-9]{32,}$/i),
  clientId: z.string().trim().min(10).max(200).regex(safeAlnumDash),
}).strict();

// Repository URL validation schema (strict)
export const RepositoryUrlSchema = z
  .object({
    repository_url: z
      .string()
      .url()
      .refine((url) => {
        try {
          const u = new URL(url);
          const allowedHosts = new Set([
            'github.com',
            'gitlab.com',
            'bitbucket.org',
          ]);
          return u.protocol === 'https:' && allowedHosts.has(u.hostname);
        } catch {
          return false;
        }
      }, { message: 'Only HTTPS GitHub, GitLab, and Bitbucket repositories are supported' }),
    github_token: z
      .string()
      .optional()
      .refine(
        (token) =>
          !token ||
          token.startsWith('ghp_') ||
          token.startsWith('gho_') ||
          token.startsWith('ghu_') ||
          token.startsWith('ghs_') ||
          token.startsWith('ghr_'),
        { message: 'Invalid GitHub token format' }
      ),
  })
  .strict();

// Generic validation function
export async function validateRequest<T>(
  request: NextRequest,
  schema: z.ZodSchema<T>
): Promise<{ success: true; data: T } | { success: false; error: string; status: number }> {
  try {
    // Minimal logging to avoid leaking sensitive info
    const contentType = request.headers.get('content-type') || '';

    if (!contentType.includes('application/json')) {
      return { success: false, error: 'Invalid content type - expected application/json', status: 400 };
    }
    
    // Parse request body
    const body = await request.json();

    // Validate against schema
    const result = schema.safeParse(body);
    if (!result.success) {
      const errorMessage = result.error.errors
        .map((e) => `${e.path.join('.') || 'root'}: ${e.message}`)
        .join(', ');
      return { success: false, error: `Validation failed: ${errorMessage}`, status: 400 };
    }
    
    return { success: true, data: result.data };
  } catch (error) {
    if (error instanceof SyntaxError) {
      return { success: false, error: 'Invalid JSON format', status: 400 };
    }
    return { success: false, error: 'Invalid request data', status: 400 };
  }
}

// Sanitize and validate string inputs
export function sanitizeString(input: string, maxLength: number = 1000): string {
  if (typeof input !== 'string') {
    throw new Error('Input must be a string');
  }
  
  // Remove null bytes and control characters
  let sanitized = input.replace(/[\x00-\x1F\x7F]/g, '');
  
  // Trim whitespace
  sanitized = sanitized.trim();
  
  // Limit length
  if (sanitized.length > maxLength) {
    sanitized = sanitized.substring(0, maxLength);
  }
  
  return sanitized;
}

// Validate and sanitize numeric inputs
export function validateNumber(input: any, min: number, max: number): number {
  const num = Number(input);
  
  if (isNaN(num) || !Number.isFinite(num)) {
    throw new Error('Input must be a valid number');
  }
  
  if (num < min || num > max) {
    throw new Error(`Number must be between ${min} and ${max}`);
  }
  
  return num;
}

// Validate file paths to prevent path traversal
export function validateFilePath(path: string): boolean {
  // Check for path traversal attempts
  if (path.includes('..') || path.includes('//') || path.startsWith('/')) {
    return false;
  }
  
  // Check for dangerous characters
  if (/[<>:"|?*]/.test(path)) {
    return false;
  }
  
  return true;
}

// Create validation middleware
export function createValidationMiddleware<T>(schema: z.ZodSchema<T>) {
  return async (request: NextRequest) => {
    const validation = await validateRequest(request, schema);
    
    if (!validation.success) {
      return NextResponse.json(
        { error: validation.error },
        { status: validation.status }
      );
    }
    
    // Attach validated data to request for use in handler
    (request as any).validatedData = validation.data;
    
    return null; // Continue to next middleware/handler
  };
}
