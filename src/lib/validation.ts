import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

// Payment intent validation schema
export const PaymentIntentSchema = z.object({
  priceId: z.string().min(1).max(100).regex(/^price_[a-zA-Z0-9]+$/),
  quantity: z.number().int().min(1).max(1000),
});

// GitHub OAuth validation schema
export const GitHubOAuthSchema = z.object({
  code: z.string().min(1).max(1000),
  state: z.string().min(1).max(1000),
});

// Repository URL validation schema
export const RepositoryUrlSchema = z.object({
  repository_url: z.string().url().refine(
    (url) => url.startsWith('https://github.com/') || 
             url.startsWith('https://gitlab.com/') || 
             url.startsWith('https://bitbucket.org/'),
    { message: 'Only GitHub, GitLab, and Bitbucket repositories are supported' }
  ),
  github_token: z.string().optional().refine(
    (token) => !token || token.startsWith('ghp_') || token.startsWith('gho_') || token.startsWith('ghu_'),
    { message: 'Invalid GitHub token format' }
  ),
});

// Generic validation function
export function validateRequest<T>(
  request: NextRequest,
  schema: z.ZodSchema<T>
): { success: true; data: T } | { success: false; error: string; status: number } {
  try {
    const body = request.json ? request.json() : {};
    const validatedData = schema.parse(body);
    return { success: true, data: validatedData };
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errorMessage = error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join(', ');
      return { success: false, error: `Validation failed: ${errorMessage}`, status: 400 };
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
  return (request: NextRequest) => {
    const validation = validateRequest(request, schema);
    
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
