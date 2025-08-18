// Security configuration for the entire application
export const SECURITY_CONFIG = {
  // Rate limiting configurations
  RATE_LIMITS: {
    // Strict limits for sensitive operations
    PAYMENT: { limit: 10, windowMs: 60000, message: 'Too many payment requests' },
    OAUTH: { limit: 5, windowMs: 60000, message: 'Too many OAuth attempts' },
    LOGIN: { limit: 5, windowMs: 300000, message: 'Too many login attempts' },
    
    // Normal limits for regular operations
    API: { limit: 100, windowMs: 900000, message: 'Rate limit exceeded' },
    SCAN: { limit: 20, windowMs: 900000, message: 'Too many scan requests' },
    
    // Loose limits for public endpoints
    PUBLIC: { limit: 1000, windowMs: 3600000, message: 'Rate limit exceeded' },
  },

  // Input validation limits
  VALIDATION: {
    MAX_STRING_LENGTH: 1000,
    MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
    ALLOWED_FILE_TYPES: ['.js', '.ts', '.tsx', '.jsx', '.py', '.php', '.rb', '.go', '.java', '.cs', '.rs', '.html', '.vue', '.svelte'],
    MAX_REPOSITORY_SIZE: 500 * 1024 * 1024, // 500MB
  },

  // Security headers (defaults to strict; dev overrides below)
  SECURITY_HEADERS: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    // Strict production CSP (no inline)
    'Content-Security-Policy': "default-src 'self'; script-src 'self' https://js.stripe.com; style-src 'self' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' https://api.stripe.com https://github.com https://api.github.com https://www.google.com https://httpbin.org https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://firestore.googleapis.com https://firebase.googleapis.com https://chatgpt-security-scanner-505997387504.us-central1.run.app; frame-src https://js.stripe.com; object-src 'none';",
  },

  // CORS configuration
  CORS: {
    ALLOWED_ORIGINS: [
      'http://localhost:9002',
      'http://localhost:3000',
      'https://vibecatcher.dev',
      'http://vibecatcher.dev'
    ],
    ALLOWED_METHODS: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    ALLOWED_HEADERS: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    MAX_AGE: 86400, // 24 hours
  },

  // Authentication settings
  AUTH: {
    SESSION_TIMEOUT: 24 * 60 * 60 * 1000, // 24 hours
    TOKEN_REFRESH_THRESHOLD: 5 * 60 * 1000, // 5 minutes
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_DURATION: 15 * 60 * 1000, // 15 minutes
  },

  // File upload security
  FILE_UPLOAD: {
    MAX_SIZE: 10 * 1024 * 1024, // 10MB
    ALLOWED_EXTENSIONS: ['.js', '.ts', '.tsx', '.jsx', '.py', '.php', '.rb', '.go', '.java', '.cs', '.rs', '.html', '.vue', '.svelte'],
    SCAN_FOR_VIRUSES: false, // Set to true in production
    VALIDATE_CONTENT: true,
  },

  // Logging and monitoring
  MONITORING: {
    LOG_AUTH_ATTEMPTS: true,
    LOG_PAYMENT_ATTEMPTS: true,
    LOG_RATE_LIMIT_VIOLATIONS: true,
    LOG_SECURITY_EVENTS: true,
    ALERT_ON_SUSPICIOUS_ACTIVITY: true,
  },
} as const;

// Environment-specific security settings
export const getSecurityConfig = () => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  // Start from defaults
  const base = { ...SECURITY_CONFIG } as any;

  if (isProduction) {
    // Stricter settings in production
    base.RATE_LIMITS = {
      ...SECURITY_CONFIG.RATE_LIMITS,
      PAYMENT: { limit: 5, windowMs: 60000, message: 'Too many payment requests' },
      OAUTH: { limit: 3, windowMs: 60000, message: 'Too many OAuth attempts' },
    };

    base.SECURITY_HEADERS = {
      ...SECURITY_CONFIG.SECURITY_HEADERS,
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Content-Security-Policy': SECURITY_CONFIG.SECURITY_HEADERS['Content-Security-Policy'] + "; upgrade-insecure-requests;",
    };
  } else {
    // Development: relax CSP to support Next.js dev runtime and HMR
    base.SECURITY_HEADERS = {
      ...SECURITY_CONFIG.SECURITY_HEADERS,
      'Content-Security-Policy': "default-src 'self' http://localhost:3000; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com http://localhost:3000; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' ws://localhost:3000 http://localhost:3000 https://api.stripe.com https://github.com https://api.github.com https://www.google.com https://httpbin.org https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://firestore.googleapis.com https://firebase.googleapis.com https://chatgpt-security-scanner-505997387504.us-central1.run.app; frame-src https://js.stripe.com; object-src 'none';",
    };
  }

  return base;
};
