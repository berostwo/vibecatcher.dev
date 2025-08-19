import { NextRequest, NextResponse } from 'next/server';
import Stripe from 'stripe';
import { requireAuth } from '@/lib/auth-middleware';
import { createRateLimitMiddleware, RATE_LIMITS } from '@/lib/rate-limit';
import { createCSRFMiddleware } from '@/lib/csrf';
import { createValidationMiddleware, PaymentIntentSchema } from '@/lib/validation';
import type { DecodedIdToken } from 'firebase-admin/auth';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2025-07-30.basil',
});

// Secure payment intent creation with all security measures
async function createPaymentIntentHandler(request: NextRequest, user: DecodedIdToken): Promise<NextResponse> {
  try {
    // 1. RATE LIMITING - Prevent abuse
    const rateLimitCheck = await createRateLimitMiddleware(RATE_LIMITS.STRICT)(request);
    if (rateLimitCheck) return rateLimitCheck;

    // 2. INPUT VALIDATION - Prevent injection attacks
    const validationCheck = await createValidationMiddleware(PaymentIntentSchema)(request);
    if (validationCheck) return validationCheck;

    // 3. CSRF PROTECTION - Prevent cross-site request forgery
    const csrfCheck = await createCSRFMiddleware()(request, user.uid);
    if (csrfCheck) return csrfCheck;

    // 4. BUSINESS LOGIC VALIDATION
    const { priceId, quantity = 1, payerEmail, payerName } = (request as any).validatedData;

    // Additional security checks
    if (!priceId || typeof priceId !== 'string') {
      return NextResponse.json(
        { error: 'Invalid priceId parameter' },
        { status: 400 }
      );
    }

    if (quantity < 1 || quantity > 1000 || !Number.isInteger(quantity)) {
      return NextResponse.json(
        { error: 'Invalid quantity parameter' },
        { status: 400 }
      );
    }

    // 5. USER AUTHORIZATION - Ensure user can make this purchase
    // Add your business logic here (e.g., check user subscription status)
    
    // 6. CREATE PAYMENT INTENT with enhanced security
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(quantity * 100), // Convert to cents
      currency: 'usd',
      // Email receipt: prefer provided payerEmail, fallback to auth user
      receipt_email: payerEmail || user.email || undefined,
      automatic_payment_methods: {
        enabled: true,
      },
      metadata: {
        priceId,
        quantity: quantity.toString(),
        userId: user.uid, // Track which user created this
        userEmail: payerEmail || user.email || '',
        userName: payerName || (user as any).name || (user as any).displayName || '',
        timestamp: Date.now().toString(),
      },
      // Add additional security measures
      capture_method: 'automatic',
      confirmation_method: 'automatic',
      setup_future_usage: 'off_session',
    });

    // 7. SECURE RESPONSE - Only return necessary data, sanitize all output
    const sanitizedResponse = {
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id.substring(0, 8) + '...', // Truncate for security
      amount: Math.round(paymentIntent.amount / 100), // Convert from cents to dollars
      status: paymentIntent.status,
      currency: paymentIntent.currency,
    };

    return NextResponse.json(sanitizedResponse, {
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Pragma': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      }
    });

  } catch (error) {
    // 8. SECURE ERROR HANDLING - Don't leak sensitive information
    console.error('Payment intent creation error');
    
    if (error instanceof Stripe.errors.StripeError) {
      return NextResponse.json(
        { error: 'Payment processing error' },
        { status: 400 }
      );
    }
    
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// Export the secured handler
export const POST = requireAuth(createPaymentIntentHandler);
