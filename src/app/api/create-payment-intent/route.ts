import { NextRequest, NextResponse } from 'next/server';
import Stripe from 'stripe';
import { AUDIT_PACKAGES } from '@/lib/stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2025-07-30.basil',
});

export async function POST(request: NextRequest) {
  try {
    const { packageId, userId } = await request.json();

    // Find the selected package
    const selectedPackage = AUDIT_PACKAGES.find(pkg => pkg.id === packageId);
    if (!selectedPackage) {
      return NextResponse.json(
        { error: 'Invalid package selected' },
        { status: 400 }
      );
    }

    // Validate that price ID is configured
    if (!selectedPackage.priceId) {
      return NextResponse.json(
        { error: 'Price ID not configured for this package' },
        { status: 500 }
      );
    }

    // Create Stripe payment intent
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(selectedPackage.price * 100), // Convert to cents
      currency: 'usd',
      payment_method_types: ['card'],
      metadata: {
        userId,
        packageId,
        audits: selectedPackage.audits.toString(),
      },
      // Optional: Add automatic payment methods
      automatic_payment_methods: {
        enabled: true,
      },
    });

    return NextResponse.json({ 
      clientSecret: paymentIntent.client_secret 
    });
  } catch (error) {
    console.error('Error creating payment intent:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

