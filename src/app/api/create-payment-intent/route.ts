import { NextRequest, NextResponse } from 'next/server';
import Stripe from 'stripe';

if (!process.env.STRIPE_SECRET_KEY) {
  console.warn('STRIPE_SECRET_KEY is not set. /api/create-payment-intent will return 500 until configured.');
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || '');

const PACKAGE_TO_PRICE_ENV: Record<string, string | undefined> = {
  single_audit: process.env.STRIPE_PRICE_SINGLE,
  five_audits: process.env.STRIPE_PRICE_FIVE,
  ten_audits: process.env.STRIPE_PRICE_TEN,
};

const PACKAGE_TO_AUDITS: Record<string, number> = {
  single_audit: 1,
  five_audits: 5,
  ten_audits: 10,
};

export async function POST(request: NextRequest) {
  try {
    if (!process.env.STRIPE_SECRET_KEY) {
      return NextResponse.json(
        { error: 'Stripe not configured. Set STRIPE_SECRET_KEY in your environment.' },
        { status: 500 }
      );
    }

    const { packageId, userId } = await request.json();

    const priceId = PACKAGE_TO_PRICE_ENV[packageId];
    if (!priceId) {
      return NextResponse.json(
        { error: `Price not configured for package '${packageId}'. Set STRIPE_PRICE_* env vars.` },
        { status: 400 }
      );
    }

    // Get audit count for this package
    const auditCount = PACKAGE_TO_AUDITS[packageId];
    if (!auditCount) {
      return NextResponse.json(
        { error: `Invalid package ID: ${packageId}` },
        { status: 400 }
      );
    }

    // Fetch the Price from Stripe to determine amount/currency server-side
    const price = await stripe.prices.retrieve(priceId);
    if (!price.unit_amount || !price.currency) {
      return NextResponse.json(
        { error: 'Configured Stripe price has no unit_amount or currency.' },
        { status: 500 }
      );
    }

    const paymentIntent = await stripe.paymentIntents.create({
      amount: price.unit_amount,
      currency: price.currency,
      automatic_payment_methods: { enabled: true },
      metadata: {
        userId: userId || 'unknown',
        packageId,
        audits: String(auditCount),
      },
    });

    return NextResponse.json({ clientSecret: paymentIntent.client_secret });
  } catch (error: any) {
    console.error('Error creating payment intent:', error?.message || error);
    return NextResponse.json(
      { error: error?.message || 'Internal server error' },
      { status: 500 }
    );
  }
}

