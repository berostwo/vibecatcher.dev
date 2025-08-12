import { NextRequest, NextResponse } from 'next/server';
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2025-07-30.basil',
});

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const paymentIntentId = searchParams.get('paymentIntentId');

    if (!paymentIntentId) {
      return NextResponse.json({ error: 'Payment intent ID is required' }, { status: 400 });
    }

    // Retrieve the payment intent from Stripe
    const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);

    if (paymentIntent.status === 'succeeded') {
      return NextResponse.json({ 
        status: 'succeeded',
        message: 'Payment completed successfully'
      });
    } else if (paymentIntent.status === 'processing') {
      return NextResponse.json({ 
        status: 'processing',
        message: 'Payment is still processing'
      });
    } else if (paymentIntent.status === 'requires_payment_method') {
      return NextResponse.json({ 
        status: 'failed',
        message: 'Payment failed'
      });
    } else {
      return NextResponse.json({ 
        status: paymentIntent.status,
        message: `Payment status: ${paymentIntent.status}`
      });
    }
  } catch (error) {
    console.error('Error checking payment status:', error);
    return NextResponse.json(
      { error: 'Failed to check payment status' },
      { status: 500 }
    );
  }
}
