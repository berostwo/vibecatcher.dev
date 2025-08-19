import { NextRequest, NextResponse } from 'next/server';
import Stripe from 'stripe';
import { getProductByPriceId } from '@/lib/stripe';
import { UserService } from '@/lib/user-service';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2025-07-30.basil',
});

const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET!;

export async function POST(request: NextRequest) {
  try {
    const body = await request.text();
    const signature = request.headers.get('stripe-signature');

    if (!signature) {
      return NextResponse.json(
        { error: 'Missing stripe-signature header' },
        { status: 400 }
      );
    }

    let event: Stripe.Event;

    try {
      event = stripe.webhooks.constructEvent(body, signature, webhookSecret);
    } catch (err) {
      console.error('Webhook signature verification failed');
      return NextResponse.json(
        { error: 'Invalid signature' },
        { status: 400 }
      );
    }

    // Handle the event
    switch (event.type) {
      case 'payment_intent.succeeded':
        const paymentIntent = event.data.object as Stripe.PaymentIntent;
        console.log('Payment succeeded:', paymentIntent.id.substring(0, 8) + '...');
        try {
          const metadata = (paymentIntent.metadata || {}) as any;
          const userId = metadata.userId as string | undefined;
          const priceId = metadata.priceId as string | undefined;
          const quantity = Number(metadata.quantity || 1);
          if (userId && priceId) {
            const product = getProductByPriceId(priceId);
            if (product && 'credits' in product) {
              const creditsToAdd = (product as any).credits * quantity;
              await UserService.addCredits(userId, creditsToAdd);
              console.log(`Added ${creditsToAdd} credits to user ${userId}`);
            }
          }
        } catch (e) {
          console.error('Failed to add credits after payment');
        }
        
        break;
      
      case 'payment_intent.payment_failed':
        const failedPayment = event.data.object as Stripe.PaymentIntent;
        console.log('Payment failed:', failedPayment.id.substring(0, 8) + '...');
        break;
      
      default:
        console.log(`Unhandled webhook event: ${event.type}`);
    }

    return NextResponse.json({ received: true });
  } catch (error) {
    console.error('Webhook processing error');
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
