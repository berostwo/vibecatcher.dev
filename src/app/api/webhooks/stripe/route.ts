import { NextRequest, NextResponse } from 'next/server';
import Stripe from 'stripe';
import { UserService } from '@/lib/user-service';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2025-07-30.basil',
});

const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET!;

export async function POST(request: NextRequest) {
  const body = await request.text();
  const signature = request.headers.get('stripe-signature')!;

  let event: Stripe.Event;

  try {
    event = stripe.webhooks.constructEvent(body, signature, webhookSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err);
    return NextResponse.json({ error: 'Invalid signature' }, { status: 400 });
  }

  // Handle the event
  switch (event.type) {
    case 'payment_intent.succeeded':
      const paymentIntent = event.data.object as Stripe.PaymentIntent;
      
      if (paymentIntent.status === 'succeeded') {
        const { userId, audits } = paymentIntent.metadata!;
        const auditCount = parseInt(audits || '0');
        
        if (userId && userId !== 'unknown' && auditCount > 0) {
          try {
            // Add audits to user's account
            await UserService.addAudits(userId, auditCount);
            console.log(`Added ${auditCount} audits to user ${userId}`);
          } catch (error) {
            console.error('Error adding audits to user:', error);
            return NextResponse.json(
              { error: 'Failed to add audits' },
              { status: 500 }
            );
          }
        } else {
          console.warn('Invalid metadata for payment intent:', { userId, audits });
        }
      }
      break;
    
    default:
      console.log(`Unhandled event type: ${event.type}`);
  }

  return NextResponse.json({ received: true });
}
