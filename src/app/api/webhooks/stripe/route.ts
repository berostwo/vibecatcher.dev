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

  console.log('Webhook received:', { 
    signature: signature ? 'present' : 'missing',
    bodyLength: body.length 
  });

  let event: Stripe.Event;

  try {
    event = stripe.webhooks.constructEvent(body, signature, webhookSecret);
    console.log('Webhook signature verified, event type:', event.type);
  } catch (err) {
    console.error('Webhook signature verification failed:', err);
    return NextResponse.json({ error: 'Invalid signature' }, { status: 400 });
  }

  // Handle the event
  switch (event.type) {
    case 'payment_intent.succeeded':
      const paymentIntent = event.data.object as Stripe.PaymentIntent;
      console.log('Processing payment_intent.succeeded:', {
        id: paymentIntent.id,
        amount: paymentIntent.amount,
        status: paymentIntent.status,
        metadata: paymentIntent.metadata
      });
      
      if (paymentIntent.status === 'succeeded') {
        const { userId, audits } = paymentIntent.metadata!;
        const auditCount = parseInt(audits || '0');
        
        console.log('Payment metadata:', { userId, audits, auditCount });
        
        if (userId && userId !== 'unknown' && auditCount > 0) {
          try {
            // Add audits to user's account
            await UserService.addAudits(userId, auditCount);
            console.log(`✅ Successfully added ${auditCount} audits to user ${userId}`);
          } catch (error) {
            console.error('❌ Error adding audits to user:', error);
            return NextResponse.json(
              { error: 'Failed to add audits' },
              { status: 500 }
            );
          }
        } else {
          console.warn('⚠️ Invalid metadata for payment intent:', { userId, audits });
        }
      }
      break;
    
    case 'payment_intent.payment_failed':
      const failedPayment = event.data.object as Stripe.PaymentIntent;
      console.log('Payment failed:', {
        id: failedPayment.id,
        status: failedPayment.status,
        lastPaymentError: (failedPayment as any).last_payment_error
      });
      break;
    
    default:
      console.log(`ℹ️ Unhandled event type: ${event.type}`);
  }

  return NextResponse.json({ received: true });
}
