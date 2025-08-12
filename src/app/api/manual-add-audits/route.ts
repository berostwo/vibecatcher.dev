import { NextRequest, NextResponse } from 'next/server';
import Stripe from 'stripe';
import { UserService } from '@/lib/user-service';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2025-07-30.basil',
});

export async function POST(request: NextRequest) {
  try {
    const { paymentIntentId, userId, packageId } = await request.json();

    if (!paymentIntentId || !userId || !packageId) {
      return NextResponse.json({ 
        error: 'Missing required fields' 
      }, { status: 400 });
    }

    // Verify the payment intent with Stripe
    const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);
    
    if (paymentIntent.status !== 'succeeded') {
      return NextResponse.json({ 
        error: 'Payment not completed' 
      }, { status: 400 });
    }

    // Get audit count from package
    const PACKAGE_TO_AUDITS: Record<string, number> = {
      single_audit: 1,
      five_audits: 5,
      ten_audits: 10,
    };

    const auditCount = PACKAGE_TO_AUDITS[packageId];
    
    if (!auditCount) {
      return NextResponse.json({ 
        error: 'Invalid package ID' 
      }, { status: 400 });
    }

    // Add audits to user's account
    await UserService.addAudits(userId, auditCount);
    
    console.log(`✅ Manually added ${auditCount} audits to user ${userId} for package ${packageId}`);

    return NextResponse.json({ 
      success: true,
      message: `Added ${auditCount} audits to your account`,
      auditCount
    });

  } catch (error) {
    console.error('Error manually adding audits:', error);
    return NextResponse.json(
      { error: 'Failed to add audits' },
      { status: 500 }
    );
  }
}
