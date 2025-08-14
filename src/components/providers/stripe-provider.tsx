'use client';

import { ReactNode } from 'react';
import { Elements } from '@stripe/react-stripe-js';
import { getStripe } from '@/lib/stripe';

interface StripeProviderProps {
  children: ReactNode;
}

export function StripeProvider({ children }: StripeProviderProps) {
  const stripePromise = getStripe();

  return (
    <Elements stripe={stripePromise}>
      {children}
    </Elements>
  );
}
