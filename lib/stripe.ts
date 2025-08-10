import Stripe from 'stripe';

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2023-10-16',
  typescript: true,
});

export const STRIPE_PLANS = {
  SINGLE_AUDIT: {
    price: 499, // $4.99 in cents
    name: 'Single Audit',
    description: 'Purchase 1 security audit',
  },
  BASIC_SUBSCRIPTION: {
    price: 999, // $9.99 in cents
    name: 'Basic Plan',
    description: '8 audits per month',
    interval: 'month',
  },
  PRO_SUBSCRIPTION: {
    price: 1499, // $14.99 in cents
    name: 'Pro Plan',
    description: '20 audits per month',
    interval: 'month',
  },
} as const;

export type PlanType = keyof typeof STRIPE_PLANS;
