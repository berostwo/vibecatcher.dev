import { loadStripe } from '@stripe/stripe-js';

// Client-side Stripe instance
export const getStripe = () => {
  const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!);
  return stripePromise;
};

// Product configuration
export const STRIPE_PRODUCTS = {
  SINGLE: {
    id: 'single_audit',
    name: 'Single Audit',
    price: 4.99,
    audits: 1,
    priceId: process.env.NEXT_PUBLIC_STRIPE_SINGLE_AUDIT_PRICE_ID,
    description: 'One comprehensive security audit'
  },
  FIVE: {
    id: 'five_audits',
    name: '5 Audits',
    price: 11.99,
    audits: 5,
    priceId: process.env.NEXT_PUBLIC_STRIPE_FIVE_AUDITS_PRICE_ID,
    description: 'Five security audits at a discount'
  },
  TEN: {
    id: 'ten_audits',
    name: '10 Audits',
    price: 18.99,
    audits: 10,
    priceId: process.env.NEXT_PUBLIC_STRIPE_TEN_AUDITS_PRICE_ID,
    description: 'Ten security audits at the best value'
  }
};

// Get product by ID
export const getProductById = (id: string) => {
  return Object.values(STRIPE_PRODUCTS).find(product => product.id === id);
};

// Get product by price ID
export const getProductByPriceId = (priceId: string) => {
  return Object.values(STRIPE_PRODUCTS).find(product => product.priceId === priceId);
};
