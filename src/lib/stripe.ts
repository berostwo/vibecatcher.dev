import { loadStripe } from '@stripe/stripe-js';

// Client-side Stripe instance
export const getStripe = () => {
  const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!);
  return stripePromise;
};

// Product configuration
export const STRIPE_PRODUCTS = {
  SINGLE: {
    id: 'one_credit',
    name: '1 Credit',
    price: 7.99,
    credits: 1,
    priceId: process.env.NEXT_PUBLIC_STRIPE_SINGLE_AUDIT_PRICE_ID,
    description: '1 credit = up to 500 scannable code files'
  },
  FIVE: {
    id: 'five_credits',
    name: '5 Credits',
    price: 24.99,
    credits: 5,
    priceId: process.env.NEXT_PUBLIC_STRIPE_FIVE_AUDITS_PRICE_ID,
    description: '5 credits (each covers up to 500 files)'
  },
  TEN: {
    id: 'ten_credits',
    name: '10 Credits',
    price: 39.99,
    credits: 10,
    priceId: process.env.NEXT_PUBLIC_STRIPE_TEN_AUDITS_PRICE_ID,
    description: '10 credits (each covers up to 500 files)'
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
