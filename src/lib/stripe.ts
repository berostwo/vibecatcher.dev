// Audit package configurations with Stripe price IDs
export const AUDIT_PACKAGES = [
  {
    id: 'single_audit',
    name: 'Single Audit',
    description: '+1 Audit',
    price: 4.99,
    audits: 1,
    popular: false,
    priceId: process.env.NEXT_PUBLIC_STRIPE_SINGLE_AUDIT_PRICE_ID || '',
  },
  {
    id: 'five_audits',
    name: '5 Audits',
    description: '+5 Audits',
    price: 11.99,
    audits: 5,
    popular: true,
    priceId: process.env.NEXT_PUBLIC_STRIPE_FIVE_AUDITS_PRICE_ID || '',
  },
  {
    id: 'ten_audits',
    name: '10 Audits',
    description: '+10 Audits',
    price: 18.99,
    audits: 10,
    popular: false,
    priceId: process.env.NEXT_PUBLIC_STRIPE_TEN_AUDITS_PRICE_ID || '',
  },
];
