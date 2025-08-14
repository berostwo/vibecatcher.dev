# Stripe Payment Integration Setup

This document explains how to set up Stripe payments for the VibeCatcher security audit application.

## Prerequisites

1. A Stripe account (https://stripe.com)
2. Access to your Stripe Dashboard

## Step 1: Create Products in Stripe

1. Go to your Stripe Dashboard > Products
2. Create three products:
   - **Single Audit**: $4.99
   - **5 Audits**: $11.99  
   - **10 Audits**: $18.99

3. For each product, create a price:
   - Set the price amount in USD
   - Choose "One-time" pricing
   - Copy the Price ID (starts with `price_`)

## Step 2: Configure Environment Variables

Add these to your `.env.local` file:

```bash
# Stripe Configuration (Client-Side)
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_test_your_publishable_key_here

# Stripe Price IDs (Client-Side)
NEXT_PUBLIC_STRIPE_SINGLE_AUDIT_PRICE_ID=price_your_single_audit_price_id
NEXT_PUBLIC_STRIPE_FIVE_AUDITS_PRICE_ID=price_your_five_audits_price_id
NEXT_PUBLIC_STRIPE_TEN_AUDITS_PRICE_ID=price_your_ten_audits_price_id
```

Add these to your production environment (Vercel, etc.):

```bash
# Stripe Configuration (Server-Side - Keep Secret!)
STRIPE_SECRET_KEY=sk_test_your_secret_key_here
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret_here
```

## Step 3: Set Up Webhooks

1. Go to Stripe Dashboard > Developers > Webhooks
2. Click "Add endpoint"
3. Set the endpoint URL to: `https://yourdomain.com/api/webhooks/stripe`
4. Select these events:
   - `payment_intent.succeeded`
   - `payment_intent.payment_failed`
5. Copy the webhook signing secret to your environment variables

## Step 4: Test the Integration

1. Start your development server: `npm run dev`
2. Navigate to the dashboard
3. Click on any of the three product cards in the sidebar
4. The sidebar should expand and show the payment form
5. Use Stripe test card numbers:
   - Success: `4242 4242 4242 4242`
   - Decline: `4000 0000 0000 0002`

## How It Works

### User Flow
1. User clicks on a product card in the sidebar
2. Sidebar expands to show payment form
3. Main content is blurred during payment
4. User enters card details and submits
5. Payment is processed via Stripe
6. On success, sidebar collapses and content unblurs
7. User's audit count is updated (TODO: implement database update)

### Technical Implementation
- **Frontend**: React components with Stripe Elements
- **Backend**: API routes for payment intent creation
- **Webhooks**: Handle successful/failed payments
- **State Management**: React Context for sidebar expansion
- **Animation**: CSS transitions for smooth sidebar expansion

## Security Features

- All sensitive Stripe operations happen server-side
- Client only receives publishable keys
- Webhook signatures are verified
- No card data touches your servers

## Troubleshooting

### Common Issues
1. **"Cannot find module '@stripe/react-stripe-js'"**
   - Run: `npm install @stripe/react-stripe-js`

2. **Payment form not showing**
   - Check that all environment variables are set
   - Verify Stripe provider is wrapping the dashboard

3. **Webhook errors**
   - Ensure webhook secret is correct
   - Check that webhook endpoint is accessible

### Testing
- Use Stripe's test mode for development
- Test with various card numbers and scenarios
- Monitor webhook events in Stripe Dashboard

## Next Steps

1. Implement database updates for successful payments
2. Add user audit count tracking
3. Implement audit usage tracking
4. Add payment history to user dashboard
5. Set up subscription-based pricing if needed
