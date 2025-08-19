'use client';

import { useState, useEffect } from 'react';
import { CardElement, CardNumberElement, CardExpiryElement, CardCvcElement, useStripe, useElements } from '@stripe/react-stripe-js';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { STRIPE_PRODUCTS, getProductById } from '@/lib/stripe';
import { ArrowLeft, CreditCard, CheckCircle } from 'lucide-react';

interface PaymentFormProps {
  productId: string;
  onBack: () => void;
  onSuccess: () => void;
}

export function PaymentForm({ productId, onBack, onSuccess }: PaymentFormProps) {
  const stripe = useStripe();
  const elements = useElements();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [paymentSuccess, setPaymentSuccess] = useState(false);
  // Minimal required fields + optional receipt details
  const [payerEmail, setPayerEmail] = useState('');
  const [payerName, setPayerName] = useState('');

  const product = getProductById(productId);

  useEffect(() => {
    if (paymentSuccess) {
      const timer = setTimeout(() => {
        onSuccess();
      }, 2000);
      return () => clearTimeout(timer);
    }
  }, [paymentSuccess, onSuccess]);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();

    if (!stripe || !elements) {
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      // Create payment intent
      const response = await fetch('/api/create-payment-intent', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          priceId: product?.priceId,
          quantity: 1,
          // attach userId so webhook can credit
          userId: (typeof window !== 'undefined' && window.localStorage.getItem('uid')) || undefined,
          payerEmail: payerEmail || undefined,
          payerName: payerName || undefined,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to create payment intent');
      }

      const { clientSecret } = await response.json();

      // Confirm payment
      const numberEl = elements.getElement(CardNumberElement);
      const { error: confirmError } = await stripe.confirmCardPayment(clientSecret, {
        payment_method: {
          card: numberEl!,
        },
      });

      if (confirmError) {
        setError('Payment failed. Please verify your card details or try another method.');
      } else {
        setPaymentSuccess(true);
      }
    } catch (err) {
      setError('Payment failed. Please try again later.');
    } finally {
      setIsLoading(false);
    }
  };

  if (paymentSuccess) {
    return (
      <div className="text-center p-6">
        <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4" />
        <h3 className="text-xl font-semibold mb-2">Payment Successful!</h3>
        <p className="text-muted-foreground">Credits added to your account.</p>
      </div>
    );
  }

  if (!product) {
    return (
      <div className="text-center p-6">
        <p className="text-red-500">Product not found</p>
        <Button onClick={onBack} variant="outline" className="mt-4">
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back
        </Button>
      </div>
    );
  }

  return (
    <div className="p-4">
      <div className="mb-6">
        <Button 
          onClick={onBack} 
          size="sm" 
          className="mb-4 px-3 py-1.5 bg-purple-600 hover:bg-purple-700 text-white"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back
        </Button>
        
        <div className="bg-primary/10 rounded-lg p-4 border border-primary/20">
          <h3 className="font-semibold text-lg mb-2">{product.name}</h3>
          <p className="text-muted-foreground text-sm mb-2">{product.description}</p>
          <div className="flex items-center justify-between">
            <span className="text-2xl font-bold">${product.price}</span>
            <span className="text-sm text-muted-foreground">
              {product.credits} credit{product.credits !== 1 ? 's' : ''}
            </span>
          </div>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Required payer details */}
        <div className="grid grid-cols-1 gap-3">
          <div className="space-y-1">
            <Label className="text-foreground">Full name</Label>
            <Input 
              value={payerName} 
              onChange={(e) => setPayerName(e.target.value)} 
              placeholder="John Doe" 
              required
              className="bg-white text-[hsl(var(--background))] placeholder:text-gray-400 border rounded-md"
              autoComplete="name"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-foreground">Email</Label>
            <Input 
              type="email" 
              value={payerEmail} 
              onChange={(e) => setPayerEmail(e.target.value)} 
              placeholder="name@email.com" 
              required
              className="bg-white text-[hsl(var(--background))] placeholder:text-gray-400 border rounded-md"
              autoComplete="email"
            />
          </div>
        </div>
        {/* Card number */}
        <div className="space-y-1">
          <Label className="text-foreground">Card number</Label>
          <div className="rounded-md p-3 border bg-white">
            <CardNumberElement
              options={{
                showIcon: true,
                style: {
                  base: {
                    fontSize: '16px',
                    color: 'hsl(var(--background))',
                    iconColor: 'hsl(var(--background))',
                    '::placeholder': { color: '#9ca3af' },
                  },
                },
              }}
            />
          </div>
        </div>
        {/* Expiry / CVC */}
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <Label className="text-foreground">Expiry</Label>
            <div className="rounded-md p-3 border bg-white">
              <CardExpiryElement
                options={{
                  style: {
                    base: {
                      fontSize: '16px',
                      color: 'hsl(var(--background))',
                      '::placeholder': { color: '#9ca3af' },
                    },
                  },
                }}
              />
            </div>
          </div>
          <div className="space-y-1">
            <Label className="text-foreground">CVC</Label>
            <div className="rounded-md p-3 border bg-white">
              <CardCvcElement
                options={{
                  style: {
                    base: {
                      fontSize: '16px',
                      color: 'hsl(var(--background))',
                      '::placeholder': { color: '#9ca3af' },
                    },
                  },
                }}
              />
            </div>
          </div>
        </div>

        {error && (
          <div className="text-red-500 text-sm bg-red-50 dark:bg-red-950/20 p-3 rounded-md">
            {error}
          </div>
        )}

        <Button 
          type="submit" 
          disabled={!stripe || isLoading} 
          className="w-full"
        >
          {isLoading ? (
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
          ) : (
            <>
              <CreditCard className="w-4 h-4 mr-2" />
              Pay ${product.price}
            </>
          )}
        </Button>
      </form>
    </div>
  );
}
