'use client';

import { useState, useEffect } from 'react';
import { CardElement, useStripe, useElements } from '@stripe/react-stripe-js';
import { Button } from '@/components/ui/button';
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
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to create payment intent');
      }

      const { clientSecret } = await response.json();

      // Confirm payment
      const { error: confirmError } = await stripe.confirmCardPayment(clientSecret, {
        payment_method: {
          card: elements.getElement(CardElement)!,
        },
      });

      if (confirmError) {
        setError(confirmError.message || 'Payment failed');
      } else {
        setPaymentSuccess(true);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Payment failed');
    } finally {
      setIsLoading(false);
    }
  };

  if (paymentSuccess) {
    return (
      <div className="text-center p-6">
        <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4" />
        <h3 className="text-xl font-semibold mb-2">Payment Successful!</h3>
        <p className="text-muted-foreground">
          You now have {product?.audits} audit{product?.audits !== 1 ? 's' : ''} available.
        </p>
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
          variant="ghost" 
          size="sm" 
          className="mb-4 p-0 h-auto text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to packages
        </Button>
        
        <div className="bg-primary/10 rounded-lg p-4 border border-primary/20">
          <h3 className="font-semibold text-lg mb-2">{product.name}</h3>
          <p className="text-muted-foreground text-sm mb-2">{product.description}</p>
          <div className="flex items-center justify-between">
            <span className="text-2xl font-bold">${product.price}</span>
            <span className="text-sm text-muted-foreground">
              {product.audits} audit{product.audits !== 1 ? 's' : ''}
            </span>
          </div>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <label className="text-sm font-medium">Card Details</label>
          <div className="border rounded-md p-3 bg-background">
            <CardElement
              options={{
                style: {
                  base: {
                    fontSize: '16px',
                    color: 'hsl(var(--foreground))',
                    '::placeholder': {
                      color: 'hsl(var(--muted-foreground))',
                    },
                  },
                },
              }}
            />
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
