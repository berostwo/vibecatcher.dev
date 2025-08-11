'use client';

import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { ShoppingCart, CreditCard, CheckCircle } from 'lucide-react';
import { AUDIT_PACKAGES } from '@/lib/stripe';
import { useAuthContext } from '@/contexts/auth-context';
import { Elements, PaymentElement, useStripe, useElements } from '@stripe/react-stripe-js';
import { loadStripe } from '@stripe/stripe-js';

// Load Stripe with your publishable key
const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!);

interface PaymentFormProps {
  packageId: string;
  onSuccess: () => void;
  onCancel: () => void;
}

function PaymentForm({ packageId, onSuccess, onCancel }: PaymentFormProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const stripe = useStripe();
  const elements = useElements();

  const selectedPackage = AUDIT_PACKAGES.find(pkg => pkg.id === packageId);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();

    if (!stripe || !elements) {
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Create payment intent
      const response = await fetch('/api/create-payment-intent', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          packageId,
          userId: useAuthContext().user?.uid,
        }),
      });

      const { clientSecret } = await response.json();

      // Confirm payment
      const { error: confirmError } = await stripe.confirmPayment({
        elements,
        clientSecret,
        confirmParams: {
          return_url: `${window.location.origin}/dashboard?success=true&package=${packageId}`,
        },
      });

      if (confirmError) {
        setError(confirmError.message || 'Payment failed');
      } else {
        onSuccess();
      }
    } catch (err) {
      setError('An unexpected error occurred');
      console.error('Payment error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Package Summary */}
      <div className="bg-sidebar-accent/50 rounded-lg p-4 border border-primary/20">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-semibold text-foreground">{selectedPackage?.name}</h3>
            <p className="text-sm text-muted-foreground">{selectedPackage?.description}</p>
          </div>
          <div className="text-right">
            <p className="text-lg font-bold text-primary">${selectedPackage?.price}</p>
            <p className="text-xs text-muted-foreground">{selectedPackage?.audits} audits</p>
          </div>
        </div>
      </div>

      {/* Payment Form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <PaymentElement 
          options={{
            layout: 'tabs',
            defaultValues: {
              billingDetails: {
                name: useAuthContext().user?.displayName || '',
                email: useAuthContext().user?.email || '',
              }
            }
          }}
        />

        {error && (
          <div className="text-red-500 text-sm bg-red-500/10 border border-red-500/20 rounded-md p-3">
            {error}
          </div>
        )}

        <div className="flex gap-3 pt-4">
          <Button
            type="button"
            variant="outline"
            onClick={onCancel}
            disabled={loading}
            className="flex-1"
          >
            Cancel
          </Button>
          <Button
            type="submit"
            disabled={!stripe || loading}
            className="flex-1"
          >
            {loading ? (
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-current"></div>
            ) : (
              <>
                <CreditCard className="h-4 w-4 mr-2" />
                Pay ${selectedPackage?.price}
              </>
            )}
          </Button>
        </div>
      </form>
    </div>
  );
}

export function StripePayment() {
  const [selectedPackage, setSelectedPackage] = useState<string | null>(null);
  const [clientSecret, setClientSecret] = useState<string | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const { user } = useAuthContext();

  const handlePackageSelect = async (packageId: string) => {
    if (!user) return;

    setLoading(packageId);
    
    try {
      // Create payment intent to get client secret
      const response = await fetch('/api/create-payment-intent', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          packageId,
          userId: user.uid,
        }),
      });

      const { clientSecret: secret } = await response.json();
      setClientSecret(secret);
      setSelectedPackage(packageId);
    } catch (error) {
      console.error('Error creating payment intent:', error);
    } finally {
      setLoading(null);
    }
  };

  const handleCancel = () => {
    setSelectedPackage(null);
    setClientSecret(null);
  };

  const handleSuccess = () => {
    setSelectedPackage(null);
    setClientSecret(null);
    // Optionally redirect or show success message
  };

  if (selectedPackage && clientSecret) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">Complete Payment</h3>
          <Button variant="ghost" size="sm" onClick={handleCancel}>
            ← Back to packages
          </Button>
        </div>
        
        <Elements 
          stripe={stripePromise} 
          options={{
            clientSecret,
            appearance: {
              theme: 'night', // Dark theme
              variables: {
                colorPrimary: '#794bc4', // Your electric purple
                colorBackground: '#0f0f23', // Dark background
                colorText: '#ffffff',
                colorDanger: '#ef4444',
                fontFamily: 'Inter, system-ui, sans-serif',
                spacingUnit: '4px',
                borderRadius: '8px',
              },
              rules: {
                '.Tab': {
                  border: '1px solid #374151',
                  backgroundColor: '#1f2937',
                },
                '.Tab:hover': {
                  backgroundColor: '#374151',
                },
                '.Tab--selected': {
                  backgroundColor: '#794bc4',
                  borderColor: '#794bc4',
                },
                '.Input': {
                  backgroundColor: '#1f2937',
                  border: '1px solid #374151',
                  color: '#ffffff',
                },
                '.Input:focus': {
                  borderColor: '#794bc4',
                  boxShadow: '0 0 0 1px #794bc4',
                },
              },
            },
          }}
        >
          <PaymentForm 
            packageId={selectedPackage} 
            onSuccess={handleSuccess}
            onCancel={handleCancel}
          />
        </Elements>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {AUDIT_PACKAGES.map((pkg) => (
        <Button 
          key={pkg.id}
          onClick={() => handlePackageSelect(pkg.id)}
          disabled={loading === pkg.id}
          variant="outline" 
          className="w-full justify-between h-auto p-3 bg-sidebar-accent border-2 border-primary/20 hover:bg-background/50"
        >
          <div>
            <p className="text-sm font-medium text-left">{pkg.name}</p>
            <p className="text-xs text-muted-foreground text-left">${pkg.price}</p>
          </div>
          {loading === pkg.id ? (
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
          ) : (
            <ShoppingCart className="h-4 w-4 text-primary" />
          )}
        </Button>
      ))}
    </div>
  );
}
