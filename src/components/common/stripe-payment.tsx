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
  const { user } = useAuthContext();

  const selectedPackage = AUDIT_PACKAGES.find(pkg => pkg.id === packageId);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();

    if (!stripe || !elements) {
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // First, submit the elements to validate the form
      const { error: submitError } = await elements.submit();
      if (submitError) {
        setError(submitError.message || 'Form validation failed');
        setLoading(false);
        return;
      }

      // Create payment intent
      const response = await fetch('/api/create-payment-intent', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          packageId,
          userId: user?.uid,
        }),
      });

      const { clientSecret } = await response.json();

      // Confirm payment
      const { error: confirmError, paymentIntent } = await stripe.confirmPayment({
        elements,
        clientSecret,
        confirmParams: {
          return_url: `${window.location.origin}/dashboard?success=true&package=${packageId}`,
        },
        redirect: 'if_required', // Don't redirect, handle locally
      });

      console.log('💳 Payment confirmation result:', { confirmError, paymentIntent });

      if (confirmError) {
        console.error('❌ Payment confirmation error:', confirmError);
        setError(confirmError.message || 'Payment failed');
      } else if (paymentIntent && paymentIntent.status === 'succeeded') {
        console.log('✅ Payment succeeded locally, calling success handler');
        // Payment succeeded locally, call success handler
        onSuccess();
      } else {
        console.log('⏳ Payment is processing, waiting for webhook...');
        // Payment is processing, wait for webhook
        setError('Payment is processing. Please wait a moment...');
        // Check payment status after a delay
        setTimeout(async () => {
          try {
            console.log('🔍 Checking payment status...');
            const response = await fetch(`/api/check-payment-status?paymentIntentId=${paymentIntent?.id}`);
            if (response.ok) {
              console.log('✅ Payment status check successful, calling success handler');
              onSuccess();
            } else {
              console.log('⚠️ Payment status check failed, attempting manual audit addition...');
              // If webhook didn't work, try to manually add audits
              console.log('Webhook may not have worked, attempting manual audit addition...');
              const manualResponse = await fetch('/api/manual-add-audits', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  paymentIntentId: paymentIntent?.id,
                  userId: user?.uid,
                  packageId
                })
              });
              
              if (manualResponse.ok) {
                console.log('✅ Manual audit addition successful');
                onSuccess();
              } else {
                console.log('❌ Manual audit addition failed');
                setError('Payment processing. Your audits will be added shortly.');
              }
            }
          } catch (err) {
            console.error('❌ Error checking payment status:', err);
            setError('Payment processing. Your audits will be added shortly.');
          }
        }, 3000);
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
                name: user?.displayName || '',
                email: user?.email || '',
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

export function StripePayment({ 
  onPaymentStart, 
  onPaymentEnd,
  onPaymentSuccess
}: { 
  onPaymentStart?: () => void;
  onPaymentEnd?: () => void;
  onPaymentSuccess?: (packageId: string) => void;
}) {
  const [selectedPackage, setSelectedPackage] = useState<string | null>(null);
  const [clientSecret, setClientSecret] = useState<string | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [showSuccess, setShowSuccess] = useState(false);
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

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to create payment intent');
      }

      const { clientSecret: secret } = await response.json();
      setClientSecret(secret);
      setSelectedPackage(packageId);
      
      // Notify parent component that payment mode has started
      onPaymentStart?.();
    } catch (error) {
      console.error('Error creating payment intent:', error);
      alert('Failed to create payment. Please try again.');
    } finally {
      setLoading(null);
    }
  };

  const handleCancel = () => {
    setSelectedPackage(null);
    setClientSecret(null);
    
    // Notify parent component that payment mode has ended
    onPaymentEnd?.();
  };

  const handleSuccess = () => {
    console.log('🎉 Payment success handler called');
    setShowSuccess(true);
    setSelectedPackage(null);
    setClientSecret(null);
    
    // Notify parent component that payment mode has ended
    onPaymentEnd?.();
    
    // Notify parent component that payment succeeded (for audit counter update)
    if (selectedPackage) {
      onPaymentSuccess?.(selectedPackage);
    }
    
    console.log('✅ Payment completed successfully - audits should be added via webhook');
    
    // Don't refresh the page - let the webhook update the audit counter
    // The dashboard will auto-refresh every 30 seconds to show the new count
    
    // Hide success message after 5 seconds
    setTimeout(() => {
      setShowSuccess(false);
    }, 5000);
  };

  if (showSuccess) {
    return (
      <div className="space-y-4">
        <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-6 text-center">
          <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-green-500 mb-2">Payment Successful!</h3>
          <p className="text-muted-foreground">
            Your audits have been added to your account. You can now start security audits.
          </p>
        </div>
        <Button 
          onClick={() => setShowSuccess(false)} 
          className="w-full"
        >
          Continue
        </Button>
      </div>
    );
  }

  if (selectedPackage && clientSecret) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">Complete Payment</h3>
          <Button 
            size="sm" 
            onClick={handleCancel}
            className="bg-primary hover:bg-primary/90 text-primary-foreground"
          >
            ← Back
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
