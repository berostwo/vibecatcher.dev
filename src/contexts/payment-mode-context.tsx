"use client"

import { createContext, useContext, useState, ReactNode } from 'react';

interface PaymentModeContextType {
  isPaymentMode: boolean;
  setIsPaymentMode: (mode: boolean) => void;
}

const PaymentModeContext = createContext<PaymentModeContextType | undefined>(undefined);

export function PaymentModeProvider({ children }: { children: ReactNode }) {
  const [isPaymentMode, setIsPaymentMode] = useState(false);

  return (
    <PaymentModeContext.Provider value={{ isPaymentMode, setIsPaymentMode }}>
      {children}
    </PaymentModeContext.Provider>
  );
}

export function usePaymentMode() {
  const context = useContext(PaymentModeContext);
  if (context === undefined) {
    throw new Error('usePaymentMode must be used within a PaymentModeProvider');
  }
  return context;
}
