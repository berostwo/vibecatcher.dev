'use client';

import React, { createContext, useContext, useState, ReactNode } from 'react';

interface PaymentSidebarContextType {
  isExpanded: boolean;
  setIsExpanded: (expanded: boolean) => void;
  selectedProduct: string | null;
  setSelectedProduct: (productId: string | null) => void;
}

const PaymentSidebarContext = createContext<PaymentSidebarContextType | undefined>(undefined);

export function PaymentSidebarProvider({ children }: { children: ReactNode }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [selectedProduct, setSelectedProduct] = useState<string | null>(null);

  const value = {
    isExpanded,
    setIsExpanded,
    selectedProduct,
    setSelectedProduct,
  };

  return (
    <PaymentSidebarContext.Provider value={value}>
      {children}
    </PaymentSidebarContext.Provider>
  );
}

export function usePaymentSidebar() {
  const context = useContext(PaymentSidebarContext);
  if (context === undefined) {
    throw new Error('usePaymentSidebar must be used within a PaymentSidebarProvider');
  }
  return context;
}
