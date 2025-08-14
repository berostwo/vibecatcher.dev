'use client';

import { ReactNode } from 'react';
import { usePaymentSidebar } from '@/contexts/sidebar-context';

interface BlurWrapperProps {
  children: ReactNode;
}

export function BlurWrapper({ children }: BlurWrapperProps) {
  const { isExpanded } = usePaymentSidebar();

  return (
    <div 
      className={`transition-all duration-300 ${
        isExpanded 
          ? 'blur-sm pointer-events-none' 
          : 'blur-none pointer-events-auto'
      }`}
    >
      {children}
    </div>
  );
}
