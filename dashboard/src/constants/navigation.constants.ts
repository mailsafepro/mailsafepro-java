/**
 * Constantes de navegación del dashboard
 */

import {
    HomeIcon,
    KeyIcon,
    ChartBarIcon,
    EnvelopeIcon,
    CreditCardIcon,
    UserIcon,
    SparklesIcon,
  } from '@heroicons/react/24/solid';
  import type { NavItem } from '../types/layout.types';
  
  export const NAV_ITEMS: NavItem[] = [
    { 
      path: '/dashboard', 
      label: 'Dashboard', 
      icon: HomeIcon 
    },
    { 
      path: '/dashboard/validate', 
      label: 'Validar Email', 
      icon: EnvelopeIcon 
    },
    { 
      path: '/dashboard/batch-validation', 
      label: 'Validación Lotes', 
      icon: SparklesIcon, 
      requireFeature: 'batch' 
    },
    { 
      path: '/dashboard/api-keys', 
      label: 'Claves API', 
      icon: KeyIcon 
    },
    { 
      path: '/dashboard/usage', 
      label: 'Uso', 
      icon: ChartBarIcon 
    },
    { 
      path: '/dashboard/billing', 
      label: 'Facturación', 
      icon: CreditCardIcon 
    },
    { 
      path: '/dashboard/profile', 
      label: 'Perfil', 
      icon: UserIcon 
    },
  ];
  
  export const PLAN_DISPLAY_NAMES: Record<string, string> = {
    FREE: 'Gratis',
    PREMIUM: 'Premium',
    ENTERPRISE: 'Enterprise',
  };
  