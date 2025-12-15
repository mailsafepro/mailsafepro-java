/**
 * Constantes del dashboard
 */

import { 
    EnvelopeIcon, 
    KeyIcon, 
    ChartBarIcon, 
    CreditCardIcon,
    DocumentTextIcon,
  } from '@heroicons/react/24/solid';
  import type { DashboardFeature } from '../types/dashboard.types';
  
  export const getDashboardFeatures = (userPlan: string): DashboardFeature[] => [
    {
      title: 'Validar Email',
      description: 'Verifica si un email es válido en tiempo real',
      icon: EnvelopeIcon,
      path: '/dashboard/validate',
      available: true,
    },
    {
      title: 'Validación Lotes',
      description: 'Valida múltiples emails a la vez',
      icon: DocumentTextIcon,
      path: '/dashboard/batch-validation',
      available: userPlan !== 'FREE',
      requiresPremium: true,
    },
    {
      title: 'Claves API',
      description: 'Gestiona tus claves de autenticación',
      icon: KeyIcon,
      path: '/dashboard/api-keys',
      available: true,
    },
    {
      title: 'Estadísticas',
      description: 'Monitorea tu consumo de API',
      icon: ChartBarIcon,
      path: '/dashboard/usage',
      available: true,
    },
    {
      title: 'Facturación',
      description: 'Gestiona tu suscripción',
      icon: CreditCardIcon,
      path: '/dashboard/billing',
      available: true,
    },
  ];
  