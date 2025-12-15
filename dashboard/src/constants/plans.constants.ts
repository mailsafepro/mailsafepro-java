/**
 * Definición de planes disponibles
 */

import type { Plan } from '../types/billing.types';

export const AVAILABLE_PLANS: Plan[] = [
  {
    id: 'FREE',
    name: 'Gratis',
    price: 0,
    currency: 'EUR',
    billing_period: 'mes',
    features: [
      '100 validaciones/mes',
      'Validación básica',
      'Soporte por email',
      '1 API Key',
    ],
  },
  {
    id: 'PREMIUM',
    name: 'Premium',
    price: 9.99,
    currency: 'EUR',
    billing_period: 'mes',
    features: [
      '10,000 validaciones/mes',
      'Validación avanzada',
      'Validación por lotes',
      'Soporte prioritario',
      '5 API Keys',
    ],
  },
  {
    id: 'ENTERPRISE',
    name: 'Enterprise',
    price: 99.99,
    currency: 'EUR',
    billing_period: 'mes',
    features: [
      'Validaciones ilimitadas',
      'Validación avanzada',
      'Validación por lotes',
      'Soporte 24/7',
      'Claves API ilimitadas',
      'Webhooks',
    ],
  },
];

