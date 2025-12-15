/**
 * Utilidades para perfil de usuario
 */

import type { AccountStatus } from '../types/profile.types';

/**
 * Formatea el nombre del plan para mostrar
 * @param plan - Identificador del plan
 * @returns Nombre formateado del plan
 */
export const formatPlanName = (plan: string): string => {
  const planNames: Record<string, string> = {
    FREE: 'Gratis',
    PREMIUM: 'Premium',
    ENTERPRISE: 'Enterprise',
  };

  return planNames[plan] || plan;
};

/**
 * Obtiene el color del estado
 * @param status - Estado de la cuenta
 * @returns Clase de color de Tailwind
 */
export const getStatusColor = (status: string): string => {
  const statusColors: Record<string, string> = {
    active: 'text-green-600',
    inactive: 'text-gray-600',
    suspended: 'text-red-600',
  };

  return statusColors[status.toLowerCase()] || 'text-gray-600';
};

/**
 * Traduce el estado al español
 * @param status - Estado en inglés
 * @returns Estado en español
 */
export const translateStatus = (status: string): AccountStatus => {
  const translations: Record<string, AccountStatus> = {
    active: 'Activo',
    inactive: 'Inactivo',
    suspended: 'Suspendido',
  };

  return translations[status.toLowerCase()] || 'Activo';
};
