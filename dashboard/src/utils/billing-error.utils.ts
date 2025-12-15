/**
 * Utilidades para el manejo de errores de facturación
 */

import type { BillingApiError } from '../types/billing.types';

const ERROR_MESSAGES = {
  CHANGE_PLAN_ERROR: 'Error al cambiar el plan',
  PAYMENT_ERROR: 'Error al procesar el pago',
  CHECKOUT_ERROR: 'Error al crear la sesión de pago',
  STRIPE_LOAD_ERROR: 'Stripe no cargó correctamente',
  NO_TOKENS: 'No se recibieron tokens en la respuesta',
  UNAUTHORIZED: 'Sesión expirada. Por favor, inicia sesión de nuevo',
  SERVER_ERROR: 'Error del servidor. Por favor intenta más tarde',
  NETWORK_ERROR: 'Error de conexión. Verifica tu conexión a internet',
} as const;

/**
 * Parsea errores de API relacionados con facturación
 * @param error - Error capturado
 * @param defaultMessage - Mensaje por defecto
 * @returns Mensaje de error formateado
 */
export const parseBillingError = (
  error: BillingApiError,
  defaultMessage: string = ERROR_MESSAGES.CHANGE_PLAN_ERROR
): string => {
  const status = error.response?.status;
  const detail = error.response?.data?.detail;

  // Errores específicos por código de estado
  switch (status) {
    case 401:
      return ERROR_MESSAGES.UNAUTHORIZED;
    case 500:
      return ERROR_MESSAGES.SERVER_ERROR;
  }

  // Error con detail
  if (detail) {
    return detail;
  }

  // Error de red
  if (error.message === 'Network Error') {
    return ERROR_MESSAGES.NETWORK_ERROR;
  }

  // Mensaje específico del error o default
  return error.message || defaultMessage;
};
