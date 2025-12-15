/**
 * Utilidades para el manejo de errores de validación
 */

import type { ValidationApiError } from '../types/validation.types';

const ERROR_MESSAGES = {
  UNKNOWN: 'Error desconocido en la validación',
  UNAUTHORIZED: 'Sesión expirada. Por favor, inicia sesión de nuevo',
  FORBIDDEN: 'No tienes permiso para validar emails',
  VALIDATION_ERROR: 'Error de validación',
  RATE_LIMIT: 'Has alcanzado tu límite diario. Intenta mañana',
  SERVER_ERROR: 'Error del servidor. Por favor intenta más tarde',
  NETWORK_ERROR: 'Error de conexión. Verifica tu conexión a internet',
} as const;

/**
 * Parsea errores de API de validación y devuelve un mensaje amigable
 * @param error - Error capturado de la petición de validación
 * @returns Mensaje de error formateado para el usuario
 */
export const parseValidationError = (error: ValidationApiError): string => {
  const status = error.response?.status;
  const data = error.response?.data;

  // Errores específicos por código de estado
  switch (status) {
    case 401:
      return ERROR_MESSAGES.UNAUTHORIZED;
    case 403:
      return ERROR_MESSAGES.FORBIDDEN;
    case 429:
      return ERROR_MESSAGES.RATE_LIMIT;
    case 500:
      return ERROR_MESSAGES.SERVER_ERROR;
  }

  // Error 422 con validaciones
  if (status === 422) {
    if (data?.errors) {
      const firstError = data.errors[0];
      return firstError.message || ERROR_MESSAGES.VALIDATION_ERROR;
    }
    return data?.detail || ERROR_MESSAGES.VALIDATION_ERROR;
  }

  // Error con detail genérico
  if (data?.detail) {
    return data.detail;
  }

  // Error de red
  if (error.message === 'Network Error') {
    return ERROR_MESSAGES.NETWORK_ERROR;
  }

  return ERROR_MESSAGES.UNKNOWN;
};

