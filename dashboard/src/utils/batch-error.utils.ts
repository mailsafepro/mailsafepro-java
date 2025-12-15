/**
 * Utilidades para el manejo de errores de validación por lotes
 */

import type { BatchValidationApiError } from '../types/batch-validation.types';

const ERROR_MESSAGES = {
  UNKNOWN: 'Error en la validación por lotes',
  UNAUTHORIZED: 'Sesión expirada. Por favor, inicia sesión de nuevo',
  FORBIDDEN: 'No tienes permiso para realizar validaciones por lotes',
  RATE_LIMIT: 'Has alcanzado tu límite de validaciones por lotes',
  SERVER_ERROR: 'Error del servidor. Por favor intenta más tarde',
  NETWORK_ERROR: 'Error de conexión. Verifica tu conexión a internet',
  FILE_REQUIRED: 'Selecciona un archivo',
  INVALID_FILE: 'El archivo seleccionado no es válido',
} as const;

/**
 * Parsea errores de API de validación por lotes
 * @param error - Error capturado de la petición
 * @returns Mensaje de error formateado
 */
export const parseBatchValidationError = (error: BatchValidationApiError): string => {
  const status = error.response?.status;
  const detail = error.response?.data?.detail;

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

  // Error con detail
  if (detail) {
    return detail;
  }

  // Error de red
  if (error.message === 'Network Error') {
    return ERROR_MESSAGES.NETWORK_ERROR;
  }

  return ERROR_MESSAGES.UNKNOWN;
};
