/**
 * Utilidades para el manejo de errores de uso
 */

import type { UsageApiError } from '../types/usage.types';

const ERROR_MESSAGES = {
  FETCH_ERROR: 'Error al cargar los datos de uso',
  UNAUTHORIZED: 'Sesión expirada. Por favor, inicia sesión de nuevo',
  FORBIDDEN: 'No tienes permiso para ver los datos de uso',
  SERVER_ERROR: 'Error del servidor. Por favor intenta más tarde',
  NETWORK_ERROR: 'Error de conexión. Verifica tu conexión a internet',
} as const;

/**
 * Parsea errores de API relacionados con uso
 * @param error - Error capturado
 * @returns Mensaje de error formateado
 */
export const parseUsageError = (error: UsageApiError): string => {
  const status = error.response?.status;
  const detail = error.response?.data?.detail;

  // Errores específicos por código de estado
  switch (status) {
    case 401:
      return ERROR_MESSAGES.UNAUTHORIZED;
    case 403:
      return ERROR_MESSAGES.FORBIDDEN;
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

  return ERROR_MESSAGES.FETCH_ERROR;
};
