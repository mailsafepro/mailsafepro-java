/**
 * Utilidades para el manejo de errores de API Keys
 */

import type { ApiKeysError } from '../types/api-keys.types';

const ERROR_MESSAGES = {
  FETCH_ERROR: 'Error al cargar claves API',
  CREATE_ERROR: 'Error creando API Key',
  REVOKE_ERROR: 'Error al revocar la clave',
  COPY_ERROR: 'Error al copiar al portapapeles',
  UNAUTHORIZED: 'Sesión expirada. Por favor, inicia sesión de nuevo',
  FORBIDDEN: 'No tienes permiso para realizar esta acción',
  RATE_LIMIT: 'Has alcanzado tu límite de API Keys',
  SERVER_ERROR: 'Error del servidor. Por favor intenta más tarde',
  NETWORK_ERROR: 'Error de conexión. Verifica tu conexión a internet',
} as const;

/**
 * Parsea errores de API relacionados con API Keys
 * @param error - Error capturado
 * @param defaultMessage - Mensaje por defecto
 * @returns Mensaje de error formateado
 */
export const parseApiKeysError = (
  error: ApiKeysError,
  defaultMessage: string = ERROR_MESSAGES.FETCH_ERROR
): string => {
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

  return defaultMessage;
};