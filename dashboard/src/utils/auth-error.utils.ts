/**
 * Utilidades para el manejo de errores de autenticación
 */

import { ApiError } from '../types/auth.types';

const ERROR_MESSAGES = {
  UNKNOWN: 'Error de autenticación desconocido',
  INVALID_CREDENTIALS: 'Credenciales inválidas. Verifica tu email y contraseña',
  ACCESS_DENIED: 'Acceso denegado',
  RATE_LIMIT: 'Demasiados intentos de inicio de sesión. Intenta más tarde',
  SERVER_ERROR: 'Error del servidor. Por favor intenta más tarde',
  NETWORK_ERROR: 'Error de conexión. Verifica tu conexión a internet',
} as const;

/**
 * Parsea errores de API y devuelve un mensaje amigable al usuario
 * @param error - Error capturado de la petición de login
 * @returns Mensaje de error formateado para el usuario
 */
export const parseLoginError = (error: ApiError): string => {
  const status = error.response?.status;
  const data = error.response?.data;

  // Error 422 con validaciones
  if (status === 422 && data?.errors) {
    const firstError = data.errors[0];
    if (firstError?.message) {
      return firstError.message;
    }
  }

  // Error con detail (string u objeto)
  if (data?.detail) {
    if (typeof data.detail === 'string') {
      return data.detail;
    }
    
    if (typeof data.detail === 'object' && 'error' in data.detail) {
      let message = data.detail.error;
      if ('retry_after' in data.detail && data.detail.retry_after) {
        message += ` Reintentar en ${data.detail.retry_after}s`;
      }
      return message;
    }
  }

  // Errores por código de estado HTTP
  switch (status) {
    case 401:
      return ERROR_MESSAGES.INVALID_CREDENTIALS;
    case 403:
      return ERROR_MESSAGES.ACCESS_DENIED;
    case 429:
      return ERROR_MESSAGES.RATE_LIMIT;
    case 500:
      return ERROR_MESSAGES.SERVER_ERROR;
  }

  // Error de red
  if (error.message === 'Network Error') {
    return ERROR_MESSAGES.NETWORK_ERROR;
  }

  return ERROR_MESSAGES.UNKNOWN;
};