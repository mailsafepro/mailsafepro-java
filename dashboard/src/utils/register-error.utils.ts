/**
 * Utilidades para el manejo de errores de registro
 */

import type { RegisterApiError, RegisterFormErrors } from '../types/register.types';

const ERROR_MESSAGES = {
  UNKNOWN: 'Error desconocido en el registro',
  EMAIL_EXISTS: 'Este email ya está registrado. Intenta con otro o inicia sesión',
  RATE_LIMIT: 'Demasiados intentos. Por favor intenta más tarde',
  SERVER_ERROR: 'Error del servidor. Por favor intenta más tarde',
  NETWORK_ERROR: 'Error de conexión. Verifica tu conexión a internet',
} as const;

/**
 * Parsea errores de API de registro y los mapea a errores de formulario
 * @param error - Error capturado de la petición de registro
 * @returns Tupla con errores de formulario y mensaje general
 */
export const parseRegisterError = (
  error: RegisterApiError
): { formErrors: RegisterFormErrors; generalError: string } => {
  const formErrors: RegisterFormErrors = {};
  let generalError: string = ERROR_MESSAGES.UNKNOWN;  // 👈 Añade el tipo explícito ": string"

  const status = error.response?.status;
  const data = error.response?.data;

  // Manejo de errores de validación de Pydantic (422)
  if (status === 422 && data?.errors) {
    const apiErrors = data.errors;

    apiErrors.forEach((apiError) => {
      const field = apiError.field?.split('.').pop() || 'general';
      const message = apiError.message || apiError.detail || 'Error de validación';

      if (field === 'email') {
        formErrors.email = message;
      } else if (field === 'password') {
        formErrors.password = message;
      } else {
        generalError = message;
      }
    });

    return { formErrors, generalError };
  }

  // Otros errores HTTP con detail
  if (data?.detail) {
    const detail = data.detail;

    if (typeof detail === 'string') {
      generalError = detail;
    } else if (typeof detail === 'object') {
      if (detail.error) {
        generalError = detail.error;
        if (detail.retry_after) {
          generalError += ` Reintentar en ${detail.retry_after}s`;
        }
      }

      if (detail.email) {
        formErrors.email = detail.email;
      }

      if (detail.password) {
        formErrors.password = detail.password;
      }
    }
  }

  // Errores específicos por código de estado
  if (status === 409) {
    formErrors.email = ERROR_MESSAGES.EMAIL_EXISTS;
  } else if (status === 429) {
    generalError = ERROR_MESSAGES.RATE_LIMIT;
  } else if (status === 500) {
    generalError = ERROR_MESSAGES.SERVER_ERROR;
  } else if (error.message === 'Network Error') {
    generalError = ERROR_MESSAGES.NETWORK_ERROR;
  }

  return { formErrors, generalError };
};
