/**
 * Utilidades para manejo de tokens
 */

import { TOKEN_STORAGE_KEYS } from '../config/api.config';

/**
 * Obtiene el access token del storage
 * @returns Access token o null
 */
export const getAccessToken = (): string | null => {
  return sessionStorage.getItem(TOKEN_STORAGE_KEYS.ACCESS_TOKEN);
};

/**
 * Obtiene el refresh token del storage
 * @returns Refresh token o null
 */
export const getRefreshToken = (): string | null => {
  return sessionStorage.getItem(TOKEN_STORAGE_KEYS.REFRESH_TOKEN);
};

/**
 * Guarda los tokens en el storage
 * @param accessToken - Access token
 * @param refreshToken - Refresh token
 */
export const setTokens = (accessToken: string, refreshToken: string): void => {
  sessionStorage.setItem(TOKEN_STORAGE_KEYS.ACCESS_TOKEN, accessToken);
  sessionStorage.setItem(TOKEN_STORAGE_KEYS.REFRESH_TOKEN, refreshToken);
};

/**
 * Limpia todos los tokens y datos de usuario del storage
 */
export const clearTokens = (): void => {
  sessionStorage.removeItem(TOKEN_STORAGE_KEYS.ACCESS_TOKEN);
  sessionStorage.removeItem(TOKEN_STORAGE_KEYS.REFRESH_TOKEN);
  sessionStorage.removeItem(TOKEN_STORAGE_KEYS.USER_EMAIL);
  sessionStorage.removeItem(TOKEN_STORAGE_KEYS.USER_PLAN);
};

/**
 * Redirige al login y limpia tokens
 */
export const redirectToLogin = (): void => {
  clearTokens();
  window.location.href = '/login';
};

