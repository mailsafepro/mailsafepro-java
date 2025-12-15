/**
 * Configuración de la API
 */

export const API_CONFIG = {
    BASE_URL: import.meta.env.VITE_API_BASE_URL,
    TIMEOUT: 30000, // 30 segundos
    REFRESH_ENDPOINT: '/auth/refresh',
  } as const;
  
  export const TOKEN_STORAGE_KEYS = {
    ACCESS_TOKEN: 'token',
    REFRESH_TOKEN: 'refresh_token',
    USER_EMAIL: 'user_email',
    USER_PLAN: 'user_plan',
  } as const;