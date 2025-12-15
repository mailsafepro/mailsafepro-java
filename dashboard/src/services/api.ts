/**
 * Configuración y setup de Axios con interceptores
 * Maneja autenticación, refresh tokens y errores
 */

import axios, { AxiosError, AxiosResponse } from 'axios';
import { API_CONFIG } from '../config/api.config';
import {
  getAccessToken,
  getRefreshToken,
  setTokens,
  redirectToLogin,
} from '../utils/token.utils';
import type {
  RefreshTokenResponse,
  QueuedRequest,
  CustomAxiosRequestConfig,
} from '../types/api.types';

/**
 * Instancia de Axios configurada
 */
const api = axios.create({
  baseURL: API_CONFIG.BASE_URL,
  timeout: API_CONFIG.TIMEOUT,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Estado para manejo de refresh token
let isRefreshing = false;
let refreshQueue: QueuedRequest[] = [];

/**
 * Procesa la cola de requests pendientes
 * @param error - Error opcional para rechazar todos
 */
const processQueue = (error: Error | null = null): void => {
  refreshQueue.forEach((promise) => {
    if (error) {
      promise.reject(error);
    } else {
      promise.resolve();
    }
  });

  refreshQueue = [];
};

/**
 * Interceptor de request: Añade token de autorización
 */
api.interceptors.request.use(
  (config: CustomAxiosRequestConfig) => {
    const token = getAccessToken();

    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    return config;
  },
  (error: AxiosError) => {
    console.error('Request interceptor error:', error);
    return Promise.reject(error);
  }
);

/**
 * Interceptor de response: Maneja errores y refresh de tokens
 */
api.interceptors.response.use(
  (response: AxiosResponse) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as CustomAxiosRequestConfig;

    if (!originalRequest) {
      return Promise.reject(error);
    }

    // Error 401: Token expirado
    if (error.response?.status === 401 && !originalRequest._retry) {
      // Prevenir loop infinito en endpoint de refresh
      if (originalRequest.url?.includes(API_CONFIG.REFRESH_ENDPOINT)) {
        console.error('Refresh token inválido o expirado');
        redirectToLogin();
        return Promise.reject(error);
      }

      // Si no hay refresh en progreso, iniciar refresh
      if (!isRefreshing) {
        isRefreshing = true;
        originalRequest._retry = true;

        const refreshToken = getRefreshToken();

        if (!refreshToken) {
          console.error('No refresh token available');
          redirectToLogin();
          return Promise.reject(error);
        }

        try {
          console.log('🔄 Refrescando access token...');

          // Realizar request de refresh
          const response = await axios.post<RefreshTokenResponse>(
            `${API_CONFIG.BASE_URL}${API_CONFIG.REFRESH_ENDPOINT}`,
            { refresh_token: refreshToken }
          );

          const { access_token, refresh_token: new_refresh_token } = response.data;

          // Guardar nuevos tokens
          setTokens(access_token, new_refresh_token);

          // Actualizar headers
          if (api.defaults.headers.common) {
            api.defaults.headers.common.Authorization = `Bearer ${access_token}`;
          }

          if (originalRequest.headers) {
            originalRequest.headers.Authorization = `Bearer ${access_token}`;
          }

          console.log('✅ Token refrescado exitosamente');

          // Procesar cola de requests pendientes
          processQueue();

          // Reintentar request original
          return api(originalRequest);
        } catch (refreshError) {
          console.error('❌ Error al refrescar token:', refreshError);

          // Rechazar todos los requests en cola
          processQueue(refreshError as Error);

          // Redirigir a login
          redirectToLogin();

          return Promise.reject(refreshError);
        } finally {
          isRefreshing = false;
        }
      }

      // Si ya hay refresh en progreso, encolar el request
      return new Promise((resolve, reject) => {
        refreshQueue.push({
          resolve: () => {
            if (originalRequest.headers) {
              const token = getAccessToken();
              if (token) {
                originalRequest.headers.Authorization = `Bearer ${token}`;
              }
            }
            resolve(api(originalRequest));
          },
          reject,
        });
      });
    }

    // Otros errores
    return Promise.reject(error);
  }
);

export default api;


