/**
 * Cliente de API con métodos helper tipados
 * Uso opcional para requests más limpios
 */

import api from './api';
import type { AxiosRequestConfig, AxiosResponse } from 'axios';

/**
 * Cliente de API con métodos helper
 */
export class ApiClient {
  /**
   * Realiza un GET request
   */
  static async get<T = unknown>(
    url: string,
    config?: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    return api.get<T>(url, config);
  }

  /**
   * Realiza un POST request
   */
  static async post<T = unknown>(
    url: string,
    data?: unknown,
    config?: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    return api.post<T>(url, data, config);
  }

  /**
   * Realiza un PUT request
   */
  static async put<T = unknown>(
    url: string,
    data?: unknown,
    config?: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    return api.put<T>(url, data, config);
  }

  /**
   * Realiza un PATCH request
   */
  static async patch<T = unknown>(
    url: string,
    data?: unknown,
    config?: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    return api.patch<T>(url, data, config);
  }

  /**
   * Realiza un DELETE request
   */
  static async delete<T = unknown>(
    url: string,
    config?: AxiosRequestConfig
  ): Promise<AxiosResponse<T>> {
    return api.delete<T>(url, config);
  }
}

// Exportar también la instancia de axios por defecto para compatibilidad
export { api };
export default api;
