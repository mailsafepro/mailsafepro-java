/**
 * Tipos relacionados con la API y requests
 */

import type { AxiosError, InternalAxiosRequestConfig } from 'axios';

export interface RefreshTokenResponse {
  access_token: string;
  refresh_token: string;
}

export interface QueuedRequest {
  resolve: (value?: unknown) => void;
  reject: (reason?: unknown) => void;
}

export interface CustomAxiosRequestConfig extends InternalAxiosRequestConfig {
  _retry?: boolean;
}

export type ApiError = AxiosError;