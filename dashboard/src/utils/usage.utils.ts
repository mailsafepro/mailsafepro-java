/**
 * Utilidades para cálculos de uso
 */

import type { UsageAlertLevel, EndpointUsage } from '../types/usage.types';

/**
 * Determina el nivel de alerta según el porcentaje de uso
 * @param usagePercentage - Porcentaje de uso (0-100+)
 * @returns Nivel de alerta
 */
export const getUsageAlertLevel = (usagePercentage: number): UsageAlertLevel => {
  if (usagePercentage >= 100) return 'over';
  if (usagePercentage >= 80) return 'near';
  return 'normal';
};

/**
 * Obtiene el color de la barra de progreso según el nivel de alerta
 * @param level - Nivel de alerta
 * @returns Clase de color de Tailwind
 */
export const getProgressBarColor = (level: UsageAlertLevel): string => {
  switch (level) {
    case 'over':
      return 'bg-red-500';
    case 'near':
      return 'bg-yellow-500';
    default:
      return 'bg-green-500';
  }
};

/**
 * Calcula la fecha de renovación (fin de mes)
 * @returns Fecha de renovación
 */
export const getRenewalDate = (): Date => {
  const date = new Date();
  const lastDay = new Date(date.getFullYear(), date.getMonth() + 1, 0);
  return lastDay;
};

/**
 * Calcula la tasa de éxito de endpoints
 * @param endpointUsage - Lista de uso por endpoint
 * @returns Porcentaje de éxito (0-100)
 */
export const calculateSuccessRate = (endpointUsage: EndpointUsage[]): number => {
  if (endpointUsage.length === 0) return 0;

  const totalSuccess = endpointUsage.reduce((sum, item) => sum + item.success, 0);
  const totalRequests = endpointUsage.reduce((sum, item) => sum + item.count, 0);

  if (totalRequests === 0) return 0;

  return Math.round((totalSuccess / totalRequests) * 100);
};

/**
 * Calcula la tasa de error de endpoints
 * @param endpointUsage - Lista de uso por endpoint
 * @returns Porcentaje de error (0-100)
 */
export const calculateErrorRate = (endpointUsage: EndpointUsage[]): number => {
  if (endpointUsage.length === 0) return 0;

  const totalErrors = endpointUsage.reduce((sum, item) => sum + item.errors, 0);
  const totalRequests = endpointUsage.reduce((sum, item) => sum + item.count, 0);

  if (totalRequests === 0) return 0;

  return Math.round((totalErrors / totalRequests) * 100);
};

