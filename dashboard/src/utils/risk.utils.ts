/**
 * Utilidades para análisis de riesgo
 */

import type { RiskLevel } from '../types/validation.types';

/**
 * Determina el nivel de riesgo basado en el score
 * @param riskScore - Score de riesgo entre 0 y 1
 * @returns Nivel de riesgo clasificado
 */
export const getRiskLevel = (riskScore: number): RiskLevel => {
  if (riskScore > 0.7) return 'Alto';
  if (riskScore > 0.4) return 'Medio';
  return 'Bajo';
};

/**
 * Obtiene el color de riesgo para UI
 * @param riskScore - Score de riesgo entre 0 y 1
 * @returns Clase de color de Tailwind
 */
export const getRiskColorClass = (riskScore: number): string => {
  if (riskScore > 0.7) return 'text-red-600';
  if (riskScore > 0.4) return 'text-yellow-600';
  return 'text-green-600';
};

/**
 * Obtiene el color para status de DNS
 * @param status - Status del registro DNS
 * @returns Clase de color de Tailwind
 */
export const getDnsStatusColor = (status?: string): string => {
  return status === 'valid' ? 'text-green-600' : 'text-red-600';
};