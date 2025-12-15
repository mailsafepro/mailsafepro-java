/**
 * Tipos relacionados con el dashboard
 */

import type { ComponentType } from 'react';

export interface DashboardFeature {
  title: string;
  description: string;
  icon: ComponentType<{ className?: string }>;
  path: string;
  available: boolean;
  requiresPremium?: boolean;
}

export interface DashboardStats {
  validationsToday: number;
  apiKeysCount: number;
  currentPlan: string;
}