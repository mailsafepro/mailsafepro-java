/**
 * Tipos relacionados con el layout del dashboard
 */

import type { ComponentType } from 'react';

export interface NavItem {
  path: string;
  label: string;
  icon: ComponentType<{ className?: string }>;
  requireFeature?: string;
}

export interface PlanInfo {
  plan: string;
  displayName: string;
  nextBillingDate?: string | null;
}
