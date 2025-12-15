/**
 * Custom hook para el dashboard
 */

import { useMemo } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { getDashboardFeatures } from '../constants/dashboard.constants';
import type { DashboardFeature } from '../types/dashboard.types';

interface UseDashboardReturn {
  userPlan: string;
  features: DashboardFeature[];
  isFreePlan: boolean;
}

/**
 * Hook personalizado para gestionar el estado del dashboard
 * @returns Estado y datos para el dashboard
 */
export const useDashboard = (): UseDashboardReturn => {
  const { userPlan } = useAuth();

  const features = useMemo(() => {
    return getDashboardFeatures(userPlan);
  }, [userPlan]);

  const isFreePlan = useMemo(() => {
    return userPlan === 'FREE';
  }, [userPlan]);

  return {
    userPlan,
    features,
    isFreePlan,
  };
};
