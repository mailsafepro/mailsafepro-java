/**
 * Banner que muestra el plan actual
 */

import { memo } from 'react';
import type { Plan, PlanType } from '../../types/billing.types';

interface CurrentPlanBannerProps {
  currentPlan: PlanType;
  plans: Plan[];
}

/**
 * Muestra el plan actual del usuario
 */
export const CurrentPlanBanner = memo<CurrentPlanBannerProps>(({ currentPlan, plans }) => {
  if (!currentPlan || currentPlan === 'FREE') {
    return null;
  }

  const plan = plans.find((p) => p.id === currentPlan);

  if (!plan) {
    return null;
  }

  return (
    <div className="bg-gradient-to-r from-green-50 to-emerald-50 border border-green-200 rounded-lg p-6">
      <p className="text-sm text-gray-600 font-semibold">PLAN ACTUAL</p>
      <p className="text-2xl font-bold text-gray-900 mt-1">
        {plan.name}
      </p>
      <p className="text-gray-600 mt-2 text-sm">
        Tu próximo período de facturación comenzará el próximo mes.
      </p>
    </div>
  );
});

CurrentPlanBanner.displayName = 'CurrentPlanBanner';