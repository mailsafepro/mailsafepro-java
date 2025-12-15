/**
 * Barra de progreso de consumo mensual
 */

import { memo } from 'react';
import { getProgressBarColor, getRenewalDate } from '../../utils/usage.utils';
import type { UsageAlertLevel } from '../../types/usage.types';

interface UsageProgressBarProps {
  usageToday: number;
  limit: number;
  usagePercentage: number;
  alertLevel: UsageAlertLevel;
}

/**
 * Muestra el progreso del consumo mensual
 */
export const UsageProgressBar = memo<UsageProgressBarProps>(({
  usageToday,
  limit,
  usagePercentage,
  alertLevel,
}) => {
  const renewalDate = getRenewalDate();
  const progressColor = getProgressBarColor(alertLevel);

  return (
    <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
      <div className="mb-4">
        <div className="flex justify-between items-center mb-2">
          <h3 className="font-semibold text-gray-900">Consumo Mensual</h3>
          <span className="text-sm text-gray-600">
            Renovación: {renewalDate.toLocaleDateString()}
          </span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
          <div
            className={`h-full transition-all duration-300 ${progressColor}`}
            style={{ width: `${Math.min(usagePercentage, 100)}%` }}
            role="progressbar"
            aria-valuenow={Math.min(usagePercentage, 100)}
            aria-valuemin={0}
            aria-valuemax={100}
          />
        </div>
        <div className="flex justify-between mt-2 text-xs text-gray-600">
          <span>{usageToday.toLocaleString()} solicitudes</span>
          <span>{limit.toLocaleString()} límite</span>
        </div>
      </div>
    </div>
  );
});

UsageProgressBar.displayName = 'UsageProgressBar';