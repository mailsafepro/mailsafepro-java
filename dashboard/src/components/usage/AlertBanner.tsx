/**
 * Banner de alerta para cuota de uso
 */

import { memo } from 'react';
import { ExclamationTriangleIcon } from '@heroicons/react/24/solid';
import type { UsageAlertLevel } from '../../types/usage.types';

interface AlertBannerProps {
  level: UsageAlertLevel;
  usagePercentage: number;
}

/**
 * Muestra alertas cuando el uso se acerca o supera la cuota
 */
export const AlertBanner = memo<AlertBannerProps>(({ level, usagePercentage }) => {
  if (level === 'normal') {
    return null;
  }

  const isOverQuota = level === 'over';

  return (
    <div
      className={`rounded-lg p-4 border ${
        isOverQuota
          ? 'bg-red-50 border-red-200'
          : 'bg-yellow-50 border-yellow-200'
      }`}
      role="alert"
    >
      <div className="flex items-center gap-3">
        <ExclamationTriangleIcon
          className={`w-5 h-5 flex-shrink-0 ${
            isOverQuota ? 'text-red-600' : 'text-yellow-600'
          }`}
          aria-hidden="true"
        />
        <p
          className={`font-semibold ${
            isOverQuota ? 'text-red-800' : 'text-yellow-800'
          }`}
        >
          {isOverQuota
            ? '⚠️ Has superado tu cuota mensual. Actualiza tu plan para continuar usando el servicio.'
            : `⚠️ Has consumido el ${Math.round(usagePercentage)}% de tu cuota mensual.`}
        </p>
      </div>
    </div>
  );
});

AlertBanner.displayName = 'AlertBanner';