/**
 * Estadísticas de éxito y error
 */

import { memo } from 'react';
import { calculateSuccessRate, calculateErrorRate } from '../../utils/usage.utils';
import type { EndpointUsage } from '../../types/usage.types';

interface UsageStatsProps {
  endpointUsage: EndpointUsage[];
}

/**
 * Muestra estadísticas de tasa de éxito y error
 */
export const UsageStats = memo<UsageStatsProps>(({ endpointUsage }) => {
  if (endpointUsage.length === 0) {
    return null;
  }

  const successRate = calculateSuccessRate(endpointUsage);
  const errorRate = calculateErrorRate(endpointUsage);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
        <p className="text-sm text-gray-600 font-semibold mb-2">
          {successRate}%
        </p>
        <p className="text-gray-700">Solicitudes Exitosas</p>
      </div>
      <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
        <p className="text-sm text-gray-600 font-semibold mb-2">
          {errorRate}%
        </p>
        <p className="text-gray-700">Errores</p>
      </div>
    </div>
  );
});

UsageStats.displayName = 'UsageStats';

