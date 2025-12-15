/**
 * Componente de estadísticas de validación por lotes
 */

import { memo } from 'react';
import { StatCard } from './StatCard';
import type { BatchValidationStats } from '../../types/batch-validation.types';

interface BatchStatsProps {
  stats: BatchValidationStats;
}

/**
 * Muestra las estadísticas de validación por lotes
 */
export const BatchStats = memo<BatchStatsProps>(({ stats }) => {
  if (stats.total === 0) {
    return null;
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
      <StatCard
        value={stats.total}
        label="Total"
        valueColor="text-gray-900"
      />
      <StatCard
        value={stats.valid}
        label="Válidos"
        valueColor="text-green-600"
        borderColor="border-l-4 border-green-500"
      />
      <StatCard
        value={stats.invalid}
        label="Inválidos"
        valueColor="text-red-600"
        borderColor="border-l-4 border-red-500"
      />
    </div>
  );
});

BatchStats.displayName = 'BatchStats';