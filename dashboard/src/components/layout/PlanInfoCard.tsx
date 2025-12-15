/**
 * Tarjeta con información del plan actual
 */

import { memo } from 'react';
import { getPlanDisplayName } from '../../utils/access.utils';

interface PlanInfoCardProps {
  plan: string;
  nextBillingDate?: string | null;
  isLoading: boolean;
}

/**
 * Muestra información del plan actual y próxima fecha de facturación
 */
export const PlanInfoCard = memo<PlanInfoCardProps>(({ 
  plan, 
  nextBillingDate, 
  isLoading 
}) => {
  const displayName = getPlanDisplayName(plan);

  return (
    <div className="p-6 bg-gradient-to-br from-indigo-50 to-purple-50 border-b border-gray-200">
      {isLoading ? (
        <p className="text-sm text-gray-600">Cargando plan...</p>
      ) : (
        <>
          <p className="text-xs text-gray-600 font-semibold uppercase tracking-wide">
            PLAN ACTUAL
          </p>
          <p className="text-lg font-bold text-gray-900 mt-1">
            {displayName}
          </p>
          {plan !== 'FREE' && nextBillingDate && (
            <p className="text-xs text-gray-600 mt-2">
              Próximo pago: {new Date(nextBillingDate).toLocaleDateString()}
            </p>
          )}
        </>
      )}
    </div>
  );
});

PlanInfoCard.displayName = 'PlanInfoCard';