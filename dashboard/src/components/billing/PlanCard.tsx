/**
 * Tarjeta individual de plan
 */

import { memo } from 'react';
import { CheckIcon } from '@heroicons/react/24/solid';
import type { Plan, PlanType } from '../../types/billing.types';

interface PlanCardProps {
  plan: Plan;
  currentPlan: PlanType;
  isLoading: boolean;
  selectedPlan: PlanType | null;
  onUpgrade: (planId: PlanType) => void;
}

/**
 * Muestra una tarjeta de plan con features y botón de acción
 */
export const PlanCard = memo<PlanCardProps>(({
  plan,
  currentPlan,
  isLoading,
  selectedPlan,
  onUpgrade,
}) => {
  const isCurrentPlan = plan.id === currentPlan;
  const isPremium = plan.id !== 'FREE' && plan.id !== currentPlan;
  const isProcessing = isLoading && selectedPlan === plan.id;

  return (
    <div
      className={`bg-white rounded-lg shadow-sm border transition-all duration-300 overflow-hidden ${
        isCurrentPlan
          ? 'ring-2 ring-indigo-500 shadow-lg scale-105'
          : 'hover:shadow-lg border-gray-200'
      }`}
    >
      {/* Featured Badge */}
      {plan.id === 'PREMIUM' && (
        <div className="bg-gradient-to-r from-indigo-600 to-purple-600 text-white text-xs font-bold px-4 py-2 text-center">
          MÁS POPULAR
        </div>
      )}

      {/* Content */}
      <div className="p-6 space-y-4">
        {/* Plan Name & Price */}
        <div>
          <h3 className="text-xl font-bold text-gray-900">{plan.name}</h3>
          <div className="mt-2 flex items-baseline">
            <span className="text-3xl font-bold text-gray-900">
              €{plan.price.toFixed(2)}
            </span>
            <span className="text-gray-600 ml-2">/{plan.billing_period}</span>
          </div>
        </div>

        {/* Features */}
        <div className="space-y-3 py-4 border-t border-b border-gray-200">
          {plan.features.map((feature, idx) => (
            <div key={idx} className="flex items-start gap-3">
              <CheckIcon className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" aria-hidden="true" />
              <span className="text-sm text-gray-700">{feature}</span>
            </div>
          ))}
        </div>

        {/* Action Button */}
        {isCurrentPlan ? (
          <button
            className="w-full py-3 bg-gray-100 text-gray-600 font-semibold rounded-lg cursor-default"
            disabled
          >
            ✓ Plan Actual
          </button>
        ) : (
          <button
            onClick={() => onUpgrade(plan.id)}
            disabled={isProcessing}
            className={`w-full py-3 font-semibold rounded-lg transition-all duration-200 ${
              isPremium
                ? 'text-white bg-indigo-600 hover:bg-indigo-700'
                : 'text-indigo-700 bg-indigo-100 hover:bg-indigo-200'
            } ${
              isProcessing
                ? 'opacity-50 cursor-not-allowed'
                : ''
            } disabled:opacity-50 disabled:cursor-not-allowed`}
          >
            {isProcessing
              ? 'Cargando...'
              : plan.id === 'FREE'
                ? 'Cambiar a Gratis'
                : 'Actualizar'}
          </button>
        )}
      </div>
    </div>
  );
});

PlanCard.displayName = 'PlanCard';
