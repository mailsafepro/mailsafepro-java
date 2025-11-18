import React from 'react';
import { CheckIcon } from '@heroicons/react/24/solid';

interface PlanSelectorProps {
  selectedPlan: string;
  onSelect: (plan: string) => void;
  disabled?: boolean;
}

interface Plan {
  id: string;
  name: string;
  price: string;
  features: string[];
}

const PlanSelector = ({ selectedPlan, onSelect, disabled = false }: PlanSelectorProps) => {
  const PLANS: Plan[] = [
    {
      id: "FREE",
      name: "Plan Gratis",
      price: "€0/mes",
      features: [
        "100 validaciones/mes",
        "Validación básica",
      ],
    },
    {
      id: "PREMIUM",
      name: "Premium",
      price: "€9.99/mes",
      features: [
        "10,000 validaciones/mes",
        "Validación avanzada",
        "Soporte prioritario",
      ],
    },
    {
      id: "ENTERPRISE",
      name: "Empresa",
      price: "Personalizado",
      features: [
        "Validaciones ilimitadas",
        "Dashboard avanzado",
        "Soporte 24/7",
      ],
    },
  ];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {PLANS.map((plan) => (
          <button
            key={plan.id}
            onClick={() => !disabled && onSelect(plan.id)}
            disabled={disabled}
            className={`card p-6 text-left transition-all duration-200 ${
              selectedPlan === plan.id
                ? "ring-2 ring-primary-500 scale-105"
                : "hover:shadow-medium"
            } ${disabled ? "opacity-50 cursor-not-allowed" : ""}`}
          >
            {/* Header */}
            <div className="flex justify-between items-start mb-2">
              <div>
                <h3 className="font-bold text-slate-900">{plan.name}</h3>
                <p className="text-primary-600 font-semibold text-lg mt-1">
                  {plan.price}
                </p>
              </div>
              {selectedPlan === plan.id && (
                <div className="w-5 h-5 bg-primary-500 rounded-full flex items-center justify-center">
                  <CheckIcon className="w-3 h-3 text-white" />
                </div>
              )}
            </div>

            {/* Features */}
            <div className="space-y-2 mt-4 pt-4 border-t border-slate-200">
              {plan.features.map((feature, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  <CheckIcon className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
                  <span className="text-xs text-slate-600">{feature}</span>
                </div>
              ))}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
};

export default PlanSelector;
