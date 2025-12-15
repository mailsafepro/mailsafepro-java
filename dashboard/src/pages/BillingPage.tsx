// ============================================
// ARCHIVO CORREGIDO: BillingPage.tsx
// ============================================
// Cambios principales: Corregido el tipo del prop 'currentPlan'

import { memo } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useBilling } from '../hooks/useBilling';
import { AVAILABLE_PLANS } from '../constants/plans.constants';
import { PlanCard } from '../components/billing/PlanCard';
import { CurrentPlanBanner } from '../components/billing/CurrentPlanBanner';
import { FAQSection } from '../components/billing/FAQSection';
import type { PlanType } from '../types/billing.types';

/**
 * Encabezado de la página de facturación
 */
const BillingHeader = memo(() => (
  <div>
    <h1 className="text-3xl font-bold text-gray-900">Facturación</h1>
    <p className="text-gray-600 mt-2">Elige el plan que mejor se adapte a ti</p>
  </div>
));

BillingHeader.displayName = 'BillingHeader';

/**
 * Página de facturación para MailSafePro
 * Muestra planes disponibles y permite cambios/upgrades
 */
const BillingPage = () => {
  const { userPlan } = useAuth();
  const { isLoading, selectedPlan, handleUpgrade } = useBilling();

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-6xl mx-auto space-y-6">
        <BillingHeader />

        {/* Current Plan Banner */}
        <CurrentPlanBanner currentPlan={userPlan as PlanType} plans={AVAILABLE_PLANS} />

        {/* Plans Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {AVAILABLE_PLANS.map((plan) => (
            <PlanCard
              key={plan.id}
              plan={plan}
              currentPlan={userPlan as PlanType}
              isLoading={isLoading}
              selectedPlan={selectedPlan}
              onUpgrade={handleUpgrade}
            />
          ))}
        </div>

        {/* FAQ Section */}
        <FAQSection />
      </div>
    </div>
  );
};

export default memo(BillingPage);
