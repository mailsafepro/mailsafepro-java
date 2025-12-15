import { memo } from 'react';
import { useDashboard } from '../hooks/useDashboard';
import { FeatureCard } from '../components/dashboard/FeatureCard';
import { UpgradeBanner } from '../components/dashboard/UpgradeBanner';

/**
 * Encabezado del dashboard
 */
const DashboardHeader = memo(() => (
  <div>
    <h1 className="text-4xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
      Bienvenido al Dashboard
    </h1>
    <p className="text-gray-600 mt-2 text-lg">
      Accede a todas las herramientas para validar emails
    </p>
  </div>
));

DashboardHeader.displayName = 'DashboardHeader';

/**
 * Página principal del dashboard de MailSafePro
 * Muestra todas las features disponibles y accesos rápidos
 */
const DashboardHome = () => {
  const { features, isFreePlan } = useDashboard();

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto space-y-8">
        <DashboardHeader />

        {/* Upgrade Banner para usuarios FREE */}
        {isFreePlan && <UpgradeBanner />}

        {/* Features Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature) => (
            <FeatureCard key={feature.path} feature={feature} />
          ))}
        </div>
      </div>
    </div>
  );
};

export default memo(DashboardHome);
