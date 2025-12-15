import { memo, useMemo } from 'react';
import { useUsageData } from '../hooks/useUsageData';
import { getUsageAlertLevel } from '../utils/usage.utils';
import { AlertBanner } from '../components/usage/AlertBanner';
import { UsageCard } from '../components/usage/UsageCard';
import { UsageProgressBar } from '../components/usage/UsageProgressBar';
import { EndpointUsageTable } from '../components/usage/EndpointUsageTable';
import { UsageStats } from '../components/usage/UsageStats';
import { LoadingState } from '../components/usage/LoadingState';
import { ErrorState } from '../components/usage/ErrorState';

/**
 * Encabezado de la página de uso
 */
const UsageHeader = memo(() => (
  <div>
    <h1 className="text-3xl font-bold text-gray-900">
      Monitorea tu consumo de API
    </h1>
    <p className="text-gray-600 mt-2">
      Visualiza tu uso actual y límites
    </p>
  </div>
));

UsageHeader.displayName = 'UsageHeader';

/**
 * Página de monitoreo de uso de API para MailSafePro
 * Muestra consumo actual, límites y estadísticas con polling automático
 */
const UsagePage = () => {
  const {
    usage,
    endpointUsage,
    isLoading,
    error,
  } = useUsageData(true);

  // Calcular nivel de alerta
  const alertLevel = useMemo(() => {
    if (!usage) return 'normal';
    return getUsageAlertLevel(usage.usage_percentage);
  }, [usage]);

  // Estados de carga y error
  if (isLoading && !usage) {
    return <LoadingState />;
  }

  if (error && !usage) {
    return <ErrorState error={error} />;
  }

  if (!usage) {
    return (
      <div className="text-gray-600">
        No hay datos de uso disponibles
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-6xl mx-auto space-y-6">
        <UsageHeader />

        {/* Alertas */}
        <AlertBanner
          level={alertLevel}
          usagePercentage={usage.usage_percentage}
        />

        {/* Tarjetas de métricas */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <UsageCard
            label="Plan Actual"
            value={usage.plan}
            gradient="bg-gradient-to-br from-blue-50 to-blue-100 border-blue-200"
            textColor="text-blue-900"
            labelColor="text-blue-600"
          />
          <UsageCard
            label="Usadas Hoy"
            value={usage.usage_today.toLocaleString()}
            gradient="bg-gradient-to-br from-purple-50 to-purple-100 border-purple-200"
            textColor="text-purple-900"
            labelColor="text-purple-600"
          />
          <UsageCard
            label="Límite Mensual"
            value={usage.limit.toLocaleString()}
            gradient="bg-gradient-to-br from-green-50 to-green-100 border-green-200"
            textColor="text-green-900"
            labelColor="text-green-600"
          />
          <UsageCard
            label="Disponibles"
            value={usage.remaining.toLocaleString()}
            gradient="bg-gradient-to-br from-orange-50 to-orange-100 border-orange-200"
            textColor="text-orange-900"
            labelColor="text-orange-600"
          />
          <UsageCard
            label="Uso"
            value={`${Math.round(usage.usage_percentage)}%`}
            gradient="bg-gradient-to-br from-gray-50 to-gray-100 border-gray-200"
            textColor="text-gray-900"
            labelColor="text-gray-600"
          />
        </div>

        {/* Barra de progreso */}
        <UsageProgressBar
          usageToday={usage.usage_today}
          limit={usage.limit}
          usagePercentage={usage.usage_percentage}
          alertLevel={alertLevel}
        />

        {/* Tabla de uso por endpoint */}
        <EndpointUsageTable endpointUsage={endpointUsage} />

        {/* Estadísticas de éxito/error */}
        <UsageStats endpointUsage={endpointUsage} />
      </div>
    </div>
  );
};

export default memo(UsagePage);
