import { useState, useEffect } from "react";
import { useAuth } from "../contexts/AuthContext";
import api from "../services/api";
import toast from "react-hot-toast";
import { ExclamationTriangleIcon } from "@heroicons/react/24/solid";

interface UsageData {
  usage_today: number;
  limit: number;
  remaining: number;
  usage_percentage: number;
  plan: string;
  reset_time: string;
  as_of: string;
}

interface EndpointUsage {
  endpoint: string;
  count: number;
  success: number;
  errors: number;
}

interface DayUsage {
  date: string;
  requests: number;
}

const UsagePage = () => {
  const { userPlan } = useAuth();
  const [usage, setUsage] = useState<UsageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [endpointUsage, setEndpointUsage] = useState<EndpointUsage[]>([]);
  const [dailyUsage, setDailyUsage] = useState<DayUsage[]>([]);

  const fetchUsageData = async () => {
    try {
      setError(null);
      const response = await api.get("/api-keys/usage");
      
      console.log('✅ Uso actualizado:', response.data.usage_today);

      setUsage(response.data);

    } catch (err: any) {
      console.error("Error fetching usage:", err);
      setError(err.response?.data?.detail || "Error al cargar los datos de uso");
    } finally {
      setLoading(false);
    }
  };

  // ✅ IMPORTANTE: useEffect con intervalo de refrescado
  useEffect(() => {
    // Ejecutar inmediatamente
    fetchUsageData();

    // ✅ Refrescar cada 5 segundos (cambiar a 30000 en producción)
    const interval = setInterval(() => {
      console.log("🔄 Refrescando uso del usuario...");
      fetchUsageData();
    }, 5000);

    // Limpiar intervalo cuando se desmonte
    return () => {
      clearInterval(interval);
    };
  }, []);

  if (loading && !usage) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto mb-4"></div>
          <p className="text-slate-600">Cargando datos de uso...</p>
        </div>
      </div>
    );
  }

  if (error && !usage) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-6">
        <div className="flex items-center gap-3">
          <ExclamationTriangleIcon className="w-6 h-6 text-red-600" />
          <div>
            <h3 className="font-semibold text-red-900">Error</h3>
            <p className="text-red-800 text-sm mt-1">{error}</p>
            <p className="text-red-700 text-sm mt-2">
              No se pudieron cargar los datos de uso.
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (!usage) {
    return <div className="text-slate-600">No hay datos de uso disponibles</div>;
  }

  const renewalDate = new Date();
  renewalDate.setDate(renewalDate.getDate() + (30 - renewalDate.getDate()));

  const usagePercentage = usage.usage_percentage;
  const isOverQuota = usagePercentage >= 100;
  const isNearQuota = usagePercentage >= 80;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-slate-900">Monitorea tu consumo de API</h1>
        <p className="text-slate-600 mt-2">Visualiza tu uso actual y límites</p>
      </div>

      {/* Alerts */}
      {isOverQuota && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <ExclamationTriangleIcon className="w-5 h-5 text-red-600" />
            <p className="text-red-800 font-semibold">
              ⚠️ Has superado tu cuota mensual. Actualiza tu plan para continuar usando el servicio.
            </p>
          </div>
        </div>
      )}

      {isNearQuota && !isOverQuota && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <ExclamationTriangleIcon className="w-5 h-5 text-yellow-600" />
            <p className="text-yellow-800 font-semibold">
              ⚠️ Has consumido el {Math.round(usagePercentage)}% de tu cuota mensual.
            </p>
          </div>
        </div>
      )}

      {/* Usage Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        {/* Current Plan */}
        <div className="card p-6 bg-gradient-to-br from-blue-50 to-blue-100 border-blue-200">
          <p className="text-xs text-blue-600 font-semibold uppercase tracking-wide">Plan Actual</p>
          <p className="text-2xl font-bold text-blue-900 mt-3">{usage.plan}</p>
        </div>

        {/* Usage Today */}
        <div className="card p-6 bg-gradient-to-br from-purple-50 to-purple-100 border-purple-200">
          <p className="text-xs text-purple-600 font-semibold uppercase tracking-wide">Usadas Hoy</p>
          <p className="text-2xl font-bold text-purple-900 mt-3">{usage.usage_today}</p>
        </div>

        {/* Monthly Limit */}
        <div className="card p-6 bg-gradient-to-br from-green-50 to-green-100 border-green-200">
          <p className="text-xs text-green-600 font-semibold uppercase tracking-wide">Límite Mensual</p>
          <p className="text-2xl font-bold text-green-900 mt-3">{usage.limit.toLocaleString()}</p>
        </div>

        {/* Remaining */}
        <div className="card p-6 bg-gradient-to-br from-orange-50 to-orange-100 border-orange-200">
          <p className="text-xs text-orange-600 font-semibold uppercase tracking-wide">Disponibles</p>
          <p className="text-2xl font-bold text-orange-900 mt-3">{usage.remaining.toLocaleString()}</p>
        </div>

        {/* Usage Percentage */}
        <div className="card p-6 bg-gradient-to-br from-slate-50 to-slate-100 border-slate-200">
          <p className="text-xs text-slate-600 font-semibold uppercase tracking-wide">Uso</p>
          <p className="text-2xl font-bold text-slate-900 mt-3">{Math.round(usagePercentage)}%</p>
        </div>
      </div>

      {/* Usage Progress Bar */}
      <div className="card p-6">
        <div className="mb-4">
          <div className="flex justify-between items-center mb-2">
            <h3 className="font-semibold text-slate-900">Consumo Mensual</h3>
            <span className="text-sm text-slate-600">
              Renovación: {renewalDate.toLocaleDateString()}
            </span>
          </div>
          <div className="w-full bg-slate-200 rounded-full h-3 overflow-hidden">
            <div
              className={`h-full transition-all duration-300 ${
                isOverQuota
                  ? "bg-red-500"
                  : isNearQuota
                    ? "bg-yellow-500"
                    : "bg-green-500"
              }`}
              style={{ width: `${Math.min(usagePercentage, 100)}%` }}
            ></div>
          </div>
          <div className="flex justify-between mt-2 text-xs text-slate-600">
            <span>{usage.usage_today} solicitudes</span>
            <span>{usage.limit.toLocaleString()} límite</span>
          </div>
        </div>
      </div>

      {/* Endpoint Usage Table */}
      {endpointUsage.length > 0 && (
        <div className="card p-6">
          <h3 className="text-lg font-semibold text-slate-900 mb-4">Uso por Endpoint</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-slate-200 bg-slate-50">
                <tr>
                  <th className="text-left py-3 px-4 font-semibold text-slate-900">Endpoint</th>
                  <th className="text-right py-3 px-4 font-semibold text-slate-900">Solicitudes</th>
                  <th className="text-right py-3 px-4 font-semibold text-slate-900">Exitosas</th>
                  <th className="text-right py-3 px-4 font-semibold text-slate-900">Errores</th>
                </tr>
              </thead>
              <tbody>
                {endpointUsage.map((item, idx) => (
                  <tr key={idx} className="border-b border-slate-100 hover:bg-slate-50">
                    <td className="py-3 px-4 text-slate-700">{item.endpoint}</td>
                    <td className="py-3 px-4 text-right text-slate-700">{item.count}</td>
                    <td className="py-3 px-4 text-right text-green-600">{item.success}</td>
                    <td className="py-3 px-4 text-right text-red-600">{item.errors}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Success Rate */}
      {endpointUsage.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="card p-6">
            <p className="text-sm text-slate-600 font-semibold mb-2">
              {Math.round(
                (endpointUsage.reduce((sum, item) => sum + item.success, 0) /
                  endpointUsage.reduce((sum, item) => sum + item.count, 0)) *
                  100
              )}{" "}
              %
            </p>
            <p className="text-slate-700">Solicitudes Exitosas</p>
          </div>
          <div className="card p-6">
            <p className="text-sm text-slate-600 font-semibold mb-2">
              {Math.round(
                (endpointUsage.reduce((sum, item) => sum + item.errors, 0) /
                  endpointUsage.reduce((sum, item) => sum + item.count, 0)) *
                  100
              )}{" "}
              %
            </p>
            <p className="text-slate-700">Errores</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default UsagePage;
