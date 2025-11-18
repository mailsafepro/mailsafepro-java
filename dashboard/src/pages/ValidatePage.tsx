import { useState } from "react";
import toast from "react-hot-toast";
import api from "../services/api";
import { CheckCircleIcon, XCircleIcon } from "@heroicons/react/24/solid";

interface ValidationResult {
  email: string;
  valid: boolean;
  detail: string;
  risk_score: number;
  quality_score: number;
  provider_analysis?: {
    provider: string;
    reputation: number;
    fingerprint?: string;
  };
  smtp_validation?: {
    checked: boolean;
    mailbox_exists?: boolean | null;
    mx_server?: string;
    detail?: string;
    skip_reason?: string; // ← AGREGADO
  };
  dns_security?: {
    spf?: { status: string; record?: string };
    dkim?: { status: string; selector?: string };
    dmarc?: { status: string; policy?: string };
  };
  processing_time: number;
  metadata?: {
    validation_id: string;
    timestamp: string;
  };
  error_type?: string;
}

const ValidatePage = () => {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ValidationResult | null>(null);
  const [showDetails, setShowDetails] = useState(false);
  const [checkSmtp, setCheckSmtp] = useState(false);
  const [includeRawDns, setIncludeRawDns] = useState(false);

  const handleValidate = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email.trim()) {
      toast.error("Por favor ingresa un email");
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      toast.error("Por favor ingresa un email válido");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const response = await api.post("/validate/email", {
        email: email.trim().toLowerCase(),
        check_smtp: checkSmtp,
        include_raw_dns: includeRawDns,
      });

      setResult(response.data);

      if (response.data.valid) {
        toast.success("Email validado correctamente");
      } else {
        toast.error(`Email no válido: ${response.data.detail}`);
      }
    } catch (err: any) {
      let errorMsg = "Error desconocido en la validación";

      if (err.response?.status === 401) {
        errorMsg = "Sesión expirada. Por favor, inicia sesión de nuevo";
      } else if (err.response?.status === 403) {
        errorMsg = "No tienes permiso para validar emails";
      } else if (err.response?.status === 422) {
        if (err.response?.data?.errors) {
          const firstError = err.response.data.errors[0];
          errorMsg = firstError.message || "Error de validación";
        } else {
          errorMsg = err.response.data.detail || "Error de validación";
        }
      } else if (err.response?.status === 429) {
        errorMsg = "Has alcanzado tu límite diario. Intenta mañana";
      } else if (err.response?.status === 500) {
        errorMsg = "Error del servidor. Por favor intenta más tarde";
      } else if (err.response?.data?.detail) {
        errorMsg = err.response.data.detail;
      } else if (err.message === "Network Error") {
        errorMsg = "Error de conexión. Verifica tu conexión a internet";
      }

      toast.error(errorMsg);
      console.error("Validation error:", err.response?.data || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto space-y-8">
        {/* Header */}
        <div className="text-center">
          <h1 className="text-4xl font-bold tracking-tight text-gray-900">
            Valida un Email
          </h1>
          <p className="mt-4 text-lg text-gray-600">
            Verifica si una dirección de email es válida y segura
          </p>
        </div>

        {/* Formulario */}
        <form
          onSubmit={handleValidate}
          className="bg-white rounded-lg shadow-md p-8 space-y-6"
        >
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700">
              Email a validar
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="ejemplo@email.com"
              className="mt-2 w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none transition"
              disabled={loading}
            />
          </div>

          <div className="space-y-3">
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={checkSmtp}
                onChange={(e) => setCheckSmtp(e.target.checked)}
                disabled={loading}
                className="w-4 h-4 text-indigo-600 rounded"
              />
              <span className="text-sm text-gray-700">
                Verificar buzón de correo (SMTP) <span className="text-xs text-gray-500">(Solo PREMIUM)</span>
              </span>
            </label>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={includeRawDns}
                onChange={(e) => setIncludeRawDns(e.target.checked)}
                disabled={loading}
                className="w-4 h-4 text-indigo-600 rounded"
              />
              <span className="text-sm text-gray-700">
                Incluir registros DNS completos <span className="text-xs text-gray-500">(Solo PREMIUM)</span>
              </span>
            </label>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed transition"
          >
            {loading ? (
              <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
            ) : (
              "Validar Email"
            )}
          </button>
        </form>

        {/* Resultado */}
        {result && (
          <div className="bg-white rounded-lg shadow-md p-8 space-y-6">
            <div
              className={`flex items-center gap-4 p-4 rounded-lg ${
                result.valid
                  ? "bg-green-50 border border-green-200"
                  : "bg-red-50 border border-red-200"
              }`}
            >
              {result.valid ? (
                <CheckCircleIcon className="h-8 w-8 text-green-600 flex-shrink-0" />
              ) : (
                <XCircleIcon className="h-8 w-8 text-red-600 flex-shrink-0" />
              )}
              <div className="flex-1">
                <h3
                  className={`text-lg font-semibold ${
                    result.valid ? "text-green-900" : "text-red-900"
                  }`}
                >
                  {result.valid ? "Email válido" : "Email no válido"}
                </h3>
                <p
                  className={`text-sm ${
                    result.valid ? "text-green-700" : "text-red-700"
                  }`}
                >
                  {result.detail}
                </p>
              </div>
            </div>

            {/* Puntuaciones */}
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-gray-50 rounded-lg p-4">
                <p className="text-sm text-gray-600">Puntuación de riesgo</p>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="text-3xl font-bold text-gray-900">
                    {(result.risk_score * 100).toFixed(0)}%
                  </span>
                  <span
                    className={`text-xs font-medium ${
                      result.risk_score > 0.7
                        ? "text-red-600"
                        : result.risk_score > 0.4
                        ? "text-yellow-600"
                        : "text-green-600"
                    }`}
                  >
                    {result.risk_score > 0.7
                      ? "Alto"
                      : result.risk_score > 0.4
                      ? "Medio"
                      : "Bajo"}
                  </span>
                </div>
              </div>

              <div className="bg-gray-50 rounded-lg p-4">
                <p className="text-sm text-gray-600">Puntuación de calidad</p>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="text-3xl font-bold text-gray-900">
                    {(result.quality_score * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
            </div>

            {/* Proveedor */}
            {result.provider_analysis && (
              <div className="bg-gray-50 rounded-lg p-4 space-y-3">
                <h4 className="font-semibold text-gray-900">Análisis del proveedor</h4>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-gray-600">Proveedor</p>
                    <p className="font-medium text-gray-900">
                      {result.provider_analysis.provider || "Desconocido"}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-600">Reputación</p>
                    <p className="font-medium text-gray-900">
                      {(result.provider_analysis.reputation * 100).toFixed(0)}%
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Validación SMTP */}
            {result.smtp_validation && (
              <div className="bg-gray-50 rounded-lg p-4 space-y-3">
                <h4 className="font-semibold text-gray-900">Validación SMTP</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-600">Verificado:</span>
                    <span className="font-medium">
                      {result.smtp_validation.checked ? "Sí" : "No"}
                    </span>
                  </div>
                  {result.smtp_validation.checked && (
                    <>
                      <div className="flex justify-between">
                        <span className="text-gray-600">Buzón existe:</span>
                        <span
                          className={`font-medium ${
                            result.smtp_validation.mailbox_exists
                              ? "text-green-600"
                              : "text-red-600"
                          }`}
                        >
                          {result.smtp_validation.mailbox_exists === null
                            ? "Desconocido"
                            : result.smtp_validation.mailbox_exists
                            ? "Sí"
                            : "No"}
                        </span>
                      </div>
                      {result.smtp_validation.mx_server && (
                        <div className="flex justify-between">
                          <span className="text-gray-600">Servidor MX:</span>
                          <span className="font-medium">
                            {result.smtp_validation.mx_server}
                          </span>
                        </div>
                      )}
                      {result.smtp_validation.detail && (
                        <p className="text-xs text-gray-500 mt-2">
                          {result.smtp_validation.detail}
                        </p>
                      )}
                    </>
                  )}
                  {!result.smtp_validation.checked &&
                    result.smtp_validation.skip_reason && (
                      <p className="text-xs text-gray-500">
                        {result.smtp_validation.skip_reason}
                      </p>
                    )}
                </div>
              </div>
            )}

            {/* DNS Security */}
            {result.dns_security && (
              <div className="bg-gray-50 rounded-lg p-4 space-y-3">
                <h4 className="font-semibold text-gray-900">Seguridad DNS</h4>
                <div className="grid grid-cols-3 gap-3 text-sm">
                  <div>
                    <p className="text-gray-600">SPF</p>
                    <p
                      className={`font-medium ${
                        result.dns_security.spf?.status === "valid"
                          ? "text-green-600"
                          : "text-red-600"
                      }`}
                    >
                      {result.dns_security.spf?.status || "N/A"}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-600">DKIM</p>
                    <p
                      className={`font-medium ${
                        result.dns_security.dkim?.status === "valid"
                          ? "text-green-600"
                          : "text-red-600"
                      }`}
                    >
                      {result.dns_security.dkim?.status || "N/A"}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-600">DMARC</p>
                    <p
                      className={`font-medium ${
                        result.dns_security.dmarc?.status === "valid"
                          ? "text-green-600"
                          : "text-red-600"
                      }`}
                    >
                      {result.dns_security.dmarc?.status || "N/A"}
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Metadata */}
            <div className="border-t pt-4">
              <p className="text-xs text-gray-500">
                ID: {result.metadata?.validation_id} • Tiempo: {result.processing_time}s
              </p>
            </div>

            {/* Toggle Detalles */}
            <button
              onClick={() => setShowDetails(!showDetails)}
              className="w-full px-4 py-2 text-sm font-medium text-indigo-600 bg-indigo-50 rounded-lg hover:bg-indigo-100 transition"
            >
              {showDetails ? "Ocultar detalles" : "Ver detalles completos"}
            </button>

            {showDetails && (
              <div className="bg-gray-900 rounded-lg p-4 text-gray-100 text-xs overflow-auto max-h-96">
                <pre>{JSON.stringify(result, null, 2)}</pre>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ValidatePage;
