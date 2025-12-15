/**
 * Componente principal para mostrar resultados de validación
 */

import { memo, useMemo } from 'react';
import { ValidationStatus } from './ValidationStatus';
import { ScoreCard } from './ScoreCard';
import { ProviderAnalysisCard } from './ProviderAnalysisCard';
import { SmtpValidationCard } from './SmtpValidationCard';
import { DnsSecurityCard } from './DnsSecurityCard';
import { getRiskLevel, getRiskColorClass } from '../../utils/risk.utils';
import type { ValidationResult } from '../../types/validation.types';

interface ValidationResultCardProps {
  result: ValidationResult;
  showDetails: boolean;
  onToggleDetails: () => void;
}

/**
 * Muestra todos los resultados de validación de email
 */
export const ValidationResultCard = memo<ValidationResultCardProps>(({
  result,
  showDetails,
  onToggleDetails,
}) => {
  const riskLevel = useMemo(() => getRiskLevel(result.risk_score), [result.risk_score]);
  const riskColorClass = useMemo(() => getRiskColorClass(result.risk_score), [result.risk_score]);

  return (
    <div className="bg-white rounded-lg shadow-md p-8 space-y-6">
      <ValidationStatus valid={result.valid} detail={result.detail} />

      {/* Puntuaciones */}
      <div className="grid grid-cols-2 gap-4">
        <ScoreCard
          title="Puntuación de riesgo"
          score={result.risk_score}
          badge={riskLevel}
          badgeColor={riskColorClass}
        />
        <ScoreCard
          title="Puntuación de calidad"
          score={result.quality_score}
        />
      </div>

      {/* Análisis del proveedor */}
      {result.provider_analysis && (
        <ProviderAnalysisCard analysis={result.provider_analysis} />
      )}

      {/* Validación SMTP */}
      {result.smtp_validation && (
        <SmtpValidationCard validation={result.smtp_validation} />
      )}

      {/* Seguridad DNS */}
      {result.dns_security && (
        <DnsSecurityCard security={result.dns_security} />
      )}

      {/* Metadata */}
      {result.metadata && (
        <div className="border-t pt-4">
          <p className="text-xs text-gray-500">
            ID: {result.metadata.validation_id} • Tiempo: {result.processing_time}s
          </p>
        </div>
      )}

      {/* Toggle Detalles */}
      <button
        onClick={onToggleDetails}
        className="w-full px-4 py-2 text-sm font-medium text-indigo-600 bg-indigo-50 rounded-lg hover:bg-indigo-100 transition"
        type="button"
      >
        {showDetails ? 'Ocultar detalles' : 'Ver detalles completos'}
      </button>

      {/* JSON completo */}
      {showDetails && (
        <div className="bg-gray-900 rounded-lg p-4 text-gray-100 text-xs overflow-auto max-h-96">
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
    </div>
  );
});

ValidationResultCard.displayName = 'ValidationResultCard';