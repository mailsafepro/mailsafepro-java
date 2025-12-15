/**
 * Componente para mostrar análisis del proveedor
 */

import { memo } from 'react';
import type { ProviderAnalysis } from '../../types/validation.types';

interface ProviderAnalysisCardProps {
  analysis: ProviderAnalysis;
}

/**
 * Muestra información del proveedor de email
 */
export const ProviderAnalysisCard = memo<ProviderAnalysisCardProps>(({ analysis }) => (
  <div className="bg-gray-50 rounded-lg p-4 space-y-3">
    <h4 className="font-semibold text-gray-900">Análisis del proveedor</h4>
    <div className="grid grid-cols-2 gap-4 text-sm">
      <div>
        <p className="text-gray-600">Proveedor</p>
        <p className="font-medium text-gray-900">
          {analysis.provider || 'Desconocido'}
        </p>
      </div>
      <div>
        <p className="text-gray-600">Reputación</p>
        <p className="font-medium text-gray-900">
          {(analysis.reputation * 100).toFixed(0)}%
        </p>
      </div>
    </div>
  </div>
));

ProviderAnalysisCard.displayName = 'ProviderAnalysisCard';