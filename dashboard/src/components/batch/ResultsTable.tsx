/**
 * Componente de tabla de resultados
 */

import { memo } from 'react';
import { CheckCircleIcon, XCircleIcon } from '@heroicons/react/24/solid';
import type { BatchValidationResult } from '../../types/batch-validation.types';

interface ResultsTableProps {
  results: BatchValidationResult[];
}

/**
 * Tabla que muestra los resultados de validación por lotes
 */
export const ResultsTable = memo<ResultsTableProps>(({ results }) => {
  if (results.length === 0) {
    return null;
  }

  return (
    <div className="bg-white rounded-lg shadow-md overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              <th className="px-6 py-3 text-left font-semibold text-gray-900">
                Email
              </th>
              <th className="px-6 py-3 text-left font-semibold text-gray-900">
                Estado
              </th>
              <th className="px-6 py-3 text-left font-semibold text-gray-900">
                Tiempo (ms)
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {results.map((result, idx) => (
              <tr 
                key={`${result.email}-${idx}`} 
                className="hover:bg-gray-50 transition-colors"
              >
                <td className="px-6 py-3 text-gray-900 font-mono text-xs">
                  {result.email}
                </td>
                <td className="px-6 py-3">
                  {result.valid ? (
                    <div className="flex items-center gap-2 text-green-600">
                      <CheckCircleIcon className="w-5 h-5 flex-shrink-0" aria-hidden="true" />
                      <span className="font-medium">Válido</span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2 text-red-600">
                      <XCircleIcon className="w-5 h-5 flex-shrink-0" aria-hidden="true" />
                      <span className="font-medium">Inválido</span>
                    </div>
                  )}
                </td>
                <td className="px-6 py-3 text-gray-600">
                  {result.processing_time.toFixed(2)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
});

ResultsTable.displayName = 'ResultsTable';