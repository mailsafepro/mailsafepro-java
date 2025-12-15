/**
 * Estado de error para página de uso
 */

import { memo } from 'react';
import { ExclamationTriangleIcon } from '@heroicons/react/24/solid';

interface ErrorStateProps {
  error: string;
}

/**
 * Muestra un mensaje de error
 */
export const ErrorState = memo<ErrorStateProps>(({ error }) => (
  <div className="bg-red-50 border border-red-200 rounded-lg p-6">
    <div className="flex items-center gap-3">
      <ExclamationTriangleIcon className="w-6 h-6 text-red-600 flex-shrink-0" aria-hidden="true" />
      <div>
        <h3 className="font-semibold text-red-900">Error</h3>
        <p className="text-red-800 text-sm mt-1">{error}</p>
        <p className="text-red-700 text-sm mt-2">
          No se pudieron cargar los datos de uso.
        </p>
      </div>
    </div>
  </div>
));

ErrorState.displayName = 'ErrorState';
