/**
 * Componente que muestra el estado de validación
 */

import { memo } from 'react';
import { CheckCircleIcon, XCircleIcon } from '@heroicons/react/24/solid';

interface ValidationStatusProps {
  valid: boolean;
  detail: string;
}

/**
 * Muestra el resultado de validación con icono y mensaje
 */
export const ValidationStatus = memo<ValidationStatusProps>(({ valid, detail }) => (
  <div
    className={`flex items-center gap-4 p-4 rounded-lg ${
      valid
        ? 'bg-green-50 border border-green-200'
        : 'bg-red-50 border border-red-200'
    }`}
  >
    {valid ? (
      <CheckCircleIcon className="h-8 w-8 text-green-600 flex-shrink-0" aria-hidden="true" />
    ) : (
      <XCircleIcon className="h-8 w-8 text-red-600 flex-shrink-0" aria-hidden="true" />
    )}
    <div className="flex-1">
      <h3
        className={`text-lg font-semibold ${
          valid ? 'text-green-900' : 'text-red-900'
        }`}
      >
        {valid ? 'Email válido' : 'Email no válido'}
      </h3>
      <p
        className={`text-sm ${
          valid ? 'text-green-700' : 'text-red-700'
        }`}
      >
        {detail}
      </p>
    </div>
  </div>
));

ValidationStatus.displayName = 'ValidationStatus';