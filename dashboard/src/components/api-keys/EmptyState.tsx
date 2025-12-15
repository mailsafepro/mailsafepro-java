/**
 * Estado vacío cuando no hay API Keys
 */

import { memo } from 'react';
import { KeyIcon } from '@heroicons/react/24/solid';

/**
 * Muestra un mensaje cuando no hay API Keys
 */
export const EmptyState = memo(() => (
  <div className="bg-white rounded-lg shadow-sm p-8 text-center border border-gray-200">
    <KeyIcon className="w-12 h-12 text-gray-300 mx-auto mb-4" aria-hidden="true" />
    <p className="text-lg font-semibold text-gray-900">
      No tienes claves API
    </p>
    <p className="text-gray-600 mt-1">
      Crea tu primera clave API para empezar a usar el servicio.
    </p>
  </div>
));

EmptyState.displayName = 'EmptyState';