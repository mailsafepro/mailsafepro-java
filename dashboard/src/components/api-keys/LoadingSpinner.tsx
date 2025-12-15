/**
 * Spinner de carga para lista de API Keys
 */

import { memo } from 'react';

/**
 * Muestra un spinner de carga centrado
 */
export const LoadingSpinner = memo(() => (
  <div className="text-center py-8">
    <div 
      className="inline-flex items-center justify-center w-8 h-8 border-4 border-indigo-200 border-t-indigo-600 rounded-full animate-spin"
      role="status"
      aria-label="Cargando"
    />
  </div>
));

LoadingSpinner.displayName = 'LoadingSpinner';
