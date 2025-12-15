/**
 * Estado de carga para página de uso
 */

import { memo } from 'react';

/**
 * Muestra un spinner de carga centrado
 */
export const LoadingState = memo(() => (
  <div className="flex items-center justify-center h-96">
    <div className="text-center">
      <div 
        className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500 mx-auto mb-4"
        role="status"
        aria-label="Cargando"
      />
      <p className="text-gray-600">Cargando datos de uso...</p>
    </div>
  </div>
));

LoadingState.displayName = 'LoadingState';