/**
 * Logo del sidebar
 */

import { memo } from 'react';

/**
 * Muestra el logo y nombre de la aplicación
 */
export const SidebarLogo = memo(() => (
  <div className="p-6 border-b border-gray-200">
    <div className="flex items-center gap-3 mb-2">
      <div className="w-8 h-8 bg-gradient-to-r from-indigo-600 to-purple-600 rounded-lg" aria-hidden="true" />
      <h1 className="text-xl font-bold text-gray-900">MailSafePro</h1>
    </div>
    <p className="text-xs text-gray-600">API de validación</p>
  </div>
));

SidebarLogo.displayName = 'SidebarLogo';