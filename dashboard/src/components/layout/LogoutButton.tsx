/**
 * Botón de cerrar sesión
 */

import { memo } from 'react';
import { ArrowRightOnRectangleIcon } from '@heroicons/react/24/solid';

interface LogoutButtonProps {
  onLogout: () => void;
}

/**
 * Botón para cerrar sesión
 */
export const LogoutButton = memo<LogoutButtonProps>(({ onLogout }) => (
  <div className="p-4 border-t border-gray-200">
    <button
      onClick={onLogout}
      className="w-full flex items-center gap-3 px-4 py-3 text-gray-600 hover:bg-red-50 hover:text-red-600 font-medium rounded-lg transition-all duration-200"
    >
      <ArrowRightOnRectangleIcon className="w-5 h-5" aria-hidden="true" />
      Cerrar sesión
    </button>
  </div>
));

LogoutButton.displayName = 'LogoutButton';

