/**
 * Barra superior del dashboard
 */

import { memo } from 'react';
import { Bars3Icon, XMarkIcon } from '@heroicons/react/24/solid';
import { getPlanDisplayName } from '../../utils/access.utils';

interface TopBarProps {
  sidebarOpen: boolean;
  userEmail: string | null;
  userPlan: string;
  onToggleSidebar: () => void;
}

/**
 * Barra superior con toggle de sidebar y info del usuario
 */
export const TopBar = memo<TopBarProps>(({ 
  sidebarOpen, 
  userEmail, 
  userPlan, 
  onToggleSidebar 
}) => {
  const planDisplayName = getPlanDisplayName(userPlan);

  return (
    <div className="bg-white shadow-sm border-b border-gray-200 px-6 py-4 flex justify-between items-center">
      <button
        onClick={onToggleSidebar}
        className="md:hidden p-2 hover:bg-gray-100 rounded-lg transition-colors"
        aria-label={sidebarOpen ? 'Cerrar menú' : 'Abrir menú'}
      >
        {sidebarOpen ? (
          <XMarkIcon className="w-6 h-6 text-gray-600" aria-hidden="true" />
        ) : (
          <Bars3Icon className="w-6 h-6 text-gray-600" aria-hidden="true" />
        )}
      </button>

      <div className="flex-1" />

      {/* User Info */}
      <div className="text-right">
        <p className="text-sm font-medium text-gray-900">
          {userEmail || 'Usuario'}
        </p>
        <p className="text-xs text-gray-600">{planDisplayName}</p>
      </div>
    </div>
  );
});

TopBar.displayName = 'TopBar';
