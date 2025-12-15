/**
 * Link de navegación individual
 */

import { memo } from 'react';
import { Link, useLocation } from 'react-router-dom';
import type { NavItem } from '../../types/layout.types';

interface NavLinkProps {
  item: NavItem;
  onClose: () => void;
}

/**
 * Link de navegación con indicador de activo
 */
export const NavLink = memo<NavLinkProps>(({ item, onClose }) => {
  const location = useLocation();
  const Icon = item.icon;
  const isActive = location.pathname === item.path;

  return (
    <Link
      to={item.path}
      onClick={onClose}
      className={`flex items-center gap-3 px-4 py-3 rounded-lg font-medium transition-all duration-200 ${
        isActive
          ? 'bg-indigo-100 border-r-4 border-indigo-600 text-indigo-600'
          : 'text-gray-600 hover:bg-gray-100'
      }`}
    >
      <Icon className="w-5 h-5" aria-hidden="true" />
      {item.label}
    </Link>
  );
});

NavLink.displayName = 'NavLink';

