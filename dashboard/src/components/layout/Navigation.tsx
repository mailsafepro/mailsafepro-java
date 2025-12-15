/**
 * Navegación del sidebar
 */

import { memo } from 'react';
import { NavLink } from './NavLink';
import { canAccessFeature } from '../../utils/access.utils';
import { NAV_ITEMS } from '../../constants/navigation.constants';

interface NavigationProps {
  userPlan: string;
  onNavigate: () => void;
}

/**
 * Lista de navegación con control de acceso por plan
 */
export const Navigation = memo<NavigationProps>(({ userPlan, onNavigate }) => (
  <nav className="flex-1 overflow-y-auto p-4 space-y-2">
    {NAV_ITEMS.map((item) => {
      const shouldShow = !item.requireFeature || canAccessFeature(item.requireFeature, userPlan);

      if (!shouldShow) {
        return null;
      }

      return (
        <NavLink 
          key={item.path} 
          item={item} 
          onClose={onNavigate} 
        />
      );
    })}
  </nav>
));

Navigation.displayName = 'Navigation';

