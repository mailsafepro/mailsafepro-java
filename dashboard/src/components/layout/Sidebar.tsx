/**
 * Sidebar completo del dashboard
 */

import { memo } from 'react';
import { SidebarLogo } from './SidebarLogo';
import { PlanInfoCard } from './PlanInfoCard';
import { Navigation } from './Navigation';
import { LogoutButton } from './LogoutButton';

interface SidebarProps {
  isOpen: boolean;
  userPlan: string;
  nextBillingDate?: string | null;
  isLoading: boolean;
  onClose: () => void;
  onLogout: () => void;
}

/**
 * Sidebar del dashboard con navegación y info del usuario
 */
export const Sidebar = memo<SidebarProps>(({ 
  isOpen, 
  userPlan, 
  nextBillingDate, 
  isLoading, 
  onClose, 
  onLogout 
}) => (
  <div
    className={`fixed inset-y-0 left-0 z-40 w-64 bg-white shadow-lg transform transition-transform duration-300 ease-in-out ${
      isOpen ? 'translate-x-0' : '-translate-x-full'
    } md:translate-x-0 md:static`}
  >
    <div className="h-full flex flex-col">
      <SidebarLogo />
      <PlanInfoCard 
        plan={userPlan} 
        nextBillingDate={nextBillingDate} 
        isLoading={isLoading} 
      />
      <Navigation userPlan={userPlan} onNavigate={onClose} />
      <LogoutButton onLogout={onLogout} />
    </div>
  </div>
));

Sidebar.displayName = 'Sidebar';
