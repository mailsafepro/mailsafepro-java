import { memo, useCallback } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { useAuth } from '../contexts/AuthContext';
import { useSidebar } from '../hooks/useSidebar';
import { Sidebar } from '../components/layout/Sidebar';
import { TopBar } from '../components/layout/TopBar';
import { MobileOverlay } from '../components/layout/MobileOverlay';

/**
 * Layout principal del dashboard de MailSafePro
 * Incluye sidebar con navegación, topbar y área de contenido
 */
const DashboardLayout = memo(() => {
  const navigate = useNavigate();
  const { isOpen, close, toggle } = useSidebar();
  const { 
    userEmail, 
    userPlan, 
    nextBillingDate, 
    isLoading, 
    logout 
  } = useAuth();

  // Fallback al plan almacenado en sesión
  const currentPlan = userPlan || sessionStorage.getItem('user_plan') || 'FREE';

  /**
   * Maneja el logout del usuario
   */
  const handleLogout = useCallback(async () => {
    try {
      await logout();
      toast.success('Sesión cerrada correctamente');
      navigate('/login');
    } catch (error) {
      console.error('Error al cerrar sesión:', error);
      toast.error('Error al cerrar sesión');
    }
  }, [logout, navigate]);

  return (
    <div className="flex h-screen bg-gray-100">
      {/* Sidebar */}
      <Sidebar
        isOpen={isOpen}
        userPlan={currentPlan}
        nextBillingDate={nextBillingDate}
        isLoading={isLoading}
        onClose={close}
        onLogout={handleLogout}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Bar */}
        <TopBar
          sidebarOpen={isOpen}
          userEmail={userEmail}
          userPlan={currentPlan}
          onToggleSidebar={toggle}
        />

        {/* Page Content */}
        <main className="flex-1 overflow-auto">
          <div className="max-w-7xl mx-auto p-6">
            <Outlet />
          </div>
        </main>
      </div>

      {/* Mobile Overlay */}
      <MobileOverlay isVisible={isOpen} onClose={close} />
    </div>
  );
});

DashboardLayout.displayName = 'DashboardLayout';

export default DashboardLayout;
