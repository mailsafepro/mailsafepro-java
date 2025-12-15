import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { lazy, Suspense, memo } from 'react';
import { Toaster } from 'react-hot-toast';
import { useAuth } from './contexts/AuthContext';

// Lazy loading de páginas para mejor performance
const LoginPage = lazy(() => import('./pages/LoginPage'));
const RegisterPage = lazy(() => import('./pages/RegisterPage'));
const DashboardLayout = lazy(() => import('./layouts/DashboardLayout'));
const DashboardHome = lazy(() => import('./pages/DashboardHome'));
const APIKeysPage = lazy(() => import('./pages/APIKeysPage'));
const UsagePage = lazy(() => import('./pages/UsagePage'));
const ValidatePage = lazy(() => import('./pages/ValidatePage'));
const BillingPage = lazy(() => import('./pages/BillingPage'));
const ProfilePage = lazy(() => import('./pages/ProfilePage'));
const BillingSuccessPage = lazy(() => import('./pages/BillingSuccessPage'));
const BatchValidationPage = lazy(() => import('./pages/BatchValidationPage'));

/**
 * Loading spinner para Suspense
 */
const LoadingFallback = memo(() => (
  <div className="flex items-center justify-center h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
    <div className="text-center">
      <div 
        className="animate-spin rounded-full h-12 w-12 border-b-4 border-indigo-600 mx-auto mb-4"
        role="status"
        aria-label="Cargando"
      />
      <p className="text-gray-600 font-medium">Cargando...</p>
    </div>
  </div>
));

LoadingFallback.displayName = 'LoadingFallback';

/**
 * Componente de ruta protegida
 */
const ProtectedRoute = memo<{ children: React.ReactElement }>(({ children }) => {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return children;
});

ProtectedRoute.displayName = 'ProtectedRoute';

/**
 * Componente de ruta pública (redirige si ya está autenticado)
 */
const PublicRoute = memo<{ children: React.ReactElement }>(({ children }) => {
  const { isAuthenticated } = useAuth();

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
});

PublicRoute.displayName = 'PublicRoute';

/**
 * Configuración de rutas de la aplicación
 */
const AppRoutes = memo(() => (
  <Routes>
    {/* Rutas públicas */}
    <Route
      path="/login"
      element={
        <PublicRoute>
          <LoginPage />
        </PublicRoute>
      }
    />
    <Route
      path="/register"
      element={
        <PublicRoute>
          <RegisterPage />
        </PublicRoute>
      }
    />

    {/* Ruta de éxito de pago (fuera del layout) */}
    <Route
      path="/dashboard/billing/success"
      element={
        <ProtectedRoute>
          <BillingSuccessPage />
        </ProtectedRoute>
      }
    />

    {/* Rutas del dashboard */}
    <Route
      path="/dashboard"
      element={
        <ProtectedRoute>
          <DashboardLayout />
        </ProtectedRoute>
      }
    >
      <Route index element={<DashboardHome />} />
      <Route path="api-keys" element={<APIKeysPage />} />
      <Route path="usage" element={<UsagePage />} />
      <Route path="validate" element={<ValidatePage />} />
      <Route path="billing" element={<BillingPage />} />
      <Route path="profile" element={<ProfilePage />} />
      <Route path="batch-validation" element={<BatchValidationPage />} />
    </Route>

    {/* Redirección por defecto */}
    <Route path="/" element={<Navigate to="/dashboard" replace />} />
    <Route path="*" element={<Navigate to="/login" replace />} />
  </Routes>
));

AppRoutes.displayName = 'AppRoutes';

/**
 * Componente principal de la aplicación
 * Configura el router y las notificaciones
 */
const App = memo(() => {
  return (
    <Router>
      <Suspense fallback={<LoadingFallback />}>
        <AppRoutes />
      </Suspense>
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#fff',
            color: '#1f2937',
            boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
          },
          success: {
            iconTheme: {
              primary: '#10b981',
              secondary: '#fff',
            },
          },
          error: {
            iconTheme: {
              primary: '#ef4444',
              secondary: '#fff',
            },
          },
        }}
      />
    </Router>
  );
});

App.displayName = 'App';

export default App;
