// src/App.tsx
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "react-hot-toast";
import { useAuth } from "./contexts/AuthContext";
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import DashboardLayout from "./layouts/DashboardLayout";
import DashboardHome from "./pages/DashboardHome";
import APIKeysPage from "./pages/APIKeysPage";
import UsagePage from "./pages/UsagePage";
import ValidatePage from "./pages/ValidatePage";
import BillingPage from "./pages/BillingPage";
import ProfilePage from "./pages/ProfilePage";
import BillingSuccessPage from "./pages/BillingSuccessPage";
import BatchValidationPage from "./pages/BatchValidationPage";

// Componente principal
const AppContent = () => {
  const { isAuthenticated } = useAuth();

  return (
    <Router>
      <Toaster position="top-right" />
      <Routes>
        <Route
          path="/login"
          element={
            isAuthenticated ? <Navigate to="/dashboard" replace /> : <LoginPage />
          }
        />
        <Route
          path="/register"
          element={
            isAuthenticated ? <Navigate to="/dashboard" replace /> : <RegisterPage />
          }
        />
        {/* ✅ CAMBIO AQUÍ */}
        <Route
          path="/dashboard/billing/success"
          element={<BillingSuccessPage />}
        />
        <Route
          path="/dashboard"
          element={
            isAuthenticated ? 
              <DashboardLayout /> : 
              <Navigate to="/login" replace />
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
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </Router>
  );
};

// App que usa el contexto
const App = () => {
  return <AppContent />;
};

export default App;
