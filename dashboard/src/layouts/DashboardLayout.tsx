import { useState } from "react";
import { Link, useLocation, Outlet, useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import { useAuth } from "../contexts/AuthContext";
import {
  Bars3Icon,
  XMarkIcon,
  HomeIcon,
  KeyIcon,
  ChartBarIcon,
  EnvelopeIcon,
  CreditCardIcon,
  UserIcon,
  ArrowRightOnRectangleIcon,
  SparklesIcon,
} from "@heroicons/react/24/solid";

const DashboardLayout = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const { userPlan, nextBillingDate, isLoading: authLoading, logout } = useAuth();

  const planNameMap: Record<string, string> = {
    FREE: "Gratis",
    PREMIUM: "Premium",
    ENTERPRISE: "Enterprise",
  };

  const currentPlan = userPlan || sessionStorage.getItem("user_plan") || "FREE";

  const canAccess = (feature: string): boolean => {
    const featureMap: Record<string, string[]> = {
      validate: ["FREE", "PREMIUM", "ENTERPRISE"],
      batch: ["PREMIUM", "ENTERPRISE"],
      "api-keys": ["FREE", "PREMIUM", "ENTERPRISE"],
      usage: ["FREE", "PREMIUM", "ENTERPRISE"],
      billing: ["FREE", "PREMIUM", "ENTERPRISE"],
    };

    return featureMap[feature]?.includes(userPlan) || false;
  };

  const isActive = (path: string) =>
    location.pathname === path
      ? "bg-primary-100 border-r-4 border-primary-600 text-primary-600"
      : "text-slate-600 hover:bg-slate-100";

  const handleLogout = async () => {
    try {
      await logout();
      navigate("/login");
    } catch (error: any) {
      toast.error("Error al cerrar sesión");
    }
  };

  const navItems = [
    { path: "/dashboard", label: "Dashboard", icon: HomeIcon },
    { path: "/dashboard/validate", label: "Validar Email", icon: EnvelopeIcon },
    { path: "/dashboard/batch-validation", label: "Validación Lotes", icon: SparklesIcon, requireFeature: "batch" },
    { path: "/dashboard/api-keys", label: "Claves API", icon: KeyIcon },
    { path: "/dashboard/usage", label: "Uso", icon: ChartBarIcon },
    { path: "/dashboard/billing", label: "Facturación", icon: CreditCardIcon },
    { path: "/dashboard/profile", label: "Perfil", icon: UserIcon },
  ];

  return (
    <div className="flex h-screen bg-slate-100">
      {/* Sidebar */}
      <div
        className={`fixed inset-y-0 left-0 z-40 w-64 bg-white shadow-lg transform transition-transform duration-300 ease-in-out ${
          sidebarOpen ? "translate-x-0" : "-translate-x-full"
        } md:translate-x-0 md:static`}
      >
        <div className="h-full flex flex-col">
          {/* Logo */}
          <div className="p-6 border-b border-slate-200">
            <div className="flex items-center gap-3 mb-2">
              <div className="w-8 h-8 bg-gradient-to-r from-primary-600 to-accent-600 rounded-lg" />
              <h1 className="text-xl font-bold text-slate-900">Email Validator</h1>
            </div>
            <p className="text-xs text-slate-600">API de validación</p>
          </div>

          {/* Plan Info */}
          <div className="p-6 bg-gradient-to-br from-primary-50 to-accent-50 border-b border-slate-200">
            {authLoading ? (
              <p className="text-sm text-slate-600">Cargando plan...</p>
            ) : (
              <>
                <p className="text-xs text-slate-600 font-semibold">PLAN ACTUAL</p>
                <p className="text-lg font-bold text-slate-900 mt-1">
                  {planNameMap[currentPlan] || currentPlan}
                </p>
                {userPlan !== "FREE" && nextBillingDate && (
                  <p className="text-xs text-slate-600 mt-2">
                    Próximo pago: {new Date(nextBillingDate).toLocaleDateString()}
                  </p>
                )}
              </>
            )}
          </div>

          {/* Navigation */}
          <nav className="flex-1 overflow-y-auto p-4 space-y-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              const shouldShow = !item.requireFeature || canAccess(item.requireFeature);

              if (!shouldShow) return null;

              return (
                <Link
                  key={item.path}
                  to={item.path}
                  onClick={() => setSidebarOpen(false)}
                  className={`flex items-center gap-3 px-4 py-3 rounded-lg font-medium transition-all duration-200 ${isActive(item.path)}`}
                >
                  <Icon className="w-5 h-5" />
                  {item.label}
                </Link>
              );
            })}
          </nav>

          {/* Logout Button */}
          <div className="p-4 border-t border-slate-200">
            <button
              onClick={handleLogout}
              className="w-full flex items-center gap-3 px-4 py-3 text-slate-600 hover:bg-red-50 hover:text-red-600 font-medium rounded-lg transition-all duration-200"
            >
              <ArrowRightOnRectangleIcon className="w-5 h-5" />
              Cerrar sesión
            </button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Bar */}
        <div className="bg-white shadow-sm border-b border-slate-200 px-6 py-4 flex justify-between items-center">
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="md:hidden p-2 hover:bg-slate-100 rounded-lg transition-colors"
          >
            {sidebarOpen ? (
              <XMarkIcon className="w-6 h-6 text-slate-600" />
            ) : (
              <Bars3Icon className="w-6 h-6 text-slate-600" />
            )}
          </button>

          <div className="flex-1" />

          {/* User Info */}
          <div className="text-right">
            <p className="text-sm font-medium text-slate-900">
              {sessionStorage.getItem("user_email") || "Usuario"}
            </p>
            <p className="text-xs text-slate-600">{planNameMap[currentPlan]}</p>
          </div>
        </div>

        {/* Page Content */}
        <div className="flex-1 overflow-auto">
          <div className="max-w-7xl mx-auto p-6">
            <Outlet />
          </div>
        </div>
      </div>

      {/* Mobile Overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-30 md:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  );
};

export default DashboardLayout;
