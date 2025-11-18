import { Link } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { ArrowRightIcon, EnvelopeIcon, KeyIcon, ChartBarIcon, CreditCardIcon } from "@heroicons/react/24/solid";

const DashboardHome = () => {
  const { userPlan } = useAuth();

  const features = [
    {
      title: "Validar Email",
      description: "Verifica si un email es válido en tiempo real",
      icon: EnvelopeIcon,
      path: "/dashboard/validate",
      available: true,
    },
    {
      title: "Validación Lotes",
      description: "Valida múltiples emails a la vez",
      icon: EnvelopeIcon,
      path: "/dashboard/batch-validation",
      available: userPlan !== "FREE",
    },
    {
      title: "Claves API",
      description: "Gestiona tus claves de autenticación",
      icon: KeyIcon,
      path: "/dashboard/api-keys",
      available: true,
    },
    {
      title: "Estadísticas",
      description: "Monitorea tu consumo de API",
      icon: ChartBarIcon,
      path: "/dashboard/usage",
      available: true,
    },
    {
      title: "Facturación",
      description: "Gestiona tu suscripción",
      icon: CreditCardIcon,
      path: "/dashboard/billing",
      available: true,
    },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-4xl font-bold gradient-text">Bienvenido al Dashboard</h1>
        <p className="text-slate-600 mt-2 text-lg">
          Accede a todas las herramientas para validar emails
        </p>
      </div>

      {/* Plan Alert */}
      {userPlan === "FREE" && (
        <div className="card p-6 bg-gradient-to-r from-primary-50 to-accent-50 border border-primary-200">
          <p className="text-slate-900 font-semibold mb-2">Estás usando el plan Gratis</p>
          <p className="text-slate-700 text-sm">
            Actualiza a Premium para acceder a más features y validaciones ilimitadas.
          </p>
          <Link to="/dashboard/billing" className="btn-primary inline-block mt-4">
            Ver planes
          </Link>
        </div>
      )}

      {/* Features Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {features.map((feature) => {
          const Icon = feature.icon;
          return (
            <Link
              key={feature.path}
              to={feature.available ? feature.path : "#"}
              className={`card p-6 transition-all duration-300 ${
                feature.available
                  ? "hover:shadow-medium hover:scale-105 cursor-pointer"
                  : "opacity-50 cursor-not-allowed"
              }`}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="w-10 h-10 bg-gradient-to-r from-primary-100 to-accent-100 rounded-lg flex items-center justify-center">
                  <Icon className="w-5 h-5 text-primary-600" />
                </div>
                {!feature.available && (
                  <span className="badge-danger">Premium</span>
                )}
              </div>

              <h3 className="font-semibold text-slate-900 mb-2">{feature.title}</h3>
              <p className="text-sm text-slate-600 mb-4">{feature.description}</p>

              {feature.available && (
                <div className="flex items-center text-primary-600 font-medium">
                  Acceder
                  <ArrowRightIcon className="w-4 h-4 ml-2" />
                </div>
              )}
            </Link>
          );
        })}
      </div>
    </div>
  );
};

export default DashboardHome;
