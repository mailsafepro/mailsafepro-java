import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import toast from "react-hot-toast";
import api from "../services/api";
import { loadStripe } from "@stripe/stripe-js";
import { CheckIcon } from "@heroicons/react/24/solid";

interface Plan {
  id: string;
  name: string;
  price: number;
  currency: string;
  billing_period: string;
  features: string[];
}

const BillingPage = () => {
  const navigate = useNavigate();
  const { userPlan, refreshUserData, updateTokens } = useAuth();
  const [plans, setPlans] = useState<Plan[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedPlan, setSelectedPlan] = useState<string | null>(null);

  const PLANS: Plan[] = [
    {
      id: "FREE",
      name: "Gratis",
      price: 0,
      currency: "EUR",
      billing_period: "mes",
      features: [
        "100 validaciones/mes",
        "Validación básica",
        "Soporte por email",
        "1 API Key",
      ],
    },
    {
      id: "PREMIUM",
      name: "Premium",
      price: 9.99,
      currency: "EUR",
      billing_period: "mes",
      features: [
        "10,000 validaciones/mes",
        "Validación avanzada",
        "Validación por lotes",
        "Soporte prioritario",
        "5 API Keys",
      ],
    },
    {
      id: "ENTERPRISE",
      name: "Enterprise",
      price: 99.99,
      currency: "EUR",
      billing_period: "mes",
      features: [
        "Validaciones ilimitadas",
        "Validación avanzada",
        "Validación por lotes",
        "Soporte 24/7",
        "Claves API ilimitadas",
        "Webhooks",
      ],
    },
  ];

  useEffect(() => {
    setPlans(PLANS);
  }, []);

  // ✅ Manejar cambio a FREE
  const handleChangePlan = async (planId: string) => {
    if (planId === userPlan) {
      toast.success(`Ya estás suscrito al plan ${planId}`);
      return;
    }
  
    setLoading(true);
    setSelectedPlan(planId);
  
    try {
      console.log("🔄 Cambiando a plan:", planId);
      
      const response = await api.post("/billing/change-plan", {
        plan: planId,
      });
  
      console.log("✅ Response:", response.data);
  
      if (response.data.access_token && response.data.refresh_token) {
        console.log("💾 Guardando nuevos tokens...");
        
        // ✅ PASO 1: Actualizar tokens EN SESSIONSTORE
        updateTokens(
          response.data.access_token,
          response.data.refresh_token,
          response.data.plan
        );
  
        // ✅ PASO 2: ESPERAR a que los cambios se propaguen
        await new Promise(resolve => setTimeout(resolve, 500));
  
        // ✅ PASO 3: Refrescar datos (ahora con el nuevo token)
        await refreshUserData();
  
        // ✅ PASO 4: Log para verificar
        console.log("✅ Plan actualizado correctamente");
  
        toast.success(`¡Plan actualizado a ${response.data.plan}!`);
        setSelectedPlan(response.data.plan);
        navigate("/dashboard");
      } else {
        toast.error("No se recibieron tokens en la respuesta");
      }
    } catch (error: any) {
      console.error("❌ Error:", error);
      toast.error(error.response?.data?.detail || "Error al cambiar el plan");
      setSelectedPlan(null);
    } finally {
      setLoading(false);
    }
  };
  

  // ✅ Manejar compra de planes pagos
  const handleUpgrade = async (planId: string) => {
    if (planId === userPlan) {
      toast.success(`Ya estás suscrito al plan ${planId}`);
      return;
    }

    if (planId === "FREE") {
      await handleChangePlan("FREE");
      return;
    }

    if (planId === "ENTERPRISE") {
      toast.error("Por favor contacta a ventas para planes enterprise");
      return;
    }

    setLoading(true);
    setSelectedPlan(planId);

    try {
      console.log("🛒 Iniciando compra para plan:", planId);

      // ✅ CRÍTICO: Asegurar que el token es válido
      // Si el token expiró, api.post hará auto-refresh
      const response = await api.post("/billing/create-checkout-session", {
        plan: planId,
      });

      console.log("✅ Session creada:", response.data.session_id);

      const { session_id } = response.data;

      const stripe = await loadStripe(
        import.meta.env.VITE_STRIPE_PUBLIC_KEY
      );

      if (!stripe) {
        throw new Error("Stripe no cargó correctamente");
      }

      console.log("🔗 Redirigiendo a Stripe...");

      const { error } = await stripe.redirectToCheckout({
        sessionId: session_id,
      });

      if (error) {
        console.error("❌ Stripe error:", error.message);
        toast.error(error.message || "Error en el pago");
      }
    } catch (error: any) {
      console.error("❌ Error creando checkout:", error);
      const errorMsg = error.response?.data?.detail || error.message || "Error al procesar el pago";
      toast.error(errorMsg);
    } finally {
      setLoading(false);
      setSelectedPlan(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-slate-900">Facturación</h1>
        <p className="text-slate-600 mt-2">Elige el plan que mejor se adapte a ti</p>
      </div>

      {/* Current Plan */}
      {userPlan && userPlan !== "FREE" && (
        <div className="card p-6 bg-gradient-to-r from-green-50 to-emerald-50 border-green-200">
          <p className="text-sm text-slate-600 font-semibold">PLAN ACTUAL</p>
          <p className="text-2xl font-bold text-slate-900 mt-1">
            {PLANS.find((p) => p.id === userPlan)?.name}
          </p>
          <p className="text-slate-600 mt-2 text-sm">
            Tu próximo período de facturación comenzará el próximo mes.
          </p>
        </div>
      )}

      {/* Plans Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {plans.map((plan) => {
          const isCurrentPlan = plan.id === userPlan;
          const isPremium = plan.id !== "FREE" && plan.id !== userPlan;

          return (
            <div
              key={plan.id}
              className={`card transition-all duration-300 overflow-hidden ${
                isCurrentPlan
                  ? "ring-2 ring-primary-500 shadow-medium scale-105"
                  : "hover:shadow-medium"
              }`}
            >
              {/* Featured Badge */}
              {plan.id === "ENTERPRISE" && (
                <div className="bg-gradient-to-r from-primary-600 to-accent-600 text-white text-xs font-bold px-4 py-2 text-center">
                  MÁS POPULAR
                </div>
              )}

              {/* Content */}
              <div className="p-6 space-y-4">
                {/* Plan Name */}
                <div>
                  <h3 className="text-xl font-bold text-slate-900">{plan.name}</h3>
                  <div className="mt-2 flex items-baseline">
                    <span className="text-3xl font-bold text-slate-900">
                      €{plan.price.toFixed(2)}
                    </span>
                    <span className="text-slate-600 ml-2">/{plan.billing_period}</span>
                  </div>
                </div>

                {/* Features */}
                <div className="space-y-3 py-4 border-t border-b border-slate-200">
                  {plan.features.map((feature, idx) => (
                    <div key={idx} className="flex items-start gap-3">
                      <CheckIcon className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                      <span className="text-sm text-slate-700">{feature}</span>
                    </div>
                  ))}
                </div>

                {/* Button */}
                {isCurrentPlan ? (
                  <button className="w-full py-3 bg-slate-100 text-slate-600 font-semibold rounded-lg cursor-default">
                    ✓ Plan Actual
                  </button>
                ) : (
                  <button
                    onClick={() => handleUpgrade(plan.id)}
                    disabled={loading && selectedPlan === plan.id}
                    className={`w-full py-3 font-semibold rounded-lg transition-all duration-200 ${
                      isPremium
                        ? "btn-primary"
                        : "btn-secondary"
                    } ${
                      loading && selectedPlan === plan.id
                        ? "opacity-50 cursor-not-allowed"
                        : ""
                    }`}
                  >
                    {loading && selectedPlan === plan.id
                      ? "Cargando..."
                      : plan.id === "FREE"
                        ? "Cambiar a Gratis"
                        : "Actualizar"}
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* FAQ */}
      <div className="space-y-4 pt-4">
        <h2 className="text-2xl font-bold text-slate-900">Preguntas Frecuentes</h2>
        
        <div className="card p-6 space-y-4">
          <div>
            <h4 className="font-semibold text-slate-900 mb-2">¿Puedo cambiar de plan?</h4>
            <p className="text-slate-600 text-sm">
              Sí, puedes cambiar de plan en cualquier momento. Los cambios se aplicarán el próximo ciclo de facturación.
            </p>
          </div>
          
          <div className="border-t border-slate-200 pt-4">
            <h4 className="font-semibold text-slate-900 mb-2">¿Qué pasa si excedo mi límite?</h4>
            <p className="text-slate-600 text-sm">
              Si usas más validaciones de las permitidas, tu API se pausará. Puedes actualizar tu plan para continuar.
            </p>
          </div>

          <div className="border-t border-slate-200 pt-4">
            <h4 className="font-semibold text-slate-900 mb-2">¿Hay contrato a largo plazo?</h4>
            <p className="text-slate-600 text-sm">
              No. Todos los planes son mensuales y puedes cancelar cuando quieras.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BillingPage;
