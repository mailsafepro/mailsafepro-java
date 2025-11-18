import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import toast from "react-hot-toast";

const BillingSuccessPage = () => {
  const navigate = useNavigate();
  const { refreshUserData, updateTokens } = useAuth();
  const hasRun = useRef(false);

  useEffect(() => {
    if (hasRun.current) return;
    hasRun.current = true;

    const processSuccess = async () => {
      try {
        console.log("🔄 Procesando pago exitoso...");
        
        // Esperar a que Stripe procese (es rápido pero seguro)
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // ✅ Refrescar datos (esto lee el plan ACTUALIZADO de Redis)
        await refreshUserData();
        
        console.log("✅ Datos refrescados");
        navigate("/dashboard");
        toast.success("¡Pago completado! 🎉");
      } catch (error) {
        console.error("❌ Error:", error);
        navigate("/dashboard");
      }
    };

    processSuccess();
  }, [navigate, refreshUserData]);

  return <div className="flex items-center justify-center h-screen">Un momento por favor...</div>;
};

export default BillingSuccessPage;
