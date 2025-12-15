import { useEffect, useRef, useState, memo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import toast from 'react-hot-toast';

/**
 * Spinner de carga
 */
const LoadingSpinner = memo(() => (
  <div className="flex items-center justify-center h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
    <div className="text-center">
      <div 
        className="animate-spin rounded-full h-16 w-16 border-b-4 border-indigo-600 mx-auto mb-4"
        role="status"
        aria-label="Procesando pago"
      />
      <p className="text-lg text-gray-700 font-medium">
        Procesando tu pago...
      </p>
      <p className="text-sm text-gray-600 mt-2">
        Un momento por favor
      </p>
    </div>
  </div>
));

LoadingSpinner.displayName = 'LoadingSpinner';

/**
 * Página de éxito después del pago con Stripe
 * Procesa la confirmación y actualiza el plan del usuario
 */
const BillingSuccessPage = () => {
  const navigate = useNavigate();
  const { refreshUserData } = useAuth();
  const hasRun = useRef(false);
  const [isProcessing, setIsProcessing] = useState(true);

  useEffect(() => {
    // Evitar ejecución múltiple
    if (hasRun.current) return;
    hasRun.current = true;

    const processSuccess = async () => {
      try {
        console.log('🔄 Procesando pago exitoso...');

        // Esperar a que Stripe procese
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Refrescar datos del usuario (plan actualizado)
        await refreshUserData();

        console.log('✅ Datos refrescados');

        toast.success('¡Pago completado! 🎉');
        navigate('/dashboard');
      } catch (error) {
        console.error('❌ Error procesando éxito:', error);
        toast.error('Error al procesar el pago. Por favor contacta a soporte.');
        navigate('/dashboard');
      } finally {
        setIsProcessing(false);
      }
    };

    processSuccess();
  }, [navigate, refreshUserData]);

  if (!isProcessing) {
    return null;
  }

  return <LoadingSpinner />;
};

export default memo(BillingSuccessPage);
