/**
 * Custom hook para manejar la lógica de facturación
 */

import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { loadStripe } from '@stripe/stripe-js';
import api from '../services/api';
import { useAuth } from '../contexts/AuthContext';
import { parseBillingError } from '../utils/billing-error.utils';
import type { 
  PlanType, 
  ChangePlanResponse, 
  CreateCheckoutResponse,
  BillingApiError 
} from '../types/billing.types';

interface UseBillingReturn {
  isLoading: boolean;
  selectedPlan: PlanType | null;
  handleChangePlan: (planId: PlanType) => Promise<void>;
  handleUpgrade: (planId: PlanType) => Promise<void>;
}

/**
 * Hook personalizado para gestionar la facturación y cambios de plan
 * @returns Estado y funciones para gestión de facturación
 */
export const useBilling = (): UseBillingReturn => {
  const navigate = useNavigate();
  const { userPlan, refreshUserData, updateTokens } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [selectedPlan, setSelectedPlan] = useState<PlanType | null>(null);

  /**
   * Maneja el cambio de plan (especialmente para downgrade a FREE)
   */
  const handleChangePlan = useCallback(async (planId: PlanType) => {
    if (planId === userPlan) {
      toast.success(`Ya estás suscrito al plan ${planId}`);
      return;
    }

    setIsLoading(true);
    setSelectedPlan(planId);

    try {
      console.log('🔄 Cambiando a plan:', planId);

      const response = await api.post<ChangePlanResponse>('/billing/change-plan', {
        plan: planId,
      });

      console.log('✅ Response:', response.data);

      if (response.data.access_token && response.data.refresh_token) {
        console.log('💾 Guardando nuevos tokens...');

        // Actualizar tokens en sessionStorage
        updateTokens(
          response.data.access_token,
          response.data.refresh_token,
          response.data.plan
        );

        // Esperar a que los cambios se propaguen
        await new Promise(resolve => setTimeout(resolve, 500));

        // Refrescar datos del usuario
        await refreshUserData();

        console.log('✅ Plan actualizado correctamente');

        toast.success(`¡Plan actualizado a ${response.data.plan}!`);
        setSelectedPlan(response.data.plan);
        navigate('/dashboard');
      } else {
        toast.error('No se recibieron tokens en la respuesta');
      }
    } catch (error) {
      console.error('❌ Error:', error);
      const errorMessage = parseBillingError(
        error as BillingApiError,
        'Error al cambiar el plan'
      );
      toast.error(errorMessage);
      setSelectedPlan(null);
    } finally {
      setIsLoading(false);
    }
  }, [userPlan, updateTokens, refreshUserData, navigate]);

  /**
   * Maneja la actualización a planes de pago
   */
  const handleUpgrade = useCallback(async (planId: PlanType) => {
    if (planId === userPlan) {
      toast.success(`Ya estás suscrito al plan ${planId}`);
      return;
    }

    // Cambio a plan gratuito
    if (planId === 'FREE') {
      await handleChangePlan('FREE');
      return;
    }

    // Plan enterprise requiere contacto
    if (planId === 'ENTERPRISE') {
      toast.error('Por favor contacta a ventas para planes enterprise');
      return;
    }

    setIsLoading(true);
    setSelectedPlan(planId);

    try {
      console.log('🛒 Iniciando compra para plan:', planId);

      const response = await api.post<CreateCheckoutResponse>(
        '/billing/create-checkout-session',
        { plan: planId }
      );

      console.log('✅ Session creada:', response.data.session_id);

      const { session_id } = response.data;

      const stripe = await loadStripe(
        import.meta.env.VITE_STRIPE_PUBLIC_KEY
      );

      if (!stripe) {
        throw new Error('Stripe no cargó correctamente');
      }

      console.log('🔗 Redirigiendo a Stripe...');

      const { error } = await stripe.redirectToCheckout({
        sessionId: session_id,
      });

      if (error) {
        console.error('❌ Stripe error:', error.message);
        toast.error(error.message || 'Error en el pago');
      }
    } catch (error) {
      console.error('❌ Error creando checkout:', error);
      const errorMessage = parseBillingError(
        error as BillingApiError,
        'Error al procesar el pago'
      );
      toast.error(errorMessage);
    } finally {
      setIsLoading(false);
      setSelectedPlan(null);
    }
  }, [userPlan, handleChangePlan]);

  return {
    isLoading,
    selectedPlan,
    handleChangePlan,
    handleUpgrade,
  };
};
