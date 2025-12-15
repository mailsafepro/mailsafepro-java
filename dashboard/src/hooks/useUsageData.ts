/**
 * Custom hook para manejar datos de uso de API
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import toast from 'react-hot-toast';
import api from '../services/api';
import { parseUsageError } from '../utils/usage-error.utils';
import type { UsageData, EndpointUsage, DayUsage, UsageApiError } from '../types/usage.types';

interface UseUsageDataReturn {
  usage: UsageData | null;
  endpointUsage: EndpointUsage[];
  dailyUsage: DayUsage[];
  isLoading: boolean;
  error: string | null;
  fetchUsage: () => Promise<void>;
}

const POLLING_INTERVAL = 60000; // 60 segundos (1 minuto)

/**
 * Hook personalizado para gestionar datos de uso de API
 * @param enablePolling - Si debe hacer polling automático
 * @returns Estado y funciones para datos de uso
 */
export const useUsageData = (enablePolling: boolean = false): UseUsageDataReturn => {
  const [usage, setUsage] = useState<UsageData | null>(null);
  const [endpointUsage, setEndpointUsage] = useState<EndpointUsage[]>([]);
  const [dailyUsage, setDailyUsage] = useState<DayUsage[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // ✅ NUEVO: Refs para prevenir llamadas duplicadas
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const isFetchingRef = useRef(false);
  const isMountedRef = useRef(true);

  /**
   * Obtiene los datos de uso
   */
  const fetchUsage = useCallback(async () => {
    // ✅ PREVENIR LLAMADAS DUPLICADAS
    if (isFetchingRef.current) {
      console.log('🚫 Fetch already in progress, skipping...');
      return;
    }

    isFetchingRef.current = true;
    
    try {
      setError(null);
      
      console.log('🔄 Fetching usage data...');
      const response = await api.get<UsageData>('/api-keys/usage');
      
      console.log('✅ Usage data received:', response.data.usage_today);
      
      // ✅ Solo actualizar si el componente sigue montado
      if (isMountedRef.current) {
        setUsage(response.data);
      }
    } catch (err) {
      const errorMessage = parseUsageError(err as UsageApiError);
      
      if (isMountedRef.current) {
        setError(errorMessage);
        console.error('❌ Error fetching usage:', err);
        
        // Solo mostrar toast si no tenemos datos previos
        if (!usage) {
          toast.error(errorMessage);
        }
      }
    } finally {
      if (isMountedRef.current) {
        setIsLoading(false);
      }
      isFetchingRef.current = false;
    }
  }, []); // ✅ SIN DEPENDENCIAS para evitar re-creación

  /**
   * Configura el polling automático
   */
  useEffect(() => {
    // ✅ Marcar como montado
    isMountedRef.current = true;

    // Ejecutar fetch inicial
    fetchUsage();

    // Configurar polling si está habilitado
    if (enablePolling) {
      console.log('🔄 Starting polling every', POLLING_INTERVAL / 1000, 'seconds');
      
      intervalRef.current = setInterval(() => {
        console.log('⏰ Polling tick - fetching usage...');
        fetchUsage();
      }, POLLING_INTERVAL);
    }

    // Cleanup al desmontar
    return () => {
      isMountedRef.current = false;
      
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
        console.log('🛑 Polling stopped');
      }
    };
  }, [enablePolling]); // ✅ SOLO enablePolling como dependencia

  return {
    usage,
    endpointUsage,
    dailyUsage,
    isLoading,
    error,
    fetchUsage,
  };
};
