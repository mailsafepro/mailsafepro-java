/**
 * Custom hook para manejar la lógica de validación de emails
 */

import { useState, useCallback } from 'react';
import toast from 'react-hot-toast';
import api from '../services/api';
import { validateEmail } from '../utils/validation.utils';
import { parseValidationError } from '../utils/validation-error.utils';
import type { ValidationResult, ValidationApiError } from '../types/validation.types';

interface UseEmailValidationReturn {
  email: string;
  checkSmtp: boolean;
  includeRawDns: boolean;
  result: ValidationResult | null;
  showDetails: boolean;
  isLoading: boolean;
  setEmail: (email: string) => void;
  setCheckSmtp: (checked: boolean) => void;
  setIncludeRawDns: (checked: boolean) => void;
  setShowDetails: (show: boolean) => void;
  toggleDetails: () => void;
  handleValidate: (e: React.FormEvent) => Promise<void>;
}

/**
 * Hook personalizado para gestionar el estado y lógica de validación de emails
 * @returns Estado y funciones para la validación de emails
 */
export const useEmailValidation = (): UseEmailValidationReturn => {
  const [email, setEmail] = useState('');
  const [checkSmtp, setCheckSmtp] = useState(false);
  const [includeRawDns, setIncludeRawDns] = useState(false);
  const [result, setResult] = useState<ValidationResult | null>(null);
  const [showDetails, setShowDetails] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  /**
   * Alterna la visibilidad de los detalles completos
   */
  const toggleDetails = useCallback(() => {
    setShowDetails((prev) => !prev);
  }, []);

  /**
   * Valida el email antes de enviarlo
   */
  const validateBeforeSubmit = useCallback((): boolean => {
    if (!email.trim()) {
      toast.error('Por favor ingresa un email');
      return false;
    }

    const emailError = validateEmail(email);
    if (emailError) {
      toast.error(emailError);
      return false;
    }

    return true;
  }, [email]);

  /**
   * Maneja el envío del formulario de validación
   */
  const handleValidate = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateBeforeSubmit()) {
      return;
    }

    setIsLoading(true);
    setResult(null);
    setShowDetails(false);

    try {
      const normalizedEmail = email.trim().toLowerCase();
      
      const response = await api.post<ValidationResult>('/validate/email', {
        email: normalizedEmail,
        check_smtp: checkSmtp,
        include_raw_dns: includeRawDns,
      });

      setResult(response.data);

      if (response.data.valid) {
        toast.success('Email validado correctamente');
      } else {
        toast.error(`Email no válido: ${response.data.detail}`);
      }
    } catch (error) {
      const errorMessage = parseValidationError(error as ValidationApiError);
      toast.error(errorMessage);
      console.error('Validation error:', (error as ValidationApiError).response?.data || (error as Error).message);
    } finally {
      setIsLoading(false);
    }
  }, [email, checkSmtp, includeRawDns, validateBeforeSubmit]);

  return {
    email,
    checkSmtp,
    includeRawDns,
    result,
    showDetails,
    isLoading,
    setEmail,
    setCheckSmtp,
    setIncludeRawDns,
    setShowDetails,
    toggleDetails,
    handleValidate,
  };
};
