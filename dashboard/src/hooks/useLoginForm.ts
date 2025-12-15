/**
 * Custom hook para manejar la lógica del formulario de login
 */

import { useState, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { useAuth } from '../contexts/AuthContext';
import { validateLoginForm } from '../utils/validation.utils';
import { parseLoginError } from '../utils/auth-error.utils';
import type { FormErrors, ApiError } from '../types/auth.types';

interface UseLoginFormReturn {
  email: string;
  password: string;
  showPassword: boolean;
  errors: FormErrors;
  isLoading: boolean;
  isFormValid: boolean;
  setEmail: (email: string) => void;
  setPassword: (password: string) => void;
  togglePasswordVisibility: () => void;
  clearError: (field: keyof FormErrors) => void;
  handleSubmit: (e: React.FormEvent) => Promise<void>;
}

/**
 * Hook personalizado para gestionar el estado y lógica del formulario de login
 * @returns Estado y funciones para el formulario de login
 */
export const useLoginForm = (): UseLoginFormReturn => {
  const [email, setEmailState] = useState('');
  const [password, setPasswordState] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState<FormErrors>({});
  const [isLoading, setIsLoading] = useState(false);

  const navigate = useNavigate();
  const { login } = useAuth();

  /**
   * Actualiza el email y limpia el error asociado
   */
  const setEmail = useCallback((value: string) => {
    setEmailState(value);
    if (errors.email) {
      setErrors((prev) => ({ ...prev, email: undefined }));
    }
  }, [errors.email]);

  /**
   * Actualiza la contraseña y limpia el error asociado
   */
  const setPassword = useCallback((value: string) => {
    setPasswordState(value);
    if (errors.password) {
      setErrors((prev) => ({ ...prev, password: undefined }));
    }
  }, [errors.password]);

  /**
   * Alterna la visibilidad de la contraseña
   */
  const togglePasswordVisibility = useCallback(() => {
    setShowPassword((prev) => !prev);
  }, []);

  /**
   * Limpia un error específico del formulario
   */
  const clearError = useCallback((field: keyof FormErrors) => {
    setErrors((prev) => ({ ...prev, [field]: undefined }));
  }, []);

  /**
   * Valida el formulario antes de enviarlo
   */
  const validateForm = useCallback((): boolean => {
    const validationErrors = validateLoginForm(email, password);
    setErrors(validationErrors);
    return Object.keys(validationErrors).length === 0;
  }, [email, password]);

  /**
   * Determina si el formulario tiene datos válidos (sin validar)
   */
  const isFormValid = useMemo(() => {
    return email.trim().length > 0 && password.length > 0;
  }, [email, password]);

  /**
   * Maneja el envío del formulario
   */
  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setIsLoading(true);

    try {
      const normalizedEmail = email.trim().toLowerCase();
      await login(normalizedEmail, password);
      
      toast.success('¡Iniciaste sesión correctamente!');
      navigate('/dashboard');
    } catch (error) {
      const errorMessage = parseLoginError(error as ApiError);
      toast.error(errorMessage);
      console.error('Login error:', (error as ApiError).response?.data || (error as Error).message);
    } finally {
      setIsLoading(false);
    }
  }, [email, password, login, navigate, validateForm]);

  return {
    email,
    password,
    showPassword,
    errors,
    isLoading,
    isFormValid,
    setEmail,
    setPassword,
    togglePasswordVisibility,
    clearError,
    handleSubmit,
  };
};


// ============================================
// NUEVO ARCHIVO: components/ui/Input.tsx
// ============================================
/**
 * Componente de input reutilizable con iconos y validación
 */

import { memo, type InputHTMLAttributes, type ReactNode } from 'react';
import { ExclamationCircleIcon } from '@heroicons/react/24/solid';

interface InputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'onChange'> {
  label: string;
  error?: string;
  icon?: ReactNode;
  endIcon?: ReactNode;
  onChange: (value: string) => void;
}

