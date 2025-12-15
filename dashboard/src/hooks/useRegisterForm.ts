/**
 * Custom hook para manejar la lógica del formulario de registro
 */

import { useState, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { useAuth } from '../contexts/AuthContext';
import api from '../services/api';
import { validateRegisterForm } from '../utils/validation.utils';
import { parseRegisterError } from '../utils/register-error.utils';
import type { RegisterFormErrors, RegisterApiError, RegisterApiResponse } from '../types/register.types';

interface UseRegisterFormReturn {
  email: string;
  password: string;
  confirmPassword: string;
  showPassword: boolean;
  showConfirmPassword: boolean;
  errors: RegisterFormErrors;
  isLoading: boolean;
  isFormValid: boolean;
  setEmail: (email: string) => void;
  setPassword: (password: string) => void;
  setConfirmPassword: (password: string) => void;
  togglePasswordVisibility: () => void;
  toggleConfirmPasswordVisibility: () => void;
  clearError: (field: keyof RegisterFormErrors) => void;
  handleSubmit: (e: React.FormEvent) => Promise<void>;
}

/**
 * Hook personalizado para gestionar el estado y lógica del formulario de registro
 * @returns Estado y funciones para el formulario de registro
 */
export const useRegisterForm = (): UseRegisterFormReturn => {
  const [email, setEmailState] = useState('');
  const [password, setPasswordState] = useState('');
  const [confirmPassword, setConfirmPasswordState] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [errors, setErrors] = useState<RegisterFormErrors>({});
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
   * Actualiza la confirmación de contraseña y limpia el error asociado
   */
  const setConfirmPassword = useCallback((value: string) => {
    setConfirmPasswordState(value);
    if (errors.confirmPassword) {
      setErrors((prev) => ({ ...prev, confirmPassword: undefined }));
    }
  }, [errors.confirmPassword]);

  /**
   * Alterna la visibilidad de la contraseña
   */
  const togglePasswordVisibility = useCallback(() => {
    setShowPassword((prev) => !prev);
  }, []);

  /**
   * Alterna la visibilidad de la confirmación de contraseña
   */
  const toggleConfirmPasswordVisibility = useCallback(() => {
    setShowConfirmPassword((prev) => !prev);
  }, []);

  /**
   * Limpia un error específico del formulario
   */
  const clearError = useCallback((field: keyof RegisterFormErrors) => {
    setErrors((prev) => ({ ...prev, [field]: undefined }));
  }, []);

  /**
   * Valida el formulario antes de enviarlo
   */
  const validateForm = useCallback((): boolean => {
    const validationErrors = validateRegisterForm(email, password, confirmPassword);
    setErrors(validationErrors);
    return Object.keys(validationErrors).length === 0;
  }, [email, password, confirmPassword]);

  /**
   * Determina si el formulario tiene datos válidos básicos
   */
  const isFormValid = useMemo(() => {
    return (
      email.trim().length > 0 &&
      password.length > 0 &&
      confirmPassword.length > 0
    );
  }, [email, password, confirmPassword]);

  /**
   * Maneja el envío del formulario de registro
   */
  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setIsLoading(true);

    try {
      const normalizedEmail = email.trim().toLowerCase();
      
      const response = await api.post<RegisterApiResponse>('/auth/register', {
        email: normalizedEmail,
        password,
      });

      const { access_token, refresh_token } = response.data;

      // Guardar tokens en sessionStorage
      sessionStorage.setItem('token', access_token);
      sessionStorage.setItem('refresh_token', refresh_token);

      // Login automático después del registro
      await login(normalizedEmail, password);

      toast.success('¡Registro exitoso! Bienvenido/a.');
      navigate('/dashboard');
    } catch (error) {
      const { formErrors, generalError } = parseRegisterError(
        error as RegisterApiError
      );

      if (Object.keys(formErrors).length > 0) {
        setErrors(formErrors);
      } else {
        toast.error(generalError);
      }

      console.error('Register error:', (error as RegisterApiError).response?.data || (error as Error).message);
    } finally {
      setIsLoading(false);
    }
  }, [email, password, confirmPassword, login, navigate, validateForm]);

  return {
    email,
    password,
    confirmPassword,
    showPassword,
    showConfirmPassword,
    errors,
    isLoading,
    isFormValid,
    setEmail,
    setPassword,
    setConfirmPassword,
    togglePasswordVisibility,
    toggleConfirmPasswordVisibility,
    clearError,
    handleSubmit,
  };
};

