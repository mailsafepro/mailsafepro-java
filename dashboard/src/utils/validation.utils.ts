/**
 * Utilidades de validación de formularios
 */

import type { FormErrors } from '../types/auth.types';
import type { RegisterFormErrors, PasswordValidationResult } from '../types/register.types';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;

export const VALIDATION_MESSAGES = {
  EMAIL_REQUIRED: 'El email es requerido',
  EMAIL_INVALID: 'Por favor ingresa un email válido',
  PASSWORD_REQUIRED: 'La contraseña es requerida',
  PASSWORD_MIN_LENGTH: `La contraseña debe tener al menos ${MIN_PASSWORD_LENGTH} caracteres`,
  PASSWORD_MAX_LENGTH: `La contraseña no puede exceder ${MAX_PASSWORD_LENGTH} caracteres`,
  PASSWORD_LOWERCASE: 'La contraseña debe contener al menos una letra minúscula',
  PASSWORD_UPPERCASE: 'La contraseña debe contener al menos una letra mayúscula',
  PASSWORD_NUMBER: 'La contraseña debe contener al menos un número',
  CONFIRM_PASSWORD_REQUIRED: 'Debes confirmar tu contraseña',
  PASSWORDS_DO_NOT_MATCH: 'Las contraseñas no coinciden',
} as const;

/**
 * Valida el formato de un email
 * @param email - Email a validar
 * @returns true si el email es válido
 */
export const isValidEmail = (email: string): boolean => {
  return EMAIL_REGEX.test(email);
};

/**
 * Valida un email y retorna un error si es inválido
 * @param email - Email a validar
 * @returns Mensaje de error o undefined si es válido
 */
export const validateEmail = (email: string): string | undefined => {
  const trimmedEmail = email.trim();
  
  if (!trimmedEmail) {
    return VALIDATION_MESSAGES.EMAIL_REQUIRED;
  }
  
  if (!isValidEmail(trimmedEmail)) {
    return VALIDATION_MESSAGES.EMAIL_INVALID;
  }
  
  return undefined;
};

/**
 * Valida una contraseña con requisitos robustos
 * @param password - Contraseña a validar
 * @returns Resultado de validación con errores específicos
 */
export const validatePasswordStrength = (password: string): PasswordValidationResult => {
  const errors: string[] = [];

  if (!password) {
    return {
      isValid: false,
      errors: [VALIDATION_MESSAGES.PASSWORD_REQUIRED],
    };
  }

  if (password.length < MIN_PASSWORD_LENGTH) {
    errors.push(VALIDATION_MESSAGES.PASSWORD_MIN_LENGTH);
  }

  if (password.length > MAX_PASSWORD_LENGTH) {
    errors.push(VALIDATION_MESSAGES.PASSWORD_MAX_LENGTH);
  }

  if (!/[a-z]/.test(password)) {
    errors.push(VALIDATION_MESSAGES.PASSWORD_LOWERCASE);
  }

  if (!/[A-Z]/.test(password)) {
    errors.push(VALIDATION_MESSAGES.PASSWORD_UPPERCASE);
  }

  if (!/\d/.test(password)) {
    errors.push(VALIDATION_MESSAGES.PASSWORD_NUMBER);
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
};

/**
 * Valida una contraseña y retorna el primer error encontrado
 * @param password - Contraseña a validar
 * @returns Mensaje de error o undefined si es válida
 */
export const validatePassword = (password: string): string | undefined => {
  const result = validatePasswordStrength(password);
  return result.errors[0];
};

/**
 * Valida que dos contraseñas coincidan
 * @param password - Contraseña original
 * @param confirmPassword - Confirmación de contraseña
 * @returns Mensaje de error o undefined si coinciden
 */
export const validatePasswordConfirmation = (
  password: string,
  confirmPassword: string
): string | undefined => {
  if (!confirmPassword) {
    return VALIDATION_MESSAGES.CONFIRM_PASSWORD_REQUIRED;
  }

  if (password !== confirmPassword) {
    return VALIDATION_MESSAGES.PASSWORDS_DO_NOT_MATCH;
  }

  return undefined;
};

/**
 * Valida un formulario de login completo
 * @param email - Email del usuario
 * @param password - Contraseña del usuario
 * @returns Objeto con errores de validación o vacío si no hay errores
 */
export const validateLoginForm = (
  email: string,
  password: string
): FormErrors => {
  const errors: FormErrors = {};
  
  const emailError = validateEmail(email);
  if (emailError) {
    errors.email = emailError;
  }
  
  const passwordError = validatePassword(password);
  if (passwordError) {
    errors.password = passwordError;
  }
  
  return errors;
};

/**
 * Valida un formulario de registro completo
 * @param email - Email del usuario
 * @param password - Contraseña del usuario
 * @param confirmPassword - Confirmación de contraseña
 * @returns Objeto con errores de validación o vacío si no hay errores
 */
export const validateRegisterForm = (
  email: string,
  password: string,
  confirmPassword: string
): RegisterFormErrors => {
  const errors: RegisterFormErrors = {};

  const emailError = validateEmail(email);
  if (emailError) {
    errors.email = emailError;
  }

  const passwordError = validatePassword(password);
  if (passwordError) {
    errors.password = passwordError;
  }

  const confirmError = validatePasswordConfirmation(password, confirmPassword);
  if (confirmError) {
    errors.confirmPassword = confirmError;
  }

  return errors;
};