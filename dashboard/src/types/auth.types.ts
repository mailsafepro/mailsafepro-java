/**
 * Tipos relacionados con autenticación y errores de API
 */

export interface LoginCredentials {
    email: string;
    password: string;
  }
  
  export interface FormErrors {
    email?: string;
    password?: string;
  }
  
  export interface ApiError {
    response?: {
      status: number;
      data?: {
        detail?: string | ErrorDetail;
        errors?: Array<{ message?: string }>;
      };
    };
    message?: string;
  }
  
  export interface ErrorDetail {
    error: string;
    retry_after?: number;
  }
  
  export interface LoginFormState {
    email: string;
    password: string;
    showPassword: boolean;
    errors: FormErrors;
    isLoading: boolean;
  }