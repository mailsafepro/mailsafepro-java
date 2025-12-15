/**
 * Tipos relacionados con registro de usuarios
 */

export interface RegisterCredentials {
    email: string;
    password: string;
    confirmPassword: string;
  }
  
  export interface RegisterFormErrors {
    email?: string;
    password?: string;
    confirmPassword?: string;
  }
  
  export interface RegisterApiResponse {
    access_token: string;
    refresh_token: string;
    user?: {
      id: string;
      email: string;
    };
  }
  
  export interface RegisterApiError {
    response?: {
      status: number;
      data?: {
        detail?: string | RegisterErrorDetail;
        errors?: Array<{
          field?: string;
          message?: string;
          detail?: string;
        }>;
      };
    };
    message?: string;
  }
  
  export interface RegisterErrorDetail {
    error?: string;
    email?: string;
    password?: string;
    retry_after?: number;
  }
  
  export interface PasswordValidationResult {
    isValid: boolean;
    errors: string[];
  }
  