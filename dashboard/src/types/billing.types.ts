/**
 * Tipos relacionados con facturación y planes
 */

export interface Plan {
    id: PlanType;
    name: string;
    price: number;
    currency: string;
    billing_period: string;
    features: string[];
  }
  
  export type PlanType = 'FREE' | 'PREMIUM' | 'ENTERPRISE';
  
  export interface ChangePlanResponse {
    access_token: string;
    refresh_token: string;
    plan: PlanType;
    message?: string;
  }
  
  export interface CreateCheckoutResponse {
    session_id: string;
    url?: string;
  }
  
  export interface BillingApiError {
    response?: {
      status: number;
      data?: {
        detail?: string;
      };
    };
    message?: string;
  }
  