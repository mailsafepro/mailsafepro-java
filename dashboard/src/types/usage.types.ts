/**
 * Tipos relacionados con uso y consumo de API
 */

export interface UsageData {
    usage_today: number;
    limit: number;
    remaining: number;
    usage_percentage: number;
    plan: string;
    reset_time: string;
    as_of: string;
  }
  
  export interface EndpointUsage {
    endpoint: string;
    count: number;
    success: number;
    errors: number;
  }
  
  export interface DayUsage {
    date: string;
    requests: number;
  }
  
  export interface UsageApiError {
    response?: {
      status: number;
      data?: {
        detail?: string;
      };
    };
    message?: string;
  }
  
  export type UsageAlertLevel = 'over' | 'near' | 'normal';
  