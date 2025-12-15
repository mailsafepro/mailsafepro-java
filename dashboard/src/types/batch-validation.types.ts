/**
 * Tipos relacionados con validación por lotes
 */

export interface BatchValidationResult {
    email: string;
    valid: boolean;
    processing_time: number;
    detail?: string;
    risk_score?: number;
  }
  
  export interface BatchValidationResponse {
    results: BatchValidationResult[];
    total: number;
    valid_count: number;
    invalid_count: number;
    processing_time: number;
  }
  
  export interface BatchValidationStats {
    total: number;
    valid: number;
    invalid: number;
  }
  
  export interface BatchValidationApiError {
    response?: {
      status: number;
      data?: {
        detail?: string;
      };
    };
    message?: string;
  }
  
  export type AcceptedFileType = '.csv' | '.txt' | '.zip';