/**
 * Tipos relacionados con API Keys
 */

export interface ApiKey {
    id: string;
    key_hash: string;
    plan: string;
    created_at: string;
    revoked: boolean;
    revoked_at: string | null;
    scopes: string[];
    name: string;
  }
  
  export interface NewApiKeyResponse {
    api_key: string;
    key_hash: string;
    plan: string;
    created_at: string;
    name: string;
    scopes: string[];
  }
  
  export interface ApiKeysListResponse {
    keys: ApiKey[];
    total: number;
  }
  
  export interface CreateApiKeyRequest {
    name: string;
  }
  
  export interface ApiKeysError {
    response?: {
      status: number;
      data?: {
        detail?: string;
      };
    };
    message?: string;
  }