/**
 * Tipos relacionados con validación de emails
 */

export interface ValidationOptions {
    email: string;
    checkSmtp: boolean;
    includeRawDns: boolean;
  }
  
  export interface ValidationResult {
    email: string;
    valid: boolean;
    detail: string;
    risk_score: number;
    quality_score: number;
    provider_analysis?: ProviderAnalysis;
    smtp_validation?: SmtpValidation;
    dns_security?: DnsSecurity;
    processing_time: number;
    metadata?: ValidationMetadata;
    error_type?: string;
  }
  
  export interface ProviderAnalysis {
    provider: string;
    reputation: number;
    fingerprint?: string;
  }
  
  export interface SmtpValidation {
    checked: boolean;
    mailbox_exists?: boolean | null;
    mx_server?: string;
    detail?: string;
    skip_reason?: string;
  }
  
  export interface DnsSecurity {
    spf?: DnsRecord;
    dkim?: DnsRecord;
    dmarc?: DnsRecord;
  }
  
  export interface DnsRecord {
    status: string;
    record?: string;
    selector?: string;
    policy?: string;
  }
  
  export interface ValidationMetadata {
    validation_id: string;
    timestamp: string;
  }
  
  export interface ValidationApiError {
    response?: {
      status: number;
      data?: {
        detail?: string;
        errors?: Array<{ message?: string }>;
      };
    };
    message?: string;
  }
  
  export type RiskLevel = 'Bajo' | 'Medio' | 'Alto';