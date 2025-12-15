/**
 * Tipos relacionados con perfil de usuario
 */

export interface UserProfile {
    email: string;
    plan: string;
    status: 'active' | 'inactive' | 'suspended';
    createdAt?: string;
    lastLogin?: string;
  }
  
  export type AccountStatus = 'Activo' | 'Inactivo' | 'Suspendido';