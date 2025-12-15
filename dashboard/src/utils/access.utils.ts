/**
 * Utilidades para control de acceso por plan
 */

const FEATURE_ACCESS_MAP: Record<string, string[]> = {
    validate: ['FREE', 'PREMIUM', 'ENTERPRISE'],
    batch: ['PREMIUM', 'ENTERPRISE'],
    'api-keys': ['FREE', 'PREMIUM', 'ENTERPRISE'],
    usage: ['FREE', 'PREMIUM', 'ENTERPRISE'],
    billing: ['FREE', 'PREMIUM', 'ENTERPRISE'],
    profile: ['FREE', 'PREMIUM', 'ENTERPRISE'],
  };
  
  /**
   * Verifica si el usuario tiene acceso a una feature según su plan
   * @param feature - Nombre de la feature
   * @param userPlan - Plan del usuario
   * @returns true si tiene acceso
   */
  export const canAccessFeature = (feature: string, userPlan: string): boolean => {
    const allowedPlans = FEATURE_ACCESS_MAP[feature];
    return allowedPlans ? allowedPlans.includes(userPlan) : false;
  };
  
  /**
   * Obtiene el nombre display del plan
   * @param planKey - Key del plan (FREE, PREMIUM, etc.)
   * @returns Nombre formateado
   */
  export const getPlanDisplayName = (planKey: string): string => {
    const names: Record<string, string> = {
      FREE: 'Gratis',
      PREMIUM: 'Premium',
      ENTERPRISE: 'Enterprise',
    };
    return names[planKey] || planKey;
  };
  