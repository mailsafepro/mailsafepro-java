// ============================================
// ARCHIVO CORREGIDO: components/profile/ProfileHeader.tsx
// ============================================
/**
 * Encabezado del perfil con avatar y email
 */

import { memo } from 'react';
import { UserIcon } from '@heroicons/react/24/solid';

interface ProfileHeaderProps {
  email: string | null;  // 👈 Añadido | null
}

/**
 * Muestra el avatar y email del usuario
 */
export const ProfileHeader = memo<ProfileHeaderProps>(({ email }) => (
  <div className="flex items-center gap-4 mb-6">
    <div 
      className="w-12 h-12 bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full flex items-center justify-center"
      aria-hidden="true"
    >
      <UserIcon className="w-6 h-6 text-white" />
    </div>
    <div>
      <p className="text-sm text-gray-600">Email</p>
      <p className="font-semibold text-gray-900">
        {email || 'No disponible'}
      </p>
    </div>
  </div>
));

ProfileHeader.displayName = 'ProfileHeader';
