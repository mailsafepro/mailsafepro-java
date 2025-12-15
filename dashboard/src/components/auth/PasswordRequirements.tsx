/**
 * Componente que muestra los requisitos de contraseña
 */

import { memo } from 'react';
import { CheckCircleIcon, XCircleIcon } from '@heroicons/react/24/solid';

interface PasswordRequirement {
  label: string;
  test: (password: string) => boolean;
}

interface PasswordRequirementsProps {
  password: string;
  show?: boolean;
}

const requirements: PasswordRequirement[] = [
  { label: 'Al menos 8 caracteres', test: (pwd) => pwd.length >= 8 },
  { label: 'Una letra mayúscula', test: (pwd) => /[A-Z]/.test(pwd) },
  { label: 'Una letra minúscula', test: (pwd) => /[a-z]/.test(pwd) },
  { label: 'Un número', test: (pwd) => /\d/.test(pwd) },
];

/**
 * Muestra indicadores visuales de los requisitos de contraseña
 */
export const PasswordRequirements = memo<PasswordRequirementsProps>(({ 
  password, 
  show = true 
}) => {
  if (!show || !password) {
    return (
      <p className="mt-2 text-xs text-gray-500">
        Mínimo 8 caracteres. Incluye mayúscula, minúscula y número
      </p>
    );
  }

  return (
    <div className="mt-2 space-y-1">
      {requirements.map((req, index) => {
        const isMet = req.test(password);
        return (
          <div
            key={index}
            className={`flex items-center gap-1 text-xs transition ${
              isMet ? 'text-green-600' : 'text-gray-500'
            }`}
          >
            {isMet ? (
              <CheckCircleIcon className="h-3.5 w-3.5 flex-shrink-0" aria-hidden="true" />
            ) : (
              <XCircleIcon className="h-3.5 w-3.5 flex-shrink-0" aria-hidden="true" />
            )}
            <span>{req.label}</span>
          </div>
        );
      })}
    </div>
  );
});

PasswordRequirements.displayName = 'PasswordRequirements';

