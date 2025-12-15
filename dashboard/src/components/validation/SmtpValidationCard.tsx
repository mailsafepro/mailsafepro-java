/**
 * Componente para mostrar validación SMTP
 */

import { memo } from 'react';
import type { SmtpValidation } from '../../types/validation.types';

interface SmtpValidationCardProps {
  validation: SmtpValidation;
}

/**
 * Muestra información de validación SMTP
 */
export const SmtpValidationCard = memo<SmtpValidationCardProps>(({ validation }) => (
  <div className="bg-gray-50 rounded-lg p-4 space-y-3">
    <h4 className="font-semibold text-gray-900">Validación SMTP</h4>
    <div className="space-y-2 text-sm">
      <div className="flex justify-between">
        <span className="text-gray-600">Verificado:</span>
        <span className="font-medium">
          {validation.checked ? 'Sí' : 'No'}
        </span>
      </div>
      {validation.checked && (
        <>
          <div className="flex justify-between">
            <span className="text-gray-600">Buzón existe:</span>
            <span
              className={`font-medium ${
                validation.mailbox_exists
                  ? 'text-green-600'
                  : 'text-red-600'
              }`}
            >
              {validation.mailbox_exists === null
                ? 'Desconocido'
                : validation.mailbox_exists
                ? 'Sí'
                : 'No'}
            </span>
          </div>
          {validation.mx_server && (
            <div className="flex justify-between">
              <span className="text-gray-600">Servidor MX:</span>
              <span className="font-medium truncate ml-2">
                {validation.mx_server}
              </span>
            </div>
          )}
          {validation.detail && (
            <p className="text-xs text-gray-500 mt-2">
              {validation.detail}
            </p>
          )}
        </>
      )}
      {!validation.checked && validation.skip_reason && (
        <p className="text-xs text-gray-500">
          {validation.skip_reason}
        </p>
      )}
    </div>
  </div>
));

SmtpValidationCard.displayName = 'SmtpValidationCard';