/**
 * Tarjeta de información del perfil
 */

import { memo } from 'react';

interface InfoCardProps {
  label: string;
  value: string;
  valueColor?: string;
}

/**
 * Muestra una tarjeta con información del perfil
 */
export const InfoCard = memo<InfoCardProps>(({ 
  label, 
  value, 
  valueColor = 'text-gray-900' 
}) => (
  <div className="p-4 bg-gray-50 rounded-lg">
    <p className="text-xs text-gray-600 font-semibold uppercase tracking-wide">
      {label}
    </p>
    <p className={`text-lg font-bold mt-1 ${valueColor}`}>
      {value}
    </p>
  </div>
));

InfoCard.displayName = 'InfoCard';