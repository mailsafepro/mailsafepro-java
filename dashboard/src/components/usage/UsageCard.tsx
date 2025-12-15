/**
 * Tarjeta de estadística de uso
 */

import { memo, type ReactNode } from 'react';

interface UsageCardProps {
  label: string;
  value: string | number;
  gradient: string;
  textColor: string;
  labelColor: string;
  icon?: ReactNode;
}

/**
 * Tarjeta para mostrar una métrica de uso
 */
export const UsageCard = memo<UsageCardProps>(({
  label,
  value,
  gradient,
  textColor,
  labelColor,
  icon,
}) => (
  <div className={`bg-white rounded-lg shadow-sm p-6 border ${gradient}`}>
    {icon && (
      <div className="mb-2">
        {icon}
      </div>
    )}
    <p className={`text-xs font-semibold uppercase tracking-wide ${labelColor}`}>
      {label}
    </p>
    <p className={`text-2xl font-bold mt-3 ${textColor}`}>
      {value}
    </p>
  </div>
));

UsageCard.displayName = 'UsageCard';
