/**
 * Componente para mostrar estadísticas
 */

import { memo, type ReactNode } from 'react';

interface StatCardProps {
  value: number;
  label: string;
  borderColor?: string;
  valueColor?: string;
  icon?: ReactNode;
}

/**
 * Tarjeta para mostrar una estadística
 */
export const StatCard = memo<StatCardProps>(({ 
  value, 
  label, 
  borderColor,
  valueColor = 'text-gray-900',
  icon 
}) => (
  <div className={`bg-white rounded-lg shadow-sm p-4 text-center ${borderColor || ''}`}>
    {icon && (
      <div className="flex justify-center mb-2">
        {icon}
      </div>
    )}
    <p className={`text-2xl font-bold ${valueColor}`}>
      {value}
    </p>
    <p className="text-sm text-gray-600 mt-1">
      {label}
    </p>
  </div>
));

StatCard.displayName = 'StatCard';