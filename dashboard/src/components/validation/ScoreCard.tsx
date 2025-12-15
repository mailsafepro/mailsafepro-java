/**
 * Componente para mostrar puntuaciones
 */

import { memo } from 'react';

interface ScoreCardProps {
  title: string;
  score: number;
  badge?: string;
  badgeColor?: string;
}

/**
 * Tarjeta para mostrar una puntuación con badge opcional
 */
export const ScoreCard = memo<ScoreCardProps>(({ 
  title, 
  score, 
  badge, 
  badgeColor 
}) => (
  <div className="bg-gray-50 rounded-lg p-4">
    <p className="text-sm text-gray-600">{title}</p>
    <div className="mt-2 flex items-baseline gap-2">
      <span className="text-3xl font-bold text-gray-900">
        {(score * 100).toFixed(0)}%
      </span>
      {badge && (
        <span className={`text-xs font-medium ${badgeColor || 'text-gray-600'}`}>
          {badge}
        </span>
      )}
    </div>
  </div>
));

ScoreCard.displayName = 'ScoreCard';