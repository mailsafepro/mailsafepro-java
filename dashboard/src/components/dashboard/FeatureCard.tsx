/**
 * Tarjeta de feature del dashboard
 */

import { memo } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRightIcon } from '@heroicons/react/24/solid';
import type { DashboardFeature } from '../../types/dashboard.types';

interface FeatureCardProps {
  feature: DashboardFeature;
}

/**
 * Muestra una tarjeta con información de una feature
 */
export const FeatureCard = memo<FeatureCardProps>(({ feature }) => {
  const Icon = feature.icon;

  return (
    <Link
      to={feature.available ? feature.path : '#'}
      className={`bg-white rounded-lg shadow-sm border border-gray-200 p-6 transition-all duration-300 ${
        feature.available
          ? 'hover:shadow-lg hover:scale-105 cursor-pointer'
          : 'opacity-50 cursor-not-allowed'
      }`}
      onClick={(e) => !feature.available && e.preventDefault()}
      aria-disabled={!feature.available}
    >
      <div className="flex items-start justify-between mb-4">
        <div 
          className="w-10 h-10 bg-gradient-to-r from-indigo-100 to-purple-100 rounded-lg flex items-center justify-center"
          aria-hidden="true"
        >
          <Icon className="w-5 h-5 text-indigo-600" />
        </div>
        {feature.requiresPremium && !feature.available && (
          <span className="px-2 py-1 text-xs font-medium text-red-700 bg-red-100 rounded-full">
            Premium
          </span>
        )}
      </div>

      <h3 className="font-semibold text-gray-900 mb-2">{feature.title}</h3>
      <p className="text-sm text-gray-600 mb-4">{feature.description}</p>

      {feature.available && (
        <div className="flex items-center text-indigo-600 font-medium">
          Acceder
          <ArrowRightIcon className="w-4 h-4 ml-2" aria-hidden="true" />
        </div>
      )}
    </Link>
  );
});

FeatureCard.displayName = 'FeatureCard';
