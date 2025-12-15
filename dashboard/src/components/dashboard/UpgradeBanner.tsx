/**
 * Banner para promover upgrade a Premium
 */

import { memo } from 'react';
import { Link } from 'react-router-dom';
import { Button } from '../ui/Button';

/**
 * Muestra un banner invitando a actualizar al plan Premium
 */
export const UpgradeBanner = memo(() => (
  <div className="bg-gradient-to-r from-indigo-50 to-purple-50 border border-indigo-200 rounded-lg p-6">
    <p className="text-gray-900 font-semibold mb-2">
      Estás usando el plan Gratis
    </p>
    <p className="text-gray-700 text-sm mb-4">
      Actualiza a Premium para acceder a más features y validaciones ilimitadas.
    </p>
    <Link to="/dashboard/billing">
      <Button variant="primary">
        Ver planes
      </Button>
    </Link>
  </div>
));

UpgradeBanner.displayName = 'UpgradeBanner';

