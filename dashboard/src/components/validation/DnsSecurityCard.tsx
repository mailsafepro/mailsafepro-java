/**
 * Componente para mostrar seguridad DNS
 */

import { memo } from 'react';
import { getDnsStatusColor } from '../../utils/risk.utils';
import type { DnsSecurity } from '../../types/validation.types';

interface DnsSecurityCardProps {
  security: DnsSecurity;
}

/**
 * Muestra información de seguridad DNS (SPF, DKIM, DMARC)
 */
export const DnsSecurityCard = memo<DnsSecurityCardProps>(({ security }) => (
  <div className="bg-gray-50 rounded-lg p-4 space-y-3">
    <h4 className="font-semibold text-gray-900">Seguridad DNS</h4>
    <div className="grid grid-cols-3 gap-3 text-sm">
      <div>
        <p className="text-gray-600">SPF</p>
        <p className={`font-medium ${getDnsStatusColor(security.spf?.status)}`}>
          {security.spf?.status || 'N/A'}
        </p>
      </div>
      <div>
        <p className="text-gray-600">DKIM</p>
        <p className={`font-medium ${getDnsStatusColor(security.dkim?.status)}`}>
          {security.dkim?.status || 'N/A'}
        </p>
      </div>
      <div>
        <p className="text-gray-600">DMARC</p>
        <p className={`font-medium ${getDnsStatusColor(security.dmarc?.status)}`}>
          {security.dmarc?.status || 'N/A'}
        </p>
      </div>
    </div>
  </div>
));

DnsSecurityCard.displayName = 'DnsSecurityCard';