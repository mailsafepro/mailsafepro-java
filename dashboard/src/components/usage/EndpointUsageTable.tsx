/**
 * Tabla de uso por endpoint
 */

import { memo } from 'react';
import type { EndpointUsage } from '../../types/usage.types';

interface EndpointUsageTableProps {
  endpointUsage: EndpointUsage[];
}

/**
 * Muestra el uso detallado por endpoint
 */
export const EndpointUsageTable = memo<EndpointUsageTableProps>(({ endpointUsage }) => {
  if (endpointUsage.length === 0) {
    return null;
  }

  return (
    <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">
        Uso por Endpoint
      </h3>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="border-b border-gray-200 bg-gray-50">
            <tr>
              <th className="text-left py-3 px-4 font-semibold text-gray-900">
                Endpoint
              </th>
              <th className="text-right py-3 px-4 font-semibold text-gray-900">
                Solicitudes
              </th>
              <th className="text-right py-3 px-4 font-semibold text-gray-900">
                Exitosas
              </th>
              <th className="text-right py-3 px-4 font-semibold text-gray-900">
                Errores
              </th>
            </tr>
          </thead>
          <tbody>
            {endpointUsage.map((item, idx) => (
              <tr
                key={`${item.endpoint}-${idx}`}
                className="border-b border-gray-100 hover:bg-gray-50 transition-colors"
              >
                <td className="py-3 px-4 text-gray-700">{item.endpoint}</td>
                <td className="py-3 px-4 text-right text-gray-700">{item.count}</td>
                <td className="py-3 px-4 text-right text-green-600 font-medium">
                  {item.success}
                </td>
                <td className="py-3 px-4 text-right text-red-600 font-medium">
                  {item.errors}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
});

EndpointUsageTable.displayName = 'EndpointUsageTable';

