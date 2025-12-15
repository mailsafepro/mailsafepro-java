/**
 * Tarjeta individual de API Key
 */

import { memo } from 'react';
import { TrashIcon } from '@heroicons/react/24/solid';
import type { ApiKey } from '../../types/api-keys.types';

interface APIKeyCardProps {
  apiKey: ApiKey;
  onRevoke: (keyHash: string) => void;
}

/**
 * Tarjeta que muestra información de una API Key
 */
export const APIKeyCard = memo<APIKeyCardProps>(({ apiKey, onRevoke }) => (
  <div className="bg-white rounded-lg shadow-sm p-6 border border-gray-200">
    <div className="flex justify-between items-start mb-4">
      <div>
        <h3 className="font-semibold text-gray-900">{apiKey.name}</h3>
        <p className="text-xs text-gray-600">
          Creada el {new Date(apiKey.created_at).toLocaleDateString()}
        </p>
      </div>
      {apiKey.revoked && (
        <span className="px-2 py-1 text-xs font-medium text-red-700 bg-red-100 rounded-full">
          Revocada
        </span>
      )}
    </div>

    <div className="flex flex-wrap gap-2 mb-4">
      {apiKey.scopes && apiKey.scopes.length > 0 ? (
        apiKey.scopes.map((scope) => (
          <span 
            key={scope} 
            className="px-2 py-1 text-xs font-medium text-indigo-700 bg-indigo-100 rounded-full"
          >
            {scope}
          </span>
        ))
      ) : (
        <p className="text-xs text-gray-600">No hay permisos definidos</p>
      )}
    </div>

    <button
      onClick={() => onRevoke(apiKey.key_hash)}
      disabled={apiKey.revoked}
      className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-red-600 bg-white border border-red-300 rounded-lg hover:bg-red-50 disabled:opacity-50 disabled:cursor-not-allowed transition"
    >
      <TrashIcon className="w-4 h-4" />
      Revocar
    </button>
  </div>
));

APIKeyCard.displayName = 'APIKeyCard';

