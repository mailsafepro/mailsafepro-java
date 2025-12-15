/**
 * Diálogo para mostrar la nueva API Key creada
 */

import { memo } from 'react';
import { DocumentDuplicateIcon } from '@heroicons/react/24/solid';
import { Modal } from '../ui/Modal';
import { Button } from '../ui/Button';
import type { NewApiKeyResponse } from '../../types/api-keys.types';

interface NewKeyDialogProps {
  isOpen: boolean;
  keyData: NewApiKeyResponse | null;
  onClose: () => void;
  onCopy: () => void;
}

/**
 * Diálogo para mostrar y copiar la nueva API Key
 */
export const NewKeyDialog = memo<NewKeyDialogProps>(({
  isOpen,
  keyData,
  onClose,
  onCopy,
}) => {
  if (!keyData) {
    return null;
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose}>
      <h2 className="text-xl font-bold text-green-600">
        ¡Nueva API Key creada!
      </h2>
      
      <p className="text-sm text-gray-600">
        Guarda esta clave en un lugar seguro. No se volverá a mostrar.
      </p>
      
      <div className="bg-gray-900 p-4 rounded-lg">
        <p className="text-xs text-gray-400 mb-2">API KEY</p>
        <p className="text-xs text-gray-100 font-mono break-all">
          {keyData.api_key}
        </p>
      </div>
      
      <p className="text-xs text-gray-600">
        Plan: {keyData.plan} • Creada: {new Date(keyData.created_at).toLocaleDateString()}
      </p>
      
      <div className="flex gap-2">
        <Button
          onClick={onClose}
          variant="secondary"
          fullWidth
        >
          Cerrar
        </Button>
        <Button
          onClick={onCopy}
          variant="primary"
          fullWidth
        >
          <DocumentDuplicateIcon className="w-4 h-4" />
          Copiar
        </Button>
      </div>
    </Modal>
  );
});

NewKeyDialog.displayName = 'NewKeyDialog';
