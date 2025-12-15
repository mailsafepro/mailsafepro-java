/**
 * Diálogo para crear una nueva API Key
 */

import { memo } from 'react';
import { Modal } from '../ui/Modal';
import { Button } from '../ui/Button';
import Input from '../ui/Input';

interface CreateKeyDialogProps {
  isOpen: boolean;
  keyName: string;
  onKeyNameChange: (name: string) => void;
  onClose: () => void;
  onCreate: () => void;
}

/**
 * Diálogo para ingresar el nombre de la nueva API Key
 */
export const CreateKeyDialog = memo<CreateKeyDialogProps>(({
  isOpen,
  keyName,
  onKeyNameChange,
  onClose,
  onCreate,
}) => {
  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      onCreate();
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose}>
      <h2 className="text-xl font-bold text-gray-900">
        Crear nueva API Key
      </h2>
      
      <Input
        id="key-name"
        type="text"
        label="Nombre de la clave"
        value={keyName}
        onChange={onKeyNameChange}
        placeholder="Ej: Producción, Testing, etc."
        onKeyDown={handleKeyPress}
        autoFocus
      />
      
      <div className="flex gap-2">
        <Button
          onClick={onClose}
          variant="secondary"
          fullWidth
        >
          Cancelar
        </Button>
        <Button
          onClick={onCreate}
          variant="primary"
          fullWidth
        >
          Crear
        </Button>
      </div>
    </Modal>
  );
});

CreateKeyDialog.displayName = 'CreateKeyDialog';