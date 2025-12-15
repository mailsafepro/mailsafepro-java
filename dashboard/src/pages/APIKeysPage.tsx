import { memo } from 'react';
import { PlusIcon, ArrowPathIcon } from '@heroicons/react/24/outline';
import { useAPIKeys } from '../hooks/useAPIKeys';
import { Button } from '../components/ui/Button';
import { CreateKeyDialog } from '../components/api-keys/CreateKeyDialog';
import { NewKeyDialog } from '../components/api-keys/NewKeyDialog';
import { APIKeyCard } from '../components/api-keys/APIKeyCard';
import { EmptyState } from '../components/api-keys/EmptyState';
import { LoadingSpinner } from '../components/api-keys/LoadingSpinner';

/**
 * Encabezado de la página de API Keys
 */
const APIKeysHeader = memo<{
  isLoading: boolean;
  onRefresh: () => void;
  onCreateNew: () => void;
}>(({ isLoading, onRefresh, onCreateNew }) => (
  <div className="flex flex-col sm:flex-row justify-between items-start gap-4">
    <div>
      <h1 className="text-3xl font-bold text-gray-900">
        Gestión de Claves API
      </h1>
      <p className="text-gray-600 mt-2">
        Crea y administra tus claves API
      </p>
    </div>
    <div className="flex gap-2">
      <Button
        onClick={onRefresh}
        disabled={isLoading}
        variant="secondary"
      >
        <ArrowPathIcon className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
        Actualizar
      </Button>
      <Button
        onClick={onCreateNew}
        variant="primary"
      >
        <PlusIcon className="w-4 h-4" />
        Nueva API Key
      </Button>
    </div>
  </div>
));

APIKeysHeader.displayName = 'APIKeysHeader';

/**
 * Banner informativo
 */
const InfoBanner = memo(() => (
  <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
    <p className="text-sm text-gray-700">
      Cada clave API tiene los mismos permisos y plan que tu cuenta. 
      Puedes crear múltiples claves para diferentes entornos.
    </p>
  </div>
));

InfoBanner.displayName = 'InfoBanner';

/**
 * Página de gestión de API Keys para MailSafePro
 * Permite crear, listar y revocar API Keys
 */
const APIKeysPage = () => {
  const {
    keys,
    isLoading,
    showCreateDialog,
    showNewKeyDialog,
    newKeyName,
    newKeyData,
    setShowCreateDialog,
    setNewKeyName,
    fetchKeys,
    createNewKey,
    revokeKey,
    copyNewKey,
    closeNewKeyDialog,
  } = useAPIKeys();

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-5xl mx-auto space-y-6">
        <APIKeysHeader
          isLoading={isLoading}
          onRefresh={fetchKeys}
          onCreateNew={() => setShowCreateDialog(true)}
        />

        <InfoBanner />

        {/* Diálogos */}
        <CreateKeyDialog
          isOpen={showCreateDialog}
          keyName={newKeyName}
          onKeyNameChange={setNewKeyName}
          onClose={() => setShowCreateDialog(false)}
          onCreate={createNewKey}
        />

        <NewKeyDialog
          isOpen={showNewKeyDialog}
          keyData={newKeyData}
          onClose={closeNewKeyDialog}
          onCopy={copyNewKey}
        />

        {/* Lista de Keys */}
        <div className="space-y-4">
          {isLoading ? (
            <LoadingSpinner />
          ) : keys.length === 0 ? (
            <EmptyState />
          ) : (
            keys.map((key) => (
              <APIKeyCard
                key={key.id}
                apiKey={key}
                onRevoke={revokeKey}
              />
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default memo(APIKeysPage);
