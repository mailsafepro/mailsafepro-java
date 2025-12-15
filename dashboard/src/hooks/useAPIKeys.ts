/**
 * Custom hook para manejar la lógica de API Keys
 */

import { useState, useCallback, useEffect } from 'react';
import toast from 'react-hot-toast';
import api from '../services/api';
import { parseApiKeysError } from '../utils/api-keys-error.utils';
import { copyToClipboard } from '../utils/clipboard.utils';
import type { 
  ApiKey, 
  NewApiKeyResponse,
  ApiKeysListResponse,
  ApiKeysError 
} from '../types/api-keys.types';

interface UseAPIKeysReturn {
  keys: ApiKey[];
  isLoading: boolean;
  showCreateDialog: boolean;
  showNewKeyDialog: boolean;
  newKeyName: string;
  newKeyData: NewApiKeyResponse | null;
  setShowCreateDialog: (show: boolean) => void;
  setNewKeyName: (name: string) => void;
  fetchKeys: () => Promise<void>;
  createNewKey: () => Promise<void>;
  revokeKey: (keyHash: string) => Promise<void>;
  copyNewKey: () => Promise<void>;
  closeNewKeyDialog: () => void;
}

/**
 * Hook personalizado para gestionar API Keys
 * @returns Estado y funciones para la gestión de API Keys
 */
export const useAPIKeys = (): UseAPIKeysReturn => {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showNewKeyDialog, setShowNewKeyDialog] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyData, setNewKeyData] = useState<NewApiKeyResponse | null>(null);

  /**
   * Obtiene la lista de API Keys
   */
  const fetchKeys = useCallback(async () => {
    setIsLoading(true);
    try {
      const response = await api.get<ApiKeysListResponse>('/api-keys');
      setKeys(response.data.keys || []);
    } catch (error) {
      const errorMessage = parseApiKeysError(
        error as ApiKeysError,
        'Error al cargar claves API'
      );
      toast.error(errorMessage);
      console.error('Fetch API keys error:', error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Crea una nueva API Key
   */
  const createNewKey = useCallback(async () => {
    const keyName = newKeyName.trim() || `Clave ${new Date().toLocaleDateString()}`;
    
    try {
      const response = await api.post<NewApiKeyResponse>('/api-keys', {
        name: keyName,
      });

      setNewKeyData(response.data);
      setShowNewKeyDialog(true);
      setShowCreateDialog(false);
      setNewKeyName('');
      
      toast.success('Nueva API Key creada');
      
      // Recargar lista de keys
      await fetchKeys();
    } catch (error) {
      const errorMessage = parseApiKeysError(
        error as ApiKeysError,
        'Error creando API Key'
      );
      toast.error(errorMessage);
      console.error('Create API key error:', error);
    }
  }, [newKeyName, fetchKeys]);

  /**
   * Revoca una API Key
   */
  const revokeKey = useCallback(async (keyHash: string) => {
    if (!window.confirm('¿Estás seguro de que quieres revocar esta clave?')) {
      return;
    }

    try {
      await api.delete(`/api-keys/${keyHash}/revoke`);
      toast.success('Clave revocada correctamente');
      await fetchKeys();
    } catch (error) {
      const errorMessage = parseApiKeysError(
        error as ApiKeysError,
        'Error al revocar la clave'
      );
      toast.error(errorMessage);
      console.error('Revoke API key error:', error);
    }
  }, [fetchKeys]);

  /**
   * Copia la nueva API Key al portapapeles
   */
  const copyNewKey = useCallback(async () => {
    if (!newKeyData?.api_key) {
      return;
    }

    try {
      await copyToClipboard(newKeyData.api_key);
      toast.success('API key copiada al portapapeles');
      setNewKeyData(null);
      setShowNewKeyDialog(false);
    } catch (error) {
      toast.error('Error al copiar al portapapeles');
      console.error('Copy to clipboard error:', error);
    }
  }, [newKeyData]);

  /**
   * Cierra el diálogo de nueva key
   */
  const closeNewKeyDialog = useCallback(() => {
    setNewKeyData(null);
    setShowNewKeyDialog(false);
  }, []);

  // Cargar keys al montar el componente
  useEffect(() => {
    fetchKeys();
  }, [fetchKeys]);

  return {
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
  };
};
