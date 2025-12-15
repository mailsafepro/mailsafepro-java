/**
 * Custom hook para manejar la lógica de validación por lotes
 */

import { useState, useRef, useCallback, useMemo } from 'react';
import toast from 'react-hot-toast';
import api from '../services/api';
import { validateFile } from '../utils/file.utils';
import { parseBatchValidationError } from '../utils/batch-error.utils';
import type { 
  BatchValidationResult, 
  BatchValidationStats,
  BatchValidationApiError 
} from '../types/batch-validation.types';

interface UseBatchValidationReturn {
  file: File | null;
  results: BatchValidationResult[];
  stats: BatchValidationStats;
  isLoading: boolean;
  fileInputRef: React.RefObject<HTMLInputElement | null>;  // 👈 Añade | null aquí
  handleFileSelect: (e: React.ChangeEvent<HTMLInputElement>) => void;
  handleFileRemove: () => void;
  handleValidate: () => Promise<void>;
  triggerFileInput: () => void;
}

/**
 * Hook personalizado para gestionar el estado y lógica de validación por lotes
 * @returns Estado y funciones para la validación por lotes
 */
export const useBatchValidation = (): UseBatchValidationReturn => {
  const [file, setFile] = useState<File | null>(null);
  const [results, setResults] = useState<BatchValidationResult[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  /**
   * Calcula estadísticas de los resultados
   */
  const stats = useMemo<BatchValidationStats>(() => {
    const valid = results.filter((r) => r.valid).length;
    const invalid = results.filter((r) => !r.valid).length;

    return {
      total: results.length,
      valid,
      invalid,
    };
  }, [results]);

  /**
   * Maneja la selección de archivo
   */
  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    
    if (!selectedFile) {
      return;
    }

    const validationError = validateFile(selectedFile);
    if (validationError) {
      toast.error(validationError);
      return;
    }

    setFile(selectedFile);
    setResults([]); // Limpiar resultados anteriores
  }, []);

  /**
   * Maneja la eliminación del archivo
   */
  const handleFileRemove = useCallback(() => {
    setFile(null);
    setResults([]);
    
    // Reset input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  }, []);

  /**
   * Trigger manual del input de archivo
   */
  const triggerFileInput = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  /**
   * Maneja la validación por lotes
   */
  const handleValidate = useCallback(async () => {
    if (!file) {
      toast.error('Selecciona un archivo');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);

    setIsLoading(true);
    setResults([]);

    try {
      const response = await api.post('/validate/batch', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });

      const resultData = response.data.results || [];
      setResults(resultData);

      toast.success(
        `Validación completada: ${resultData.length} email${resultData.length !== 1 ? 's' : ''} procesado${resultData.length !== 1 ? 's' : ''}`
      );
    } catch (error) {
      const errorMessage = parseBatchValidationError(error as BatchValidationApiError);
      toast.error(errorMessage);
      console.error('Batch validation error:', (error as BatchValidationApiError).response?.data || (error as Error).message);
    } finally {
      setIsLoading(false);
    }
  }, [file]);

  return {
    file,
    results,
    stats,
    isLoading,
    fileInputRef,
    handleFileSelect,
    handleFileRemove,
    handleValidate,
    triggerFileInput,
  };
};
