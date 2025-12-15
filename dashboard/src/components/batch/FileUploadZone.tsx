/**
 * Componente de zona de carga de archivos
 */

import { memo, type ChangeEvent } from 'react';
import { DocumentIcon } from '@heroicons/react/24/solid';
import { formatFileSize } from '../../utils/file.utils';

interface FileUploadZoneProps {
  file: File | null;
  fileInputRef: React.RefObject<HTMLInputElement | null>;  // 👈 Añade | null aquí también
  onFileSelect: (e: ChangeEvent<HTMLInputElement>) => void;
  onFileRemove: () => void;
  onTriggerInput: () => void;
  disabled?: boolean;
}

/**
 * Zona de arrastrar y soltar archivo con preview
 */
export const FileUploadZone = memo<FileUploadZoneProps>(({
  file,
  fileInputRef,
  onFileSelect,
  onFileRemove,
  onTriggerInput,
  disabled = false,
}) => (
  <div>
    <div
      className={`
        border-2 border-dashed rounded-xl p-12 text-center transition-colors
        ${disabled 
          ? 'border-gray-200 bg-gray-50 cursor-not-allowed' 
          : 'border-indigo-200 cursor-pointer hover:border-indigo-400'
        }
      `}
      onClick={disabled ? undefined : onTriggerInput}
      role="button"
      tabIndex={disabled ? -1 : 0}
      aria-label="Zona de carga de archivos"
      onKeyDown={(e) => {
        if (!disabled && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault();
          onTriggerInput();
        }
      }}
    >
      <DocumentIcon 
        className={`w-12 h-12 mx-auto mb-4 ${disabled ? 'text-gray-300' : 'text-indigo-400'}`}
        aria-hidden="true"
      />
      <p className={`text-lg font-semibold ${disabled ? 'text-gray-400' : 'text-gray-900'}`}>
        {file ? file.name : 'Arrastra un archivo aquí'}
      </p>
      <p className={`text-sm mt-2 ${disabled ? 'text-gray-400' : 'text-gray-600'}`}>
        CSV, TXT o ZIP (máximo 5MB)
      </p>
      <input
        ref={fileInputRef}
        type="file"
        onChange={onFileSelect}
        className="hidden"
        accept=".csv,.txt,.zip"
        disabled={disabled}
        aria-label="Seleccionar archivo"
      />
    </div>

    {file && (
      <div className="mt-4 p-4 bg-indigo-50 rounded-lg flex justify-between items-center">
        <div>
          <p className="text-sm text-indigo-600 font-medium">
            {file.name} ({formatFileSize(file.size)} MB)
          </p>
        </div>
        <button
          onClick={onFileRemove}
          className="text-xs text-indigo-600 hover:text-indigo-700 font-semibold transition"
          disabled={disabled}
          type="button"
        >
          Cambiar archivo
        </button>
      </div>
    )}
  </div>
));

FileUploadZone.displayName = 'FileUploadZone';
