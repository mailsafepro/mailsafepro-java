import { memo } from 'react';
import { useBatchValidation } from '../hooks/useBatchValidation';
import { Button } from '../components/ui/Button';
import { FileUploadZone } from '../components/batch/FileUploadZone';
import { BatchStats } from '../components/batch/BatchStats';
import { ResultsTable } from '../components/batch/ResultsTable';

/**
 * Encabezado de la página de validación por lotes
 */
const BatchValidationHeader = memo(() => (
  <div>
    <h1 className="text-3xl font-bold text-gray-900">
      Validación por Lotes
    </h1>
    <p className="text-gray-600 mt-2">
      Valida múltiples emails de una sola vez
    </p>
  </div>
));

BatchValidationHeader.displayName = 'BatchValidationHeader';

/**
 * Página de validación por lotes para MailSafePro
 * Permite validar múltiples emails mediante carga de archivos
 */
const BatchValidationPage = () => {
  const {
    file,
    results,
    stats,
    isLoading,
    fileInputRef,
    handleFileSelect,
    handleFileRemove,
    handleValidate,
    triggerFileInput,
  } = useBatchValidation();

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-5xl mx-auto space-y-6">
        <BatchValidationHeader />

        {/* Upload Card */}
        <div className="bg-white rounded-lg shadow-md p-8">
          <FileUploadZone
            file={file}
            fileInputRef={fileInputRef}
            onFileSelect={handleFileSelect}
            onFileRemove={handleFileRemove}
            onTriggerInput={triggerFileInput}
            disabled={isLoading}
          />

          <Button
            onClick={handleValidate}
            isLoading={isLoading}
            disabled={!file}
            fullWidth
            variant="primary"
            className="mt-6"
          >
            Iniciar Validación
          </Button>
        </div>

        {/* Results Summary */}
        <BatchStats stats={stats} />

        {/* Results Table */}
        <ResultsTable results={results} />
      </div>
    </div>
  );
};

export default memo(BatchValidationPage);
