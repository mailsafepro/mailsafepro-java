import { useState, useRef } from "react";
import api from "../services/api";
import toast from "react-hot-toast";
import { DocumentIcon, CheckCircleIcon, XCircleIcon } from "@heroicons/react/24/solid";

interface ValidationResult {
  email: string;
  valid: boolean;
  processing_time: number;
}

const BatchValidationPage = () => {
  const [file, setFile] = useState<File | null>(null);
  const [results, setResults] = useState<ValidationResult[]>([]);
  const [loading, setLoading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      if (selectedFile.size > 5 * 1024 * 1024) {
        toast.error("El archivo no puede exceder 5MB");
        return;
      }
      setFile(selectedFile);
    }
  };

  const handleValidate = async () => {
    if (!file) {
      toast.error("Selecciona un archivo");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    setLoading(true);
    try {
      const response = await api.post("/validate/batch", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setResults(response.data.results || []);
      toast.success(`Validación completada: ${response.data.results.length} emails procesados`);
    } catch (error: any) {
      toast.error(error.response?.data?.detail || "Error en la validación por lotes");
    } finally {
      setLoading(false);
    }
  };

  const validCount = results.filter((r) => r.valid).length;
  const invalidCount = results.filter((r) => !r.valid).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-slate-900">Validación por Lotes</h1>
        <p className="text-slate-600 mt-2">
          Valida múltiples emails de una sola vez
        </p>
      </div>

      {/* Upload Card */}
      <div className="card p-8">
        <div
          className="border-2 border-dashed border-primary-200 rounded-xl p-12 text-center cursor-pointer hover:border-primary-400 transition-colors"
          onClick={() => fileInputRef.current?.click()}
        >
          <DocumentIcon className="w-12 h-12 text-primary-400 mx-auto mb-4" />
          <p className="text-lg font-semibold text-slate-900">
            {file ? file.name : "Arrastra un archivo aquí"}
          </p>
          <p className="text-sm text-slate-600 mt-2">
            CSV, TXT o ZIP (máximo 5MB)
          </p>
          <input
            ref={fileInputRef}
            type="file"
            onChange={handleFileSelect}
            className="hidden"
            accept=".csv,.txt,.zip"
          />
        </div>

        {file && (
          <div className="mt-4 p-4 bg-primary-50 rounded-lg flex justify-between items-center">
            <div>
              <p className="text-sm text-primary-600">
                {file.name} ({(file.size / 1024 / 1024).toFixed(2)} MB)
              </p>
            </div>
            <button
              onClick={() => setFile(null)}
              className="text-xs text-primary-600 hover:text-primary-700 font-semibold"
            >
              Cambiar archivo
            </button>
          </div>
        )}

        <button
          onClick={handleValidate}
          disabled={loading || !file}
          className="btn-primary w-full mt-6"
        >
          {loading ? "Validando..." : "Iniciar Validación"}
        </button>
      </div>

      {/* Results Summary */}
      {results.length > 0 && (
        <div className="grid grid-cols-3 gap-4">
          <div className="card p-4 text-center">
            <p className="text-2xl font-bold text-slate-900">{results.length}</p>
            <p className="text-sm text-slate-600">Total</p>
          </div>
          <div className="card p-4 text-center border-l-4 border-green-500">
            <p className="text-2xl font-bold text-green-600">{validCount}</p>
            <p className="text-sm text-slate-600">Válidos</p>
          </div>
          <div className="card p-4 text-center border-l-4 border-red-500">
            <p className="text-2xl font-bold text-red-600">{invalidCount}</p>
            <p className="text-sm text-slate-600">Inválidos</p>
          </div>
        </div>
      )}

      {/* Results Table */}
      {results.length > 0 && (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 border-b border-slate-200">
                <tr>
                  <th className="px-6 py-3 text-left font-semibold text-slate-900">Email</th>
                  <th className="px-6 py-3 text-left font-semibold text-slate-900">Estado</th>
                  <th className="px-6 py-3 text-left font-semibold text-slate-900">Tiempo (ms)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {results.map((result, idx) => (
                  <tr key={idx} className="hover:bg-slate-50 transition-colors">
                    <td className="px-6 py-3 text-slate-900 font-mono text-xs">{result.email}</td>
                    <td className="px-6 py-3">
                      {result.valid ? (
                        <div className="flex items-center gap-2 text-green-600">
                          <CheckCircleIcon className="w-5 h-5" />
                          <span className="font-medium">Válido</span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-2 text-red-600">
                          <XCircleIcon className="w-5 h-5" />
                          <span className="font-medium">Inválido</span>
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-3 text-slate-600">{result.processing_time.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default BatchValidationPage;
