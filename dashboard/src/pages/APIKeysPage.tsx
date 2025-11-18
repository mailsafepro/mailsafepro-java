import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import api from "../services/api";
import { useAuth } from "../contexts/AuthContext";
import { KeyIcon, TrashIcon, PlusIcon, DocumentDuplicateIcon } from "@heroicons/react/24/solid";
import { ArrowPathIcon } from "@heroicons/react/24/outline";

interface ApiKey {
  id: string;
  key_hash: string;
  plan: string;
  created_at: string;
  revoked: boolean;
  revoked_at: string | null;
  scopes: string[];
  name: string;
}

const APIKeysPage = () => {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(false);
  const [showNewKeyDialog, setShowNewKeyDialog] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyData, setNewKeyData] = useState<any>(null);
  const { userEmail } = useAuth();

  const fetchKeys = async () => {
    setLoading(true);
    try {
      const res = await api.get("/api-keys");
      setKeys(res.data.keys || []);
    } catch (error: any) {
      let errorMsg = "Error al cargar claves API";
      if (error.response?.status === 401) {
        errorMsg = "Sesión expirada. Por favor, inicia sesión de nuevo.";
      }
      toast.error(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  const createNewKey = async () => {
    try {
      const response = await api.post("/api-keys", {
        name: newKeyName || `Clave ${new Date().toLocaleDateString()}`,
      });
      setNewKeyData(response.data);
      toast.success("Nueva API Key creada");
      setShowNewKeyDialog(false);
      setNewKeyName("");
      fetchKeys();
    } catch (error: any) {
      const errorMsg = error.response?.data?.detail || "Error creando API Key";
      toast.error(errorMsg);
    }
  };

  const copyNewKey = async () => {
    if (newKeyData?.api_key) {
      try {
        await navigator.clipboard.writeText(newKeyData.api_key);
        toast.success("API key copiada al portapapeles");
        setNewKeyData(null);
      } catch (err) {
        toast.error("Error al copiar al portapapeles");
      }
    }
  };

  const revokeKey = async (keyHash: string) => {
    if (!window.confirm("¿Estás seguro de que quieres revocar esta clave?")) return;
    try {
      await api.delete(`/api-keys/${keyHash}/revoke`);
      toast.success("Clave revocada correctamente");
      fetchKeys();
    } catch (error: any) {
      const errorMsg = error.response?.data?.detail || "Error al revocar la clave";
      toast.error(errorMsg);
    }
  };

  useEffect(() => {
    fetchKeys();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-start">
        <div>
          <h1 className="text-3xl font-bold text-slate-900">Gestión de Claves API</h1>
          <p className="text-slate-600 mt-2">
            Crea y administra tus claves API
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={fetchKeys} disabled={loading} className="btn-secondary">
            <ArrowPathIcon className={`w-4 h-4 inline mr-2 ${loading ? 'animate-spin' : ''}`} />
            Actualizar
          </button>
          <button
            onClick={() => setShowNewKeyDialog(true)}
            className="btn-primary"
          >
            <PlusIcon className="w-4 h-4 inline mr-2" />
            Nueva API Key
          </button>
        </div>
      </div>

      {/* Info */}
      <div className="card p-4 bg-blue-50 border-blue-200">
        <p className="text-sm text-slate-700">
          Cada clave API tiene los mismos permisos y plan que tu cuenta. Puedes crear múltiples claves para diferentes entornos.
        </p>
      </div>

      {/* Dialog - Nueva Clave */}
      {showNewKeyDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="card max-w-md w-full p-6 space-y-4">
            <h2 className="text-xl font-bold">Crear nueva API Key</h2>
            <input
              type="text"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              placeholder="Ej: Producción, Testing, etc."
              className="input-field"
              onKeyPress={(e) => e.key === "Enter" && createNewKey()}
            />
            <div className="flex gap-2">
              <button
                onClick={() => setShowNewKeyDialog(false)}
                className="btn-secondary flex-1"
              >
                Cancelar
              </button>
              <button
                onClick={createNewKey}
                className="btn-primary flex-1"
              >
                Crear
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Dialog - Nueva Clave Creada */}
      {newKeyData && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="card max-w-md w-full p-6 space-y-4">
            <h2 className="text-xl font-bold text-green-600">¡Nueva API Key creada!</h2>
            <p className="text-sm text-slate-600">
              Guarda esta clave en un lugar seguro. No se volverá a mostrar.
            </p>
            <div className="bg-slate-900 p-4 rounded-lg">
              <p className="text-xs text-slate-400 mb-2">API KEY</p>
              <p className="text-xs text-slate-100 font-mono break-all">{newKeyData?.api_key}</p>
            </div>
            <p className="text-xs text-slate-600">
              Plan: {newKeyData?.plan} • Creada: {new Date(newKeyData?.created_at).toLocaleDateString()}
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setNewKeyData(null)}
                className="btn-secondary flex-1"
              >
                Cerrar
              </button>
              <button
                onClick={copyNewKey}
                className="btn-primary flex-1"
              >
                <DocumentDuplicateIcon className="w-4 h-4 inline mr-2" />
                Copiar
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Keys List */}
      <div className="space-y-4">
        {loading ? (
          <div className="text-center py-8">
            <div className="inline-flex items-center justify-center w-8 h-8 border-4 border-primary-200 border-t-primary-600 rounded-full animate-spin" />
          </div>
        ) : keys.length === 0 ? (
          <div className="card p-8 text-center">
            <KeyIcon className="w-12 h-12 text-slate-300 mx-auto mb-4" />
            <p className="text-lg font-semibold text-slate-900">No tienes claves API</p>
            <p className="text-slate-600 mt-1">
              Crea tu primera clave API para empezar a usar el servicio.
            </p>
          </div>
        ) : (
          keys.map((key) => (
            <div key={key.id} className="card p-6">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h3 className="font-semibold text-slate-900">{key.name}</h3>
                  <p className="text-xs text-slate-600">
                    Creada el {new Date(key.created_at).toLocaleDateString()}
                  </p>
                </div>
                {key.revoked && (
                  <span className="badge-danger">Revocada</span>
                )}
              </div>

              <div className="flex flex-wrap gap-2 mb-4">
                {key.scopes?.map((scope) => (
                  <span key={scope} className="badge-primary">
                    {scope}
                  </span>
                )) || (
                  <p className="text-xs text-slate-600">No hay permisos definidos</p>
                )}
              </div>

              <button
                onClick={() => revokeKey(key.key_hash)}
                disabled={key.revoked}
                className="btn-outline text-red-600 hover:bg-red-50"
              >
                <TrashIcon className="w-4 h-4 inline mr-2" />
                Revocar
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default APIKeysPage;
