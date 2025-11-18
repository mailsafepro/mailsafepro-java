import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import toast from "react-hot-toast";
import api from "../services/api";
import { useAuth } from "../contexts/AuthContext";
import { EnvelopeIcon, LockClosedIcon, ExclamationCircleIcon, EyeIcon, EyeSlashIcon } from "@heroicons/react/24/solid";

interface ValidationErrors {
  email?: string;
  password?: string;
  confirmPassword?: string;
  [key: string]: string | undefined;
}

const RegisterPage = () => {
  const [loading, setLoading] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [errors, setErrors] = useState<ValidationErrors>({});
  const navigate = useNavigate();
  const { login } = useAuth();

  const validateEmail = (emailValue: string): boolean => {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailValue);
  };

  const validatePassword = (pwd: string): string | null => {
    if (!pwd) {
      return "La contraseña es requerida";
    }
    if (pwd.length < 8) {
      return "La contraseña debe tener al menos 8 caracteres";
    }
    if (pwd.length > 128) {
      return "La contraseña no puede exceder 128 caracteres";
    }
    if (!/[a-z]/.test(pwd)) {
      return "La contraseña debe contener al menos una letra minúscula";
    }
    if (!/[A-Z]/.test(pwd)) {
      return "La contraseña debe contener al menos una letra mayúscula";
    }
    if (!/\d/.test(pwd)) {
      return "La contraseña debe contener al menos un número";
    }
    return null;
  };

  const validateForm = (): boolean => {
    const newErrors: ValidationErrors = {};

    if (!email.trim()) {
      newErrors.email = "El email es requerido";
    } else if (!validateEmail(email)) {
      newErrors.email = "Por favor ingresa un email válido";
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
      newErrors.password = passwordError;
    }

    if (!confirmPassword) {
      newErrors.confirmPassword = "Debes confirmar tu contraseña";
    } else if (password !== confirmPassword) {
      newErrors.confirmPassword = "Las contraseñas no coinciden";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setLoading(true);

    try {
      const response = await api.post("/auth/register", {
        email: email.trim().toLowerCase(),
        password,
      });

      const { access_token, refresh_token } = response.data;

      sessionStorage.setItem("token", access_token);
      sessionStorage.setItem("refresh_token", refresh_token);

      await login(email.trim().toLowerCase(), password);
      toast.success("¡Registro exitoso! Bienvenido/a.");
      navigate("/dashboard");
    } catch (err: any) {
      const newErrors: ValidationErrors = {};
      let generalError = "Error desconocido en el registro";

      // Manejo de errores de validación de Pydantic (422)
      if (err.response?.status === 422 && err.response?.data?.errors) {
        const apiErrors = err.response.data.errors;

        apiErrors.forEach((error: any) => {
          const field = error.field?.split(".").pop() || "general";
          const message = error.message || error.detail || "Error de validación";

          if (field === "email") {
            newErrors.email = message;
          } else if (field === "password") {
            newErrors.password = message;
          } else {
            generalError = message;
          }
        });

        if (Object.keys(newErrors).length > 0) {
          setErrors(newErrors);
        } else {
          toast.error(generalError);
        }
      }
      // Otros errores HTTP
      else if (err.response?.data?.detail) {
        const detail = err.response.data.detail;

        if (typeof detail === "string") {
          generalError = detail;
        } else if (typeof detail === "object") {
          if (detail.error) {
            generalError = detail.error;

            if (detail.retry_after) {
              generalError += ` Reintentar en ${detail.retry_after}s`;
            }
          }

          if (detail.email) {
            newErrors.email = detail.email;
          }

          if (detail.password) {
            newErrors.password = detail.password;
          }
        }
      } else if (err.response?.status === 409) {
        newErrors.email = "Este email ya está registrado. Intenta con otro o inicia sesión";
      } else if (err.response?.status === 429) {
        generalError = "Demasiados intentos. Por favor intenta más tarde";
      } else if (err.response?.status === 500) {
        generalError = "Error del servidor. Por favor intenta más tarde";
      } else if (err.message === "Network Error") {
        generalError = "Error de conexión. Verifica tu conexión a internet";
      }

      if (Object.keys(newErrors).length > 0) {
        setErrors(newErrors);
      } else {
        toast.error(generalError);
      }

      console.error("Register error:", err.response?.data || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center px-4 py-12 sm:px-6 lg:px-8">
      <div className="w-full max-w-md space-y-8">
        <div className="text-center">
          <h1 className="mt-6 text-3xl font-bold tracking-tight text-gray-900">
            Crea tu cuenta
          </h1>
          <p className="mt-2 text-sm text-gray-600">
            Únete a nuestra plataforma de validación de emails
          </p>
        </div>

        <form className="mt-8 space-y-6 bg-white rounded-lg shadow-md p-8" onSubmit={handleRegister}>
          <div className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                Email
              </label>
              <div className="mt-1 relative">
                <EnvelopeIcon className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    if (errors.email) setErrors({ ...errors, email: undefined });
                  }}
                  placeholder="tu@ejemplo.com"
                  className={`block w-full pl-10 pr-4 py-2 border rounded-lg shadow-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none transition ${
                    errors.email ? "border-red-500 focus:ring-red-500" : "border-gray-300"
                  }`}
                  disabled={loading}
                />
              </div>
              {errors.email && (
                <p className="mt-1 text-sm text-red-600 flex items-center gap-1">
                  <ExclamationCircleIcon className="h-4 w-4" />
                  {errors.email}
                </p>
              )}
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                Contraseña
              </label>
              <div className="mt-1 relative">
                <LockClosedIcon className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (errors.password) setErrors({ ...errors, password: undefined });
                  }}
                  placeholder="••••••••"
                  className={`block w-full pl-10 pr-10 py-2 border rounded-lg shadow-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none transition ${
                    errors.password ? "border-red-500 focus:ring-red-500" : "border-gray-300"
                  }`}
                  disabled={loading}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3 text-gray-400 hover:text-gray-600 disabled:opacity-50"
                  disabled={loading}
                  aria-label={showPassword ? "Ocultar contraseña" : "Mostrar contraseña"}
                >
                  {showPassword ? (
                    <EyeSlashIcon className="h-5 w-5" />
                  ) : (
                    <EyeIcon className="h-5 w-5" />
                  )}
                </button>
              </div>
              {errors.password && (
                <p className="mt-1 text-sm text-red-600 flex items-center gap-1">
                  <ExclamationCircleIcon className="h-4 w-4" />
                  {errors.password}
                </p>
              )}
              <p className="mt-2 text-xs text-gray-500">
                Mínimo 8 caracteres. Incluye mayúscula, minúscula y número
              </p>
            </div>

            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700">
                Confirmar contraseña
              </label>
              <div className="mt-1 relative">
                <LockClosedIcon className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
                <input
                  id="confirmPassword"
                  type={showConfirmPassword ? "text" : "password"}
                  value={confirmPassword}
                  onChange={(e) => {
                    setConfirmPassword(e.target.value);
                    if (errors.confirmPassword) setErrors({ ...errors, confirmPassword: undefined });
                  }}
                  placeholder="••••••••"
                  className={`block w-full pl-10 pr-10 py-2 border rounded-lg shadow-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none transition ${
                    errors.confirmPassword ? "border-red-500 focus:ring-red-500" : "border-gray-300"
                  }`}
                  disabled={loading}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-3 text-gray-400 hover:text-gray-600 disabled:opacity-50"
                  disabled={loading}
                  aria-label={showConfirmPassword ? "Ocultar contraseña" : "Mostrar contraseña"}
                >
                  {showConfirmPassword ? (
                    <EyeSlashIcon className="h-5 w-5" />
                  ) : (
                    <EyeIcon className="h-5 w-5" />
                  )}
                </button>
              </div>
              {errors.confirmPassword && (
                <p className="mt-1 text-sm text-red-600 flex items-center gap-1">
                  <ExclamationCircleIcon className="h-4 w-4" />
                  {errors.confirmPassword}
                </p>
              )}
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed transition"
          >
            {loading ? (
              <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
            ) : (
              "Crear cuenta"
            )}
          </button>
        </form>

        <p className="text-center text-sm text-gray-600">
          ¿Ya tienes una cuenta?{" "}
          <Link to="/login" className="font-medium text-indigo-600 hover:text-indigo-500">
            Inicia sesión
          </Link>
        </p>
      </div>
    </div>
  );
};

export default RegisterPage;
