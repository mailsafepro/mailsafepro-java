import { memo } from 'react';
import { Link } from 'react-router-dom';
import { 
  EnvelopeIcon, 
  LockClosedIcon, 
  EyeIcon, 
  EyeSlashIcon 
} from '@heroicons/react/24/solid';
import { useLoginForm } from '../hooks/useLoginForm';
import Input from '../components/ui/Input';
import { Button } from '../components/ui/Button';

/**
 * Botón para alternar visibilidad de contraseña
 */
const PasswordToggleButton = memo<{
  showPassword: boolean;
  onToggle: () => void;
  disabled?: boolean;
}>(({ showPassword, onToggle, disabled }) => (
  <button
    type="button"
    onClick={onToggle}
    className="text-gray-400 hover:text-gray-600 disabled:opacity-50 transition"
    disabled={disabled}
    aria-label={showPassword ? 'Ocultar contraseña' : 'Mostrar contraseña'}
  >
    {showPassword ? (
      <EyeSlashIcon className="h-5 w-5" aria-hidden="true" />
    ) : (
      <EyeIcon className="h-5 w-5" aria-hidden="true" />
    )}
  </button>
));

PasswordToggleButton.displayName = 'PasswordToggleButton';

/**
 * Encabezado de la página de login
 */
const LoginHeader = memo(() => (
  <div className="text-center">
    <h1 className="mt-6 text-3xl font-bold tracking-tight text-gray-900">
      API de validación de emails
    </h1>
    <p className="mt-2 text-sm text-gray-600">
      Inicia sesión en tu cuenta
    </p>
  </div>
));

LoginHeader.displayName = 'LoginHeader';

/**
 * Footer con enlace de registro
 */
const LoginFooter = memo(() => (
  <p className="text-center text-sm text-gray-600">
    ¿No tienes una cuenta?{' '}
    <Link 
      to="/register" 
      className="font-medium text-indigo-600 hover:text-indigo-500 transition"
    >
      Regístrate aquí
    </Link>
  </p>
));

LoginFooter.displayName = 'LoginFooter';

/**
 * Página de inicio de sesión para MailSafePro
 * Incluye validación de email y contraseña con manejo completo de errores
 */
const LoginPage = () => {
  const {
    email,
    password,
    showPassword,
    errors,
    isLoading,
    setEmail,
    setPassword,
    togglePasswordVisibility,
    handleSubmit,
  } = useLoginForm();

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center px-4 py-12 sm:px-6 lg:px-8">
      <div className="w-full max-w-md space-y-8">
        <LoginHeader />

        <form 
          className="mt-8 space-y-6 bg-white rounded-lg shadow-md p-8" 
          onSubmit={handleSubmit}
          noValidate
          aria-label="Formulario de inicio de sesión"
        >
          <div className="space-y-4">
            <Input
              id="email"
              type="email"
              label="Email"
              value={email}
              onChange={setEmail}
              placeholder="tu@ejemplo.com"
              error={errors.email}
              icon={<EnvelopeIcon className="h-5 w-5 text-gray-400" />}
              disabled={isLoading}
              autoComplete="email"
              required
            />

            <Input
              id="password"
              type={showPassword ? 'text' : 'password'}
              label="Contraseña"
              value={password}
              onChange={setPassword}
              placeholder="••••••••"
              error={errors.password}
              icon={<LockClosedIcon className="h-5 w-5 text-gray-400" />}
              endIcon={
                <PasswordToggleButton
                  showPassword={showPassword}
                  onToggle={togglePasswordVisibility}
                  disabled={isLoading}
                />
              }
              disabled={isLoading}
              autoComplete="current-password"
              required
            />
          </div>

          <Button
            type="submit"
            isLoading={isLoading}
            fullWidth
            variant="primary"
          >
            Iniciar sesión
          </Button>
        </form>

        <LoginFooter />
      </div>
    </div>
  );
};

export default memo(LoginPage);
