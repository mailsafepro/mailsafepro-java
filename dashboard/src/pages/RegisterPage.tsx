import { memo } from 'react';
import { Link } from 'react-router-dom';
import { 
  EnvelopeIcon, 
  LockClosedIcon, 
  EyeIcon, 
  EyeSlashIcon 
} from '@heroicons/react/24/solid';
import { useRegisterForm } from '../hooks/useRegisterForm';
import Input from '../components/ui/Input';
import { Button } from '../components/ui/Button';
import { PasswordRequirements } from '../components/auth/PasswordRequirements';

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
 * Encabezado de la página de registro
 */
const RegisterHeader = memo(() => (
  <div className="text-center">
    <h1 className="mt-6 text-3xl font-bold tracking-tight text-gray-900">
      Crea tu cuenta
    </h1>
    <p className="mt-2 text-sm text-gray-600">
      Únete a nuestra plataforma de validación de emails
    </p>
  </div>
));

RegisterHeader.displayName = 'RegisterHeader';

/**
 * Footer con enlace de inicio de sesión
 */
const RegisterFooter = memo(() => (
  <p className="text-center text-sm text-gray-600">
    ¿Ya tienes una cuenta?{' '}
    <Link 
      to="/login" 
      className="font-medium text-indigo-600 hover:text-indigo-500 transition"
    >
      Inicia sesión
    </Link>
  </p>
));

RegisterFooter.displayName = 'RegisterFooter';

/**
 * Página de registro para MailSafePro
 * Incluye validación robusta de contraseñas con confirmación y requisitos de seguridad
 */
const RegisterPage = () => {
  const {
    email,
    password,
    confirmPassword,
    showPassword,
    showConfirmPassword,
    errors,
    isLoading,
    setEmail,
    setPassword,
    setConfirmPassword,
    togglePasswordVisibility,
    toggleConfirmPasswordVisibility,
    handleSubmit,
  } = useRegisterForm();

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center px-4 py-12 sm:px-6 lg:px-8">
      <div className="w-full max-w-md space-y-8">
        <RegisterHeader />

        <form
          className="mt-8 space-y-6 bg-white rounded-lg shadow-md p-8"
          onSubmit={handleSubmit}
          noValidate
          aria-label="Formulario de registro"
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

            <div>
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
                autoComplete="new-password"
                required
              />
              <PasswordRequirements password={password} show={password.length > 0} />
            </div>

            <Input
              id="confirmPassword"
              type={showConfirmPassword ? 'text' : 'password'}
              label="Confirmar contraseña"
              value={confirmPassword}
              onChange={setConfirmPassword}
              placeholder="••••••••"
              error={errors.confirmPassword}
              icon={<LockClosedIcon className="h-5 w-5 text-gray-400" />}
              endIcon={
                <PasswordToggleButton
                  showPassword={showConfirmPassword}
                  onToggle={toggleConfirmPasswordVisibility}
                  disabled={isLoading}
                />
              }
              disabled={isLoading}
              autoComplete="new-password"
              required
            />
          </div>

          <Button
            type="submit"
            isLoading={isLoading}
            fullWidth
            variant="primary"
          >
            Crear cuenta
          </Button>
        </form>

        <RegisterFooter />
      </div>
    </div>
  );
};

export default memo(RegisterPage);
