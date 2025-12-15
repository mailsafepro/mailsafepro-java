import { memo } from 'react';
import { useEmailValidation } from '../hooks/useEmailValidation';
import Input from '../components/ui/Input';
import { Button } from '../components/ui/Button';
import { Checkbox } from '../components/ui/Checkbox';
import { ValidationResultCard } from '../components/validation/ValidationResultCard';

/**
 * Encabezado de la página de validación
 */
const ValidateHeader = memo(() => (
  <div className="text-center">
    <h1 className="text-4xl font-bold tracking-tight text-gray-900">
      Valida un Email
    </h1>
    <p className="mt-4 text-lg text-gray-600">
      Verifica si una dirección de email es válida y segura
    </p>
  </div>
));

ValidateHeader.displayName = 'ValidateHeader';

/**
 * Página de validación de emails para MailSafePro
 * Incluye opciones avanzadas de validación SMTP y DNS
 */
const ValidatePage = () => {
  const {
    email,
    checkSmtp,
    includeRawDns,
    result,
    showDetails,
    isLoading,
    setEmail,
    setCheckSmtp,
    setIncludeRawDns,
    toggleDetails,
    handleValidate,
  } = useEmailValidation();

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto space-y-8">
        <ValidateHeader />

        {/* Formulario */}
        <form
          onSubmit={handleValidate}
          className="bg-white rounded-lg shadow-md p-8 space-y-6"
          noValidate
          aria-label="Formulario de validación de email"
        >
          <Input
            id="email"
            type="email"
            label="Email a validar"
            value={email}
            onChange={setEmail}
            placeholder="ejemplo@email.com"
            disabled={isLoading}
            autoComplete="email"
            required
          />

          <div className="space-y-3" role="group" aria-label="Opciones de validación">
            <Checkbox
              id="check-smtp"
              label="Verificar buzón de correo (SMTP)"
              helpText="Solo PREMIUM"
              checked={checkSmtp}
              onChange={setCheckSmtp}
              disabled={isLoading}
            />

            <Checkbox
              id="include-raw-dns"
              label="Incluir registros DNS completos"
              helpText="Solo PREMIUM"
              checked={includeRawDns}
              onChange={setIncludeRawDns}
              disabled={isLoading}
            />
          </div>

          <Button
            type="submit"
            isLoading={isLoading}
            fullWidth
            variant="primary"
          >
            Validar Email
          </Button>
        </form>

        {/* Resultado */}
        {result && (
          <ValidationResultCard
            result={result}
            showDetails={showDetails}
            onToggleDetails={toggleDetails}
          />
        )}
      </div>
    </div>
  );
};

export default memo(ValidatePage);
