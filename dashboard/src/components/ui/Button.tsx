/**
 * Componente de botón reutilizable con estados de carga
 */

import { memo, type ButtonHTMLAttributes, type ReactNode } from 'react';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  isLoading?: boolean;
  loadingText?: string;
  children: ReactNode;
  variant?: 'primary' | 'secondary';
  fullWidth?: boolean;
}

const LoadingSpinner = memo(() => (
  <svg 
    className="animate-spin h-5 w-5" 
    xmlns="http://www.w3.org/2000/svg" 
    fill="none" 
    viewBox="0 0 24 24"
    aria-hidden="true"
  >
    <circle 
      className="opacity-25" 
      cx="12" 
      cy="12" 
      r="10" 
      stroke="currentColor" 
      strokeWidth="4" 
    />
    <path 
      className="opacity-75" 
      fill="currentColor" 
      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" 
    />
  </svg>
));

LoadingSpinner.displayName = 'LoadingSpinner';

/**
 * Botón personalizado con estado de carga
 */
export const Button = memo<ButtonProps>(({
  isLoading = false,
  loadingText,
  children,
  variant = 'primary',
  fullWidth = false,
  disabled,
  className = '',
  type = 'button',
  ...props
}) => {
  const baseStyles = `
    flex justify-center items-center gap-2 py-2 px-4 
    border border-transparent rounded-lg shadow-sm 
    text-sm font-medium transition
    focus:outline-none focus:ring-2 focus:ring-offset-2
    disabled:opacity-50 disabled:cursor-not-allowed
  `.trim().replace(/\s+/g, ' ');

  const variantStyles = variant === 'primary'
    ? 'text-white bg-indigo-600 hover:bg-indigo-700 focus:ring-indigo-500'
    : 'text-indigo-700 bg-indigo-100 hover:bg-indigo-200 focus:ring-indigo-500';

  const widthStyles = fullWidth ? 'w-full' : '';

  const isDisabled = disabled || isLoading;

  return (
    <button
      type={type}
      disabled={isDisabled}
      className={`${baseStyles} ${variantStyles} ${widthStyles} ${className}`.trim()}
      aria-busy={isLoading}
      {...props}
    >
      {isLoading ? (
        <>
          <LoadingSpinner />
          {loadingText && <span>{loadingText}</span>}
        </>
      ) : (
        children
      )}
    </button>
  );
});

Button.displayName = 'Button';