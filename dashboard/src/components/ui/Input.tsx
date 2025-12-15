/**
 * Componente de input reutilizable con iconos y validación
 */

import { memo, type InputHTMLAttributes, type ReactNode } from 'react';
import { ExclamationCircleIcon } from '@heroicons/react/24/solid';

interface InputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'onChange'> {
  label: string;
  error?: string;
  icon?: ReactNode;
  endIcon?: ReactNode;
  onChange: (value: string) => void;
}

const Input = memo<InputProps>(({
  label,
  error,
  icon,
  endIcon,
  onChange,
  id,
  className = '',
  disabled,
  ...props
}) => {
  const inputId = id || label.toLowerCase().replace(/\s+/g, '-');
  const hasError = Boolean(error);

  return (
    <div>
      <label 
        htmlFor={inputId} 
        className="block text-sm font-medium text-gray-700"
      >
        {label}
      </label>
      <div className="mt-1 relative">
        {icon && (
          <div className="absolute left-3 top-3 pointer-events-none" aria-hidden="true">
            {icon}
          </div>
        )}
        <input
          id={inputId}
          onChange={(e) => onChange(e.target.value)}
          className={`
            block w-full py-2 border rounded-lg shadow-sm 
            focus:ring-2 focus:ring-indigo-500 focus:border-transparent 
            outline-none transition
            disabled:opacity-50 disabled:cursor-not-allowed disabled:bg-gray-50
            ${icon ? 'pl-10' : 'pl-4'}
            ${endIcon ? 'pr-10' : 'pr-4'}
            ${hasError 
              ? 'border-red-500 focus:ring-red-500' 
              : 'border-gray-300'
            }
            ${className}
          `.trim().replace(/\s+/g, ' ')}
          disabled={disabled}
          aria-invalid={hasError}
          aria-describedby={hasError ? `${inputId}-error` : undefined}
          {...props}
        />
        {endIcon && (
          <div className="absolute right-3 top-3">
            {endIcon}
          </div>
        )}
      </div>
      {hasError && (
        <p 
          id={`${inputId}-error`}
          className="mt-1 text-sm text-red-600 flex items-center gap-1"
          role="alert"
        >
          <ExclamationCircleIcon className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
          {error}
        </p>
      )}
    </div>
  );
});

Input.displayName = 'Input';

export default Input;

