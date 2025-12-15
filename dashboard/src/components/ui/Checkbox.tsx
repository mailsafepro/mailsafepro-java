/**
 * Componente de checkbox reutilizable
 */

import { memo, type InputHTMLAttributes } from 'react';

interface CheckboxProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type' | 'onChange'> {
  label: string;
  helpText?: string;
  onChange: (checked: boolean) => void;
}

/**
 * Checkbox personalizado con label y texto de ayuda opcional
 */
export const Checkbox = memo<CheckboxProps>(({
  label,
  helpText,
  onChange,
  checked,
  disabled,
  id,
  className = '',
  ...props
}) => {
  const checkboxId = id || label.toLowerCase().replace(/\s+/g, '-');

  return (
    <label
      htmlFor={checkboxId}
      className={`flex items-center gap-3 ${disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'}`}
    >
      <input
        id={checkboxId}
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        disabled={disabled}
        className={`w-4 h-4 text-indigo-600 rounded border-gray-300 focus:ring-2 focus:ring-indigo-500 disabled:cursor-not-allowed ${className}`}
        {...props}
      />
      <span className="text-sm text-gray-700">
        {label}
        {helpText && (
          <span className="text-xs text-gray-500 ml-1">({helpText})</span>
        )}
      </span>
    </label>
  );
});

Checkbox.displayName = 'Checkbox';