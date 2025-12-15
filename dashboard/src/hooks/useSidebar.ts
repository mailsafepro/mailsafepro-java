/**
 * Custom hook para manejo del sidebar
 */

import { useState, useCallback } from 'react';

interface UseSidebarReturn {
  isOpen: boolean;
  open: () => void;
  close: () => void;
  toggle: () => void;
}

/**
 * Hook para gestionar el estado del sidebar
 * @returns Estado y funciones del sidebar
 */
export const useSidebar = (): UseSidebarReturn => {
  const [isOpen, setIsOpen] = useState(false);

  const open = useCallback(() => setIsOpen(true), []);
  const close = useCallback(() => setIsOpen(false), []);
  const toggle = useCallback(() => setIsOpen(prev => !prev), []);

  return {
    isOpen,
    open,
    close,
    toggle,
  };
};
