/**
 * Overlay para cerrar sidebar en mobile
 */

import { memo } from 'react';

interface MobileOverlayProps {
  isVisible: boolean;
  onClose: () => void;
}

/**
 * Overlay oscuro para mobile cuando el sidebar está abierto
 */
export const MobileOverlay = memo<MobileOverlayProps>(({ isVisible, onClose }) => {
  if (!isVisible) {
    return null;
  }

  return (
    <div
      className="fixed inset-0 bg-black/50 z-30 md:hidden"
      onClick={onClose}
      role="button"
      tabIndex={0}
      aria-label="Cerrar menú"
      onKeyDown={(e) => {
        if (e.key === 'Escape') {
          onClose();
        }
      }}
    />
  );
});

MobileOverlay.displayName = 'MobileOverlay';

