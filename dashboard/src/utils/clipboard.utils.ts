/**
 * Utilidades para manejo del portapapeles
 */

/**
 * Copia texto al portapapeles
 * @param text - Texto a copiar
 * @returns Promise que resuelve cuando se copia exitosamente
 */
export const copyToClipboard = async (text: string): Promise<void> => {
    if (!navigator.clipboard) {
      throw new Error('Clipboard API no disponible');
    }
    
    await navigator.clipboard.writeText(text);
  };