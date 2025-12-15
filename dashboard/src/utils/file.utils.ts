/**
 * Utilidades para manejo de archivos
 */

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const ACCEPTED_EXTENSIONS = ['.csv', '.txt', '.zip'];

/**
 * Valida el tamaño de un archivo
 * @param file - Archivo a validar
 * @param maxSize - Tamaño máximo en bytes
 * @returns true si el tamaño es válido
 */
export const isValidFileSize = (file: File, maxSize: number = MAX_FILE_SIZE): boolean => {
  return file.size <= maxSize;
};

/**
 * Valida la extensión de un archivo
 * @param file - Archivo a validar
 * @param acceptedExtensions - Extensiones permitidas
 * @returns true si la extensión es válida
 */
export const isValidFileExtension = (
  file: File,
  acceptedExtensions: string[] = ACCEPTED_EXTENSIONS
): boolean => {
  const fileName = file.name.toLowerCase();
  return acceptedExtensions.some((ext) => fileName.endsWith(ext));
};

/**
 * Formatea el tamaño de un archivo en MB
 * @param bytes - Tamaño en bytes
 * @returns Tamaño formateado con 2 decimales
 */
export const formatFileSize = (bytes: number): string => {
  return (bytes / 1024 / 1024).toFixed(2);
};

/**
 * Valida un archivo completo
 * @param file - Archivo a validar
 * @returns Mensaje de error o undefined si es válido
 */
export const validateFile = (file: File): string | undefined => {
  if (!isValidFileSize(file)) {
    return 'El archivo no puede exceder 5MB';
  }

  if (!isValidFileExtension(file)) {
    return 'Formato de archivo no válido. Usa CSV, TXT o ZIP';
  }

  return undefined;
};