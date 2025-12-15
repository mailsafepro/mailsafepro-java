/**
 * Sección de preguntas frecuentes
 */

import { memo } from 'react';

interface FAQItem {
  question: string;
  answer: string;
}

const FAQ_ITEMS: FAQItem[] = [
  {
    question: '¿Puedo cambiar de plan?',
    answer: 'Sí, puedes cambiar de plan en cualquier momento. Los cambios se aplicarán el próximo ciclo de facturación.',
  },
  {
    question: '¿Qué pasa si excedo mi límite?',
    answer: 'Si usas más validaciones de las permitidas, tu API se pausará. Puedes actualizar tu plan para continuar.',
  },
  {
    question: '¿Hay contrato a largo plazo?',
    answer: 'No. Todos los planes son mensuales y puedes cancelar cuando quieras.',
  },
];

/**
 * Muestra las preguntas frecuentes sobre facturación
 */
export const FAQSection = memo(() => (
  <div className="space-y-4 pt-4">
    <h2 className="text-2xl font-bold text-gray-900">Preguntas Frecuentes</h2>

    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 space-y-4">
      {FAQ_ITEMS.map((item, index) => (
        <div key={index} className={index > 0 ? 'border-t border-gray-200 pt-4' : ''}>
          <h4 className="font-semibold text-gray-900 mb-2">{item.question}</h4>
          <p className="text-gray-600 text-sm">{item.answer}</p>
        </div>
      ))}
    </div>
  </div>
));

FAQSection.displayName = 'FAQSection';