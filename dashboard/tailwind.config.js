/** @type {import('tailwindcss').Config} */
export default {
    content: [
      "./index.html",
      "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
      extend: {
        colors: {
          primary: {
            50: '#f0f9ff',
            100: '#e0f2fe',
            200: '#bae6fd',
            300: '#7dd3fc',
            400: '#38bdf8',
            500: '#0ea5e9',
            600: '#0284c7',
            700: '#0369a1',
            800: '#075985',
            900: '#0c3d66',
          },
          accent: {
            50: '#f3e8ff',
            100: '#e9d5ff',
            200: '#d8b4fe',
            300: '#c084fc',
            400: '#a855f7',
            500: '#9333ea',
            600: '#7e22ce',
            700: '#6b21a8',
            800: '#581c87',
            900: '#3f0f5c',
          },
        },
        fontFamily: {
          sans: ['Inter', 'system-ui', 'sans-serif'],
        },
        boxShadow: {
          'glass': '0 8px 32px rgba(31, 38, 135, 0.37)',
          'soft': '0 4px 6px rgba(0, 0, 0, 0.05)',
          'medium': '0 10px 25px rgba(0, 0, 0, 0.1)',
        },
        backdropBlur: {
          'glass': '10px',
        },
      },
    },
    plugins: [],
  }
  