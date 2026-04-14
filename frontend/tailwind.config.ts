import type { Config } from 'tailwindcss'

const config: Config = {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // nyx-* palette is driven by CSS custom properties in index.css so the
        // same utility classes flip between dark (default) and light themes.
        nyx: {
          void:      'rgb(var(--nyx-void) / <alpha-value>)',
          midnight:  'rgb(var(--nyx-midnight) / <alpha-value>)',
          dusk:      'rgb(var(--nyx-dusk) / <alpha-value>)',
          twilight:  'rgb(var(--nyx-twilight) / <alpha-value>)',
          iris:      'rgb(var(--nyx-iris) / <alpha-value>)',
          amethyst:  'rgb(var(--nyx-amethyst) / <alpha-value>)',
          lavender:  'rgb(var(--nyx-lavender) / <alpha-value>)',
          moonbeam:  'rgb(var(--nyx-moonbeam) / <alpha-value>)',
          stardust:  'rgb(var(--nyx-stardust) / <alpha-value>)',
          nebula:    'rgb(var(--nyx-nebula) / <alpha-value>)',
          mist:      'rgb(var(--nyx-mist) / <alpha-value>)',
          eclipse:   'rgb(var(--nyx-eclipse) / <alpha-value>)',
        },
        severity: {
          critical: '#ef4444',
          high:     '#f97316',
          medium:   '#eab308',
          low:      '#22c55e',
          info:     '#64748b',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Menlo', 'monospace'],
      },
      backgroundImage: {
        'nyx-gradient': 'linear-gradient(135deg, #08080f 0%, #141428 50%, #08080f 100%)',
        'card-gradient': 'linear-gradient(135deg, #0d0d1a 0%, #141428 100%)',
      },
      boxShadow: {
        'nyx': '0 0 0 1px rgba(124, 58, 237, 0.2), 0 4px 24px rgba(0, 0, 0, 0.4)',
        'nyx-glow': '0 0 20px rgba(139, 92, 246, 0.3)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'shimmer': 'shimmer 2s linear infinite',
      },
      keyframes: {
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
      },
    },
  },
  plugins: [],
}

export default config
