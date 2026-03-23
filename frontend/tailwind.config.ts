import type { Config } from 'tailwindcss'

const config: Config = {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        nyx: {
          void:      '#08080f',   // Deepest background
          midnight:  '#0d0d1a',   // Card backgrounds
          dusk:      '#141428',   // Sidebar
          twilight:  '#1a1a35',   // Hover states
          iris:      '#7c3aed',   // Primary purple (violet-700)
          amethyst:  '#8b5cf6',   // Interactive (violet-500)
          lavender:  '#a78bfa',   // Muted accent (violet-400)
          moonbeam:  '#ede9fe',   // Primary text (violet-50)
          stardust:  '#6366f1',   // Info / links (indigo-500)
          nebula:    '#4f46e5',   // Pressed state
          mist:      '#c4b5fd',   // Subtext
          eclipse:   '#2d1b69',   // Selected state bg
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
