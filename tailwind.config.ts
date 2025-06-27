import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // Business Theme Colors
        business: {
          gold: {
            50: '#fffbeb',
            100: '#fef3c7',
            200: '#fde68a',
            300: '#fcd34d',
            400: '#fbbf24',
            500: '#ffc451', // Primary golden yellow
            600: '#f59e0b',
            700: '#d97706',
            800: '#92400e',
            900: '#78350f',
            950: '#451a03',
          },
          black: {
            50: '#f8fafc',
            100: '#f1f5f9',
            200: '#e2e8f0',
            300: '#cbd5e1',
            400: '#94a3b8',
            500: '#64748b',
            600: '#475569',
            700: '#334155',
            800: '#1e293b',
            900: '#0f172a',
            950: '#020617',
          }
        },
        
        // System Colors using CSS Variables
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))'
        },
        
        popover: {
          DEFAULT: 'hsl(var(--popover))',
          foreground: 'hsl(var(--popover-foreground))'
        },
        
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
          50: '#fffbeb',
          100: '#fef3c7',
          200: '#fde68a',
          300: '#fcd34d',
          400: '#fbbf24',
          500: '#ffc451',
          600: '#f59e0b',
          700: '#d97706',
          800: '#92400e',
          900: '#78350f',
        },
        
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))'
        },
        
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))'
        },
        
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))'
        },
        
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))'
        },
        
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        
        chart: {
          '1': 'hsl(var(--chart-1))',
          '2': 'hsl(var(--chart-2))',
          '3': 'hsl(var(--chart-3))',
          '4': 'hsl(var(--chart-4))',
          '5': 'hsl(var(--chart-5))'
        }
      },
      
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-conic': 'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
        'business-gold': 'linear-gradient(135deg, #ffc451 0%, #f7b731 100%)',
        'business-dark': 'linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%)',
        'business-premium': 'linear-gradient(135deg, #000000 0%, #1a1a1a 50%, #000000 100%)',
        'business-surface': 'linear-gradient(135deg, #ffffff 0%, #fafafa 100%)',
      },
      
      boxShadow: {
        'business-sm': '0 1px 2px 0 rgba(255, 196, 81, 0.05)',
        'business': '0 4px 6px -1px rgba(255, 196, 81, 0.1), 0 2px 4px -1px rgba(255, 196, 81, 0.06)',
        'business-md': '0 10px 15px -3px rgba(255, 196, 81, 0.1), 0 4px 6px -2px rgba(255, 196, 81, 0.05)',
        'business-lg': '0 20px 25px -5px rgba(255, 196, 81, 0.1), 0 10px 10px -5px rgba(255, 196, 81, 0.04)',
        'business-xl': '0 25px 50px -12px rgba(255, 196, 81, 0.25)',
        'business-2xl': '0 50px 100px -20px rgba(255, 196, 81, 0.25)',
        'business-inner': 'inset 0 2px 4px 0 rgba(255, 196, 81, 0.06)',
        'premium': '0 25px 50px -12px rgba(0, 0, 0, 0.25), 0 0 30px rgba(255, 196, 81, 0.1)',
      },
      
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      
      container: {
        center: true,
        padding: {
          DEFAULT: '1rem',
          sm: '2rem',
          lg: '4rem',
          xl: '5rem',
          '2xl': '6rem',
        },
        screens: {
          sm: '640px',
          md: '768px',
          lg: '1024px',
          xl: '1280px',
          '2xl': '1536px',
        },
      },
      
      animation: {
        'fade-in': 'fadeIn 0.5s ease-in-out',
        'fade-up': 'fadeUp 0.5s ease-out',
        'slide-in': 'slideIn 0.3s ease-out',
        'bounce-gentle': 'bounceGentle 2s infinite',
        'pulse-gold': 'pulseGold 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'shimmer': 'shimmer 2s linear infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        fadeUp: {
          '0%': { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideIn: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(0)' },
        },
        bounceGentle: {
          '0%, 100%': { transform: 'translateY(-5%)' },
          '50%': { transform: 'translateY(0)' },
        },
        pulseGold: {
          '0%, 100%': { boxShadow: '0 0 0 0 rgba(255, 196, 81, 0.4)' },
          '70%': { boxShadow: '0 0 0 10px rgba(255, 196, 81, 0)' },
        },
        shimmer: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(255, 196, 81, 0.2), 0 0 10px rgba(255, 196, 81, 0.2), 0 0 15px rgba(255, 196, 81, 0.2)' },
          '100%': { boxShadow: '0 0 10px rgba(255, 196, 81, 0.4), 0 0 20px rgba(255, 196, 81, 0.4), 0 0 30px rgba(255, 196, 81, 0.4)' },
        },
      },
      
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        heading: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      
      fontSize: {
        'xs': ['0.75rem', { lineHeight: '1rem' }],
        'sm': ['0.875rem', { lineHeight: '1.25rem' }],
        'base': ['1rem', { lineHeight: '1.5rem' }],
        'lg': ['1.125rem', { lineHeight: '1.75rem' }],
        'xl': ['1.25rem', { lineHeight: '1.75rem' }],
        '2xl': ['1.5rem', { lineHeight: '2rem' }],
        '3xl': ['1.875rem', { lineHeight: '2.25rem' }],
        '4xl': ['2.25rem', { lineHeight: '2.5rem' }],
        '5xl': ['3rem', { lineHeight: '1' }],
        '6xl': ['3.75rem', { lineHeight: '1' }],
        '7xl': ['4.5rem', { lineHeight: '1' }],
        '8xl': ['6rem', { lineHeight: '1' }],
        '9xl': ['8rem', { lineHeight: '1' }],
      },
      
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
        '128': '32rem',
      },
      
      maxWidth: {
        '8xl': '88rem',
        '9xl': '96rem',
      },
      
      backdropBlur: {
        xs: '2px',
      },
      
      transitionTimingFunction: {
        'bounce-in': 'cubic-bezier(0.68, -0.55, 0.265, 1.55)',
        'smooth': 'cubic-bezier(0.4, 0, 0.2, 1)',
      },
    },
  },
  plugins: [
    require("tailwindcss-animate"),
  ],
} satisfies Config;