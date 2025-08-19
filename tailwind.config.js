/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        'tiger-orange': 'hsl(var(--tiger-orange))',
        'tiger-orange-light': 'hsl(var(--tiger-orange-light))',
        'tiger-purple': 'hsl(var(--tiger-purple))',
        'tiger-blue': 'hsl(var(--tiger-blue))',
        'tiger-pink': 'hsl(var(--tiger-pink))',
      },
    },
  },
  plugins: [],
} 