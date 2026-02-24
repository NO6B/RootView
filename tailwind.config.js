/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/templates/**/*.html",
    "./app/**/*.py"
  ],
  theme: {
    extend: {
      colors: {
        rootdark: '#0f172a',
        panel: '#1e293b',
      }
    }
  },
  plugins: [],
}