export default {
  plugins: {
    tailwindcss: {}, // This activates the JIT compiler by default in modern Tailwind, no need for 'unsafe-inline' in csp style-src
    autoprefixer: {},
  },
}
