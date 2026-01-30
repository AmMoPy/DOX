import { defineConfig, loadEnv } from 'vite';
import path from 'path';
import solidPlugin from 'vite-plugin-solid';
import { resolve } from 'path';

// if you only need to pass values from .env* files to the app, 
// you don't need to call anything in the config. however, if 
// values from .env* files must influence the config itself 
// you can load them manually using the exported loadEnv helper.
const rootDir = path.resolve(__dirname, '..');// absolute path of the parent directory

export default defineConfig(({ mode }) => {
  // Vite's behavior when loading environment files is layered. By default, 
  // regardless of the mode provided, it will always load the base .env file.
  // If you run in development mode (npm run dev), it tries to load .env.development.local, then .env.development, then finally .env.
  // In production mode (npm run build), it loads .env.production.local, then .env.production, then finally .env.
  const env = loadEnv(mode, rootDir, 'VITE_') // use '' in third argument to load non-prefixed variables (danger)

  return {
    plugins: [
      solidPlugin(),
    ],
    css: {
      postcss: './postcss.config.js',
    },
    server: {
      // vite.config.js operates in a Node.js JavaScript environment 
      // where environment variables are universally loaded as strings, 
      // you must explicitly convert them to the correct data type (type casting) 
      // if the configuration setting expects anything other than a string.
      // Examples:
      // true or false: Boolean -> env.VAR === 'true'
      // 8000: Number ->  Number(env.VAR) or +env.VAR
      // ["a", "b"]: Array/Object -> JSON.parse(env.VAR)
      // hello: String -> env.VAR      
      port: env.VITE_APP_PORT ? Number(env.VITE_APP_PORT) : 5173,
      open: false,
      // proxy is a development-only feature, intercepting calls from frontend 
      // (e.g.: //localhost:5173/api/users) and forwarding it to backend URL 
      // (e.g.: target/api/users) and vise versa. Direct JavaScript calls from one origin 
      // (frontend port: 5173) to another (backend port: 5000) are blocked by default 
      // (Same-Origin Policy) unless the backend is configured to allow CORS 
      // Thus, acting as a "middleman" between the two different servers bypassing 
      // Cross-Origin Resource Sharing (CORS) issues 
      proxy: {
        '/api': {
          target: env.VITE_API_BASE_URL, // must match backend URL 
          changeOrigin: true,
        },
      },
    },
    envDir: rootDir, // where to search for .env file for calls within app
    resolve: {
      alias: {
        '~': resolve(__dirname, 'src'),
      },
    },
    build: {
      target: 'esnext',
      minify: 'terser',
      sourcemap: false,
      rollupOptions: {
        output: {
          manualChunks: {
            vendor: ['solid-js', '@solidjs/router'],
            api: ['axios'],
          },
        },
      },
    },
  }
});