import { readFileSync } from 'node:fs';
import { fileURLToPath, URL } from 'node:url';

import tailwindcss from '@tailwindcss/vite';
import vue from '@vitejs/plugin-vue';
import { defineConfig, loadEnv } from 'vite';

const packageJson = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf8')
);

function normalizeSemver(rawValue = '') {
  return String(rawValue || '').trim().replace(/^[~^]/, '');
}

function normalizeBase(rawValue = '') {
  const value = String(rawValue || '').trim();
  if (!value) return '/';

  if (/^https?:\/\//i.test(value)) {
    return value.endsWith('/') ? value : `${value}/`;
  }

  const normalized = value.startsWith('/') ? value : `/${value}`;
  return normalized.endsWith('/') ? normalized : `${normalized}/`;
}

function normalizeMode(rawValue = '') {
  return String(rawValue || 'bundle').trim().toLowerCase() === 'cdn' ? 'cdn' : 'bundle';
}

function normalizeRoutePath(rawValue = '/admin') {
  const value = String(rawValue || '').trim();
  if (!value) return '/admin';
  const normalized = value.startsWith('/') ? value : `/${value}`;
  return normalized === '/' ? '/' : normalized.replace(/\/+$/, '');
}

function normalizeProxyTarget(rawValue = '') {
  const value = String(rawValue || '').trim();
  return value || 'http://127.0.0.1:8787';
}

function resolveVendorImportMap(env) {
  const dependencies = packageJson.dependencies || {};
  const vueVersion = normalizeSemver(dependencies.vue);
  const lucideVersion = normalizeSemver(dependencies['lucide-vue-next']);
  const chartVersion = normalizeSemver(dependencies['chart.js']);

  return {
    vue: String(
      env.VITE_CDN_IMPORT_VUE || `https://cdn.jsdelivr.net/npm/vue@${vueVersion}/dist/vue.esm-browser.prod.js`
    ).trim(),
    'lucide-vue-next': String(
      env.VITE_CDN_IMPORT_LUCIDE || `https://cdn.jsdelivr.net/npm/lucide-vue-next@${lucideVersion}/dist/esm/lucide-vue-next.js`
    ).trim(),
    'chart.js/auto': String(
      env.VITE_CDN_IMPORT_CHART || `https://cdn.jsdelivr.net/npm/chart.js@${chartVersion}/auto/auto.js`
    ).trim()
  };
}

function createManualChunks(useCdnExternals) {
  return function manualChunks(id) {
    if (!useCdnExternals) {
      if (id.includes('node_modules/chart.js')) return 'vendor-chart';
      if (id.includes('node_modules/lucide-vue-next')) return 'vendor-icons';
      if (id.includes('node_modules/vue')) return 'vendor-vue';
    }

    if (id.includes('/src/features/overview/')) return 'feature-overview';
    if (id.includes('/src/features/runtime/')) return 'feature-runtime';
    if (id.includes('/src/features/release/')) return 'feature-release';
    return null;
  };
}

function createCdnExternalPlugin({ useCdnExternals, vendorImportMap }) {
  return {
    name: 'cdn-externals-importmap',
    transformIndexHtml: {
      order: 'pre',
      handler(html) {
        if (!useCdnExternals) return html;

        return {
          html,
          tags: [
            {
              tag: 'script',
              attrs: {
                type: 'importmap',
                'data-vendor-mode': 'cdn'
              },
              children: JSON.stringify({ imports: vendorImportMap }, null, 2),
              injectTo: 'head-prepend'
            }
          ]
        };
      }
    }
  };
}

function createDevProxy(env) {
  const adminPath = normalizeRoutePath(env.VITE_ADMIN_PATH || '/admin');
  const target = normalizeProxyTarget(env.VITE_DEV_PROXY_TARGET || env.VITE_API_BASE_URL);

  return {
    [adminPath]: {
      target,
      changeOrigin: true,
      secure: false,
      ws: false
    },
    [`${adminPath}/`]: {
      target,
      changeOrigin: true,
      secure: false,
      ws: false
    }
  };
}

export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const vendorMode = normalizeMode(env.VITE_VENDOR_MODE);
  const useCdnExternals = command === 'build' && vendorMode === 'cdn';
  const vendorImportMap = resolveVendorImportMap(env);

  return {
    base: normalizeBase(env.VITE_CDN_BASE_URL),
    plugins: [
      vue(),
      tailwindcss(),
      createCdnExternalPlugin({ useCdnExternals, vendorImportMap })
    ],
    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url))
      }
    },
    server: {
      host: '0.0.0.0',
      port: 5173,
      proxy: createDevProxy(env)
    },
    preview: {
      host: '0.0.0.0',
      port: 4173
    },
    build: {
      target: 'es2022',
      manifest: true,
      sourcemap: true,
      cssCodeSplit: true,
      rolldownOptions: {
        external: useCdnExternals ? Object.keys(vendorImportMap) : [],
        output: {
          manualChunks: createManualChunks(useCdnExternals)
        }
      }
    }
  };
});
