function normalizeRoutePath(rawValue = '/admin') {
  const value = String(rawValue || '').trim();
  if (!value) return '/admin';
  if (/^https?:\/\//i.test(value)) return value;
  const normalized = value.startsWith('/') ? value : `/${value}`;
  return normalized === '/' ? '/' : normalized.replace(/\/+$/, '');
}

function readBrowserOrigin() {
  if (typeof window === 'undefined') return '';
  return String(window.location.origin || '').trim();
}

export const runtimeConfig = Object.freeze({
  apiBaseUrl: String(import.meta.env.VITE_API_BASE_URL || '').trim(),
  adminPath: normalizeRoutePath(import.meta.env.VITE_ADMIN_PATH || '/admin'),
  releaseIndexUrl: String(import.meta.env.VITE_RELEASE_INDEX_URL || import.meta.env.VITE_INDEX_URL || '').trim(),
  cdnBaseUrl: String(import.meta.env.VITE_CDN_BASE_URL || '').trim(),
  releaseChannel: String(import.meta.env.VITE_FRONTEND_RELEASE_CHANNEL || 'test').trim() || 'test',
  vendorMode: String(import.meta.env.VITE_VENDOR_MODE || 'bundle').trim() || 'bundle',
  devProxyTarget: String(import.meta.env.VITE_DEV_PROXY_TARGET || '').trim()
});

export function resolveApiBaseUrl(baseUrl = runtimeConfig.apiBaseUrl) {
  return String(baseUrl || '').trim() || readBrowserOrigin();
}

export function resolveRuntimeUrl(pathname = '/', baseUrl = runtimeConfig.apiBaseUrl) {
  const normalizedPath = String(pathname || '').trim() || '/';
  if (/^https?:\/\//i.test(normalizedPath)) return normalizedPath;

  const resolvedBaseUrl = resolveApiBaseUrl(baseUrl);
  if (!resolvedBaseUrl) {
    return normalizedPath.startsWith('/') ? normalizedPath : `/${normalizedPath}`;
  }

  return new URL(
    normalizedPath.startsWith('/') ? normalizedPath : `/${normalizedPath}`,
    resolvedBaseUrl.endsWith('/') ? resolvedBaseUrl : `${resolvedBaseUrl}/`
  ).toString();
}

export function resolveAdminLoginPath(adminPath = runtimeConfig.adminPath) {
  if (/^https?:\/\//i.test(String(adminPath || '').trim())) {
    return `${String(adminPath || '').trim().replace(/\/+$/, '')}/login`;
  }
  const normalizedAdminPath = normalizeRoutePath(adminPath || runtimeConfig.adminPath);
  return normalizedAdminPath === '/' ? '/login' : `${normalizedAdminPath}/login`;
}

export function resolveAdminUrl(pathname = runtimeConfig.adminPath, baseUrl = runtimeConfig.apiBaseUrl) {
  return resolveRuntimeUrl(pathname, baseUrl);
}

export function resolveAdminLoginUrl(loginPath = '', baseUrl = runtimeConfig.apiBaseUrl) {
  return resolveRuntimeUrl(loginPath || resolveAdminLoginPath(runtimeConfig.adminPath), baseUrl);
}

export function resolveReleaseIndexExample() {
  return 'https://github.com/axuitomo/CF-EMBY-PROXY-UI/releases/download/<tag>/index.html';
}

export function resolveRepoCdnExample() {
  return resolveReleaseIndexExample();
}

export function resolveReleaseRuntimeSummary(config = runtimeConfig) {
  const runtime = config && typeof config === 'object' ? config : runtimeConfig;
  const releaseIndexUrl = String(runtime.releaseIndexUrl || runtime.cdnBaseUrl || '').trim();
  return {
    releaseChannel: String(runtime.releaseChannel || 'test').trim() || 'test',
    vendorMode: String(runtime.vendorMode || 'bundle').trim() || 'bundle',
    adminPath: normalizeRoutePath(runtime.adminPath || runtimeConfig.adminPath),
    apiBaseUrl: resolveApiBaseUrl(runtime.apiBaseUrl || runtimeConfig.apiBaseUrl),
    releaseIndexUrl,
    cdnBaseUrl: String(runtime.cdnBaseUrl || '').trim(),
    devProxyTarget: String(runtime.devProxyTarget || '').trim()
  };
}

export function resolveAdminShellIndexUrl(releaseIndexUrl = runtimeConfig.releaseIndexUrl || runtimeConfig.cdnBaseUrl) {
  const normalizedUrl = String(releaseIndexUrl || '').trim();
  if (!normalizedUrl) return '';
  if (/^https?:\/\//i.test(normalizedUrl)) {
    return normalizedUrl;
  }

  const normalizedPath = normalizeRoutePath(normalizedUrl);
  if (normalizedPath.endsWith('/index.html')) return normalizedPath;
  return normalizedPath.endsWith('/')
    ? `${normalizedPath}index.html`
    : `${normalizedPath}/index.html`;
}
