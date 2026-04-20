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

export function resolveRepoCdnExample() {
  return 'https://cdn.jsdelivr.net/gh/axuitomo/CF-EMBY-PROXY-UI@<tag-or-commit>/frontend/dist/';
}

export function resolveReleaseRuntimeSummary(config = runtimeConfig) {
  const runtime = config && typeof config === 'object' ? config : runtimeConfig;
  return {
    releaseChannel: String(runtime.releaseChannel || 'test').trim() || 'test',
    vendorMode: String(runtime.vendorMode || 'bundle').trim() || 'bundle',
    adminPath: normalizeRoutePath(runtime.adminPath || runtimeConfig.adminPath),
    apiBaseUrl: resolveApiBaseUrl(runtime.apiBaseUrl || runtimeConfig.apiBaseUrl),
    cdnBaseUrl: String(runtime.cdnBaseUrl || '').trim(),
    devProxyTarget: String(runtime.devProxyTarget || '').trim()
  };
}

export function resolveAdminShellIndexUrl(cdnBaseUrl = runtimeConfig.cdnBaseUrl) {
  const normalizedBase = String(cdnBaseUrl || '').trim();
  if (!normalizedBase) return '';
  const baseUrl = normalizeRoutePath(normalizedBase).startsWith('http')
    ? normalizedBase.replace(/\/+$/, '/')
    : normalizedBase.endsWith('/') ? normalizedBase : `${normalizedBase}/`;
  return /^https?:\/\//i.test(baseUrl) ? new URL('index.html', baseUrl).toString() : `${baseUrl}index.html`;
}
