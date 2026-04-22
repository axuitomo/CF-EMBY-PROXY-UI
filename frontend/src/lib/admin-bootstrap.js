import { runtimeConfig } from '@/config/runtime';

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseInlineBootstrapScript(scriptId = 'admin-bootstrap') {
  if (typeof document === 'undefined') return {};

  const element = document.getElementById(scriptId);
  const rawText = String(element?.textContent || '').trim();
  if (!rawText) return {};

  try {
    return JSON.parse(rawText);
  } catch {
    return {};
  }
}

export function readInlineAdminBootstrap() {
  const windowBootstrap = typeof window !== 'undefined' && isPlainObject(window.__ADMIN_BOOTSTRAP__)
    ? window.__ADMIN_BOOTSTRAP__
    : null;
  const payload = windowBootstrap || parseInlineBootstrapScript();

  return {
    adminPath: String(payload?.adminPath || runtimeConfig.adminPath).trim() || runtimeConfig.adminPath,
    loginPath: String(payload?.loginPath || '').trim(),
    hostDomain: String(payload?.hostDomain || '').trim(),
    legacyHost: String(payload?.legacyHost || '').trim(),
    generatedAt: String(payload?.generatedAt || '').trim(),
    initHealth: isPlainObject(payload?.initHealth) ? payload.initHealth : null,
    contract: isPlainObject(payload?.contract) ? payload.contract : {},
    shell: isPlainObject(payload?.shell) ? payload.shell : null,
    runtimeStatus: isPlainObject(payload?.runtimeStatus) ? payload.runtimeStatus : {},
    revisions: isPlainObject(payload?.revisions) ? payload.revisions : {},
    config: isPlainObject(payload?.config) ? payload.config : {},
    nodes: Array.isArray(payload?.nodes) ? payload.nodes : [],
    configSnapshots: Array.isArray(payload?.configSnapshots) ? payload.configSnapshots : []
  };
}
