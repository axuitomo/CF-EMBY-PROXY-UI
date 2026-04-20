import {
  resolveAdminLoginPath,
  resolveAdminLoginUrl,
  resolveAdminUrl,
  runtimeConfig
} from '@/config/runtime';
import { readInlineAdminBootstrap } from '@/lib/admin-bootstrap';

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

async function parseResponsePayload(response) {
  const rawText = await response.text();
  if (!rawText) return null;

  try {
    return JSON.parse(rawText);
  } catch {
    return rawText;
  }
}

function normalizeErrorMessage(response, payload) {
  if (isPlainObject(payload)) {
    const nestedError = isPlainObject(payload.error) ? payload.error : null;
    const payloadMessage = String(
      payload.message
      || nestedError?.message
      || payload.error
      || ''
    ).trim();
    if (payloadMessage) return payloadMessage;
  }

  if (typeof payload === 'string' && payload.trim()) return payload.trim();
  return response.status === 401 ? '未授权，请先登录管理台。' : `请求失败（HTTP ${response.status}）`;
}

export class AdminApiError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = 'AdminApiError';
    this.status = Number(options.status) || 500;
    this.code = String(options.code || 'REQUEST_FAILED').trim() || 'REQUEST_FAILED';
    this.payload = options.payload ?? null;
  }
}

export async function callAdminAction(action, data = {}, options = {}) {
  const seedBootstrap = isPlainObject(options.seedBootstrap) ? options.seedBootstrap : readInlineAdminBootstrap();
  const adminPath = String(options.adminPath || seedBootstrap.adminPath || runtimeConfig.adminPath).trim() || runtimeConfig.adminPath;
  const endpoint = resolveAdminUrl(adminPath, options.apiBaseUrl || runtimeConfig.apiBaseUrl);
  const response = await fetch(endpoint, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(isPlainObject(options.headers) ? options.headers : {})
    },
    body: JSON.stringify({
      action,
      ...(isPlainObject(data) ? data : {})
    })
  });

  const payload = await parseResponsePayload(response);
  if (!response.ok) {
    const nestedError = isPlainObject(payload?.error) ? payload.error : null;
    const code = isPlainObject(payload) && String(payload.code || nestedError?.code || payload.error || '').trim()
      ? String(payload.code || nestedError?.code || payload.error).trim()
      : (response.status === 401 ? 'UNAUTHORIZED' : 'REQUEST_FAILED');
    throw new AdminApiError(normalizeErrorMessage(response, payload), {
      status: response.status,
      code,
      payload
    });
  }

  return payload;
}

export function resolveAdminLoginHref(options = {}) {
  const seedBootstrap = isPlainObject(options.seedBootstrap) ? options.seedBootstrap : readInlineAdminBootstrap();
  const adminPath = String(seedBootstrap.adminPath || runtimeConfig.adminPath).trim() || runtimeConfig.adminPath;
  const loginPath = String(options.loginPath || seedBootstrap.loginPath || resolveAdminLoginPath(adminPath)).trim();

  return resolveAdminLoginUrl(loginPath, options.apiBaseUrl || runtimeConfig.apiBaseUrl);
}
