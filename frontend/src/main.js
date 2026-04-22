import { createApp } from 'vue';

import App from './App.vue';
import './style.css';

function renderBootError(title = '管理台启动失败', detail = '未知错误') {
  const target = document.getElementById('app') || document.body;
  if (!target) return;

  target.innerHTML = `
    <main class="min-h-screen flex items-center justify-center px-6 py-10">
      <section class="w-full max-w-xl rounded-[28px] border border-rose-300/40 bg-white/95 p-8 text-slate-900 shadow-[0_24px_80px_rgba(15,23,42,0.18)]">
        <p class="inline-flex rounded-full bg-rose-100 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-rose-700">
          Admin Boot Error
        </p>
        <h1 class="mt-5 text-3xl font-semibold tracking-tight">${String(title || '管理台启动失败')}</h1>
        <p class="mt-4 text-sm leading-7 text-slate-600">${String(detail || '未知错误')}</p>
      </section>
    </main>
  `;
}

window.__ADMIN_UI_BOOTED__ = false;
window.__ADMIN_UI_BOOT_ERROR__ = String(window.__ADMIN_UI_BOOT_ERROR__ || '');
window.__ADMIN_UI_RENDER_BOOT_ERROR__ = window.__ADMIN_UI_RENDER_BOOT_ERROR__ || renderBootError;

try {
  createApp(App).mount('#app');
  window.__ADMIN_UI_BOOTED__ = true;

  if (window.__ADMIN_UI_DEPENDENCY_TIMEOUT__) {
    window.clearTimeout(window.__ADMIN_UI_DEPENDENCY_TIMEOUT__);
    window.__ADMIN_UI_DEPENDENCY_TIMEOUT__ = 0;
  }
} catch (error) {
  const detail = String(error?.message || error || 'admin_frontend_boot_failed');
  window.__ADMIN_UI_BOOT_ERROR__ = detail;
  window.__ADMIN_UI_RENDER_BOOT_ERROR__('管理台启动失败', detail);
  throw error;
}
