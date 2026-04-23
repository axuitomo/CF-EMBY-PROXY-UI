<script setup>
const primaryViews = Object.freeze([
  'dashboard',
  'nodes',
  'logs',
  'dns',
  'settings'
]);

const settingsVisualSections = Object.freeze([
  '系统 UI',
  '代理与网络',
  '静态资源策略',
  '安全防护',
  '日志设置',
  '监控告警',
  '账号设置',
  '备份与恢复'
]);

const settingsSaveGroups = Object.freeze([
  'ui',
  'proxy',
  'security',
  'logs',
  'account'
]);
</script>

<template>
  <main class="mx-auto flex min-h-screen max-w-4xl flex-col justify-center gap-6 px-6 py-12 text-slate-900">
    <section class="rounded-3xl border border-slate-200 bg-white p-8 shadow-sm">
      <p class="text-sm font-semibold uppercase tracking-[0.2em] text-slate-500">Admin Runtime Host</p>
      <h1 class="mt-4 text-3xl font-semibold tracking-tight text-slate-950">
        正式管理台运行时已切换为 frontend/index.html 承接
      </h1>
      <p class="mt-4 text-sm leading-7 text-slate-600">
        当前正式入口由 <code>frontend/scripts/sync-admin-runtime.mjs</code> 把
        <code>frontend/admin-runtime.template.html</code> 同步为 <code>frontend/index.html</code>，
        再由根 <code>worker.js</code> 在 <code>/admin</code> 远端壳阶段替换 bootstrap。
      </p>
    </section>

    <section class="rounded-3xl border border-slate-200 bg-slate-50 p-8">
      <h2 class="text-lg font-semibold text-slate-950">契约摘要</h2>
      <p class="mt-4 text-sm leading-7 text-slate-600">
        主视图固定为
        <code v-for="(view, index) in primaryViews" :key="view">
          {{ index === 0 ? '' : ' -> ' }}#{{ view }}
        </code>
        ，不再保留旧的 <code>overview</code> / <code>release</code> 一级导航。
      </p>
      <p class="mt-4 text-sm leading-7 text-slate-600">
        Settings 继续遵守 {{ settingsVisualSections.length }} 个视觉分区与 {{ settingsSaveGroups.length }} 个保存分区的管理台契约。
      </p>
    </section>
  </main>
</template>
