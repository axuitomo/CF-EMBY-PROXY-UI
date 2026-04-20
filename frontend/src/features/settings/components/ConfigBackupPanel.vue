<script setup>
import { computed, ref } from 'vue';
import {
  Archive,
  CheckCircle2,
  Download,
  FileJson,
  Info,
  RefreshCw,
  ShieldAlert,
  TriangleAlert,
  Upload,
  X
} from 'lucide-vue-next';

import SectionCard from '@/components/SectionCard.vue';

defineOptions({
  name: 'ConfigBackupPanel'
});

const props = defineProps({
  eyebrow: {
    type: String,
    default: 'Config Backup'
  },
  title: {
    type: String,
    default: '配置备份 / 导入导出'
  },
  description: {
    type: String,
    default: '这个子面板只负责承载快照摘要、导出、导入预检与确认导入的交互外壳。真正的数据读写、协议适配与状态持久化由上层通过 props 注入。'
  },
  data: {
    type: Object,
    default: () => ({})
  },
  loading: {
    type: Object,
    default: () => ({})
  },
  actions: {
    type: Object,
    default: () => ({})
  }
});

const fileInputRef = ref(null);

const panelData = computed(() => (isPlainObject(props.data) ? props.data : {}));
const summary = computed(() => (isPlainObject(panelData.value.summary) ? panelData.value.summary : {}));
const exportState = computed(() => (isPlainObject(panelData.value.exportState) ? panelData.value.exportState : {}));
const importDraft = computed(() => (isPlainObject(panelData.value.importDraft) ? panelData.value.importDraft : {}));
const previewState = computed(() => (isPlainObject(panelData.value.previewState) ? panelData.value.previewState : {}));
const feedback = computed(() => (isPlainObject(panelData.value.feedback) ? panelData.value.feedback : {}));
const status = computed(() => (isPlainObject(panelData.value.status) ? panelData.value.status : {}));
const permissions = computed(() => (isPlainObject(panelData.value.permissions) ? panelData.value.permissions : {}));

const loadingState = computed(() => ({
  refreshSummary: Boolean(props.loading?.refreshSummary),
  exportConfig: Boolean(props.loading?.exportConfig),
  previewImport: Boolean(props.loading?.previewImport),
  confirmImport: Boolean(props.loading?.confirmImport),
  selectFile: Boolean(props.loading?.selectFile)
}));

const authRequired = computed(() => panelData.value.authRequired === true);
const loginHref = computed(() => String(panelData.value.loginHref || '').trim());
const isBusy = computed(() => Object.values(loadingState.value).some(Boolean));

const feedbackTone = computed(() => resolveTone(feedback.value.tone));
const feedbackTitle = computed(() => String(feedback.value.title || '').trim());
const feedbackText = computed(() => String(feedback.value.text || '').trim());

const selectedFileName = computed(() => {
  const fromDraft = String(importDraft.value.fileName || '').trim();
  if (fromDraft) return fromDraft;
  const file = importDraft.value.file;
  return isNativeFile(file) ? String(file.name || '').trim() : '';
});

const selectedFileSize = computed(() => {
  const size = Number(importDraft.value.fileSize);
  if (Number.isFinite(size) && size >= 0) return size;
  const file = importDraft.value.file;
  return isNativeFile(file) && Number.isFinite(file.size) ? file.size : null;
});

const importText = computed(() => String(importDraft.value.text || ''));
const importSourceLabel = computed(() => String(importDraft.value.sourceLabel || '').trim());
const importTextPlaceholder = computed(() => (
  String(importDraft.value.placeholder || '').trim()
  || '支持上传旧版导出的 JSON，也支持直接粘贴配置快照文本。解析、兼容检查和最终导入动作都由上层 action 决定。'
));

const previewTone = computed(() => {
  if (String(previewState.value.tone || '').trim()) return resolveTone(previewState.value.tone);
  if (previewErrors.value.length) return 'error';
  if (loadingState.value.previewImport) return 'info';
  if (previewReady.value && previewWarnings.value.length) return 'warning';
  if (previewReady.value) return 'success';
  return 'neutral';
});

const previewTitle = computed(() => (
  String(previewState.value.title || '').trim()
  || '导入预检结果'
));

const previewDescription = computed(() => (
  String(previewState.value.description || '').trim()
  || '上层完成 schema、版本兼容和影响评估后，可以把结论、警告和变更摘要回填到这里。'
));

const previewWarnings = computed(() => normalizeList(previewState.value.warnings));
const previewErrors = computed(() => normalizeList(previewState.value.errors));
const previewHighlights = computed(() => normalizeDisplayItems(
  previewState.value.items
  ?? previewState.value.highlights
  ?? previewState.value.changes
));

const previewStats = computed(() => {
  const rawStats = Array.isArray(previewState.value.stats)
    ? previewState.value.stats.map(normalizeStatItem).filter(Boolean)
    : [];

  if (rawStats.length) return rawStats;

  const derived = [];
  const importedCount = coerceCount(
    previewState.value.importedCount
    ?? previewState.value.affectedCount
    ?? previewState.value.changeCount
  );
  const warningCount = previewWarnings.value.length;
  const errorCount = previewErrors.value.length;
  const skippedCount = coerceCount(previewState.value.skippedCount);

  if (importedCount !== null) derived.push({ label: '变更项', value: formatCount(importedCount) });
  if (warningCount > 0) derived.push({ label: '警告', value: formatCount(warningCount) });
  if (errorCount > 0) derived.push({ label: '阻塞项', value: formatCount(errorCount) });
  if (skippedCount !== null) derived.push({ label: '跳过项', value: formatCount(skippedCount) });

  return derived.slice(0, 4);
});

const previewMeta = computed(() => {
  const items = [];
  const revision = compactRevision(
    previewState.value.configRevision
    ?? previewState.value.revision
    ?? summary.value.configRevision
  );
  if (revision !== '--') items.push(`Revision ${revision}`);

  const previewedAt = formatDateTime(previewState.value.generatedAt ?? previewState.value.previewedAt, '');
  if (previewedAt) items.push(`预检时间 ${previewedAt}`);

  if (importSourceLabel.value) items.push(`来源 ${importSourceLabel.value}`);
  return items;
});

const previewReady = computed(() => {
  if (previewState.value.ready === true || previewState.value.canConfirm === true) return true;
  if (previewStats.value.length > 0) return true;
  if (previewHighlights.value.length > 0) return true;
  if (previewWarnings.value.length > 0 && previewErrors.value.length === 0) return true;
  return false;
});

const canPreviewImport = computed(() => permissions.value.canPreviewImport !== false && !authRequired.value);
const canConfirmImport = computed(() => {
  if (permissions.value.canConfirmImport === false) return false;
  if (authRequired.value) return false;
  if (previewState.value.canConfirm === false) return false;
  return previewReady.value;
});

const statusTone = computed(() => {
  const explicitTone = String(status.value.tone || '').trim();
  if (explicitTone) return resolveTone(explicitTone);
  if (loadingState.value.confirmImport) return 'info';
  if (loadingState.value.previewImport || loadingState.value.exportConfig || loadingState.value.refreshSummary) return 'info';
  if (feedbackTone.value === 'error' || previewTone.value === 'error') return 'error';
  if (canConfirmImport.value) return 'warning';
  if (feedbackTone.value === 'success') return 'success';
  return 'neutral';
});

const statusLabel = computed(() => {
  const explicitLabel = String(status.value.label || '').trim();
  if (explicitLabel) return explicitLabel;
  if (loadingState.value.confirmImport) return '正在导入';
  if (loadingState.value.previewImport) return '正在预检';
  if (loadingState.value.exportConfig) return '正在导出';
  if (loadingState.value.refreshSummary) return '正在刷新';
  if (previewTone.value === 'error') return '预检阻塞';
  if (canConfirmImport.value) return '待确认';
  if (feedbackTone.value === 'success') return '已就绪';
  return '待操作';
});

const summaryCards = computed(() => {
  const rawCards = Array.isArray(summary.value.cards)
    ? summary.value.cards.map(normalizeSummaryCard).filter(Boolean)
    : [];

  if (rawCards.length) return rawCards;

  const importSource = selectedFileName.value || importSourceLabel.value || '等待选择文件或粘贴文本';
  const draftSummary = buildImportDraftSummary(importDraft.value, importText.value);

  return [
    {
      title: '配置 Revision',
      value: compactRevision(summary.value.configRevision ?? previewState.value.configRevision ?? previewState.value.revision),
      note: formatDateTime(summary.value.generatedAt ?? previewState.value.generatedAt, '等待上层注入快照时间')
    },
    {
      title: '最近导出',
      value: formatDateTime(exportState.value.lastExportedAt, '尚未导出'),
      note: String(exportState.value.note || '').trim() || '点击按钮后，由上层 action 决定下载、复制或生成脱敏副本。'
    },
    {
      title: '预检状态',
      value: previewReady.value ? '可确认' : '待预检',
      note: previewDescription.value
    },
    {
      title: '导入来源',
      value: importSource,
      note: draftSummary
    }
  ];
});

const summaryTags = computed(() => normalizeList(summary.value.tags));

const exportButtons = computed(() => {
  const rawButtons = Array.isArray(exportState.value.actions)
    ? exportState.value.actions.map(normalizeActionButton).filter(Boolean)
    : [];

  if (rawButtons.length) return rawButtons;

  return [{
    key: 'export-config',
    label: String(exportState.value.buttonLabel || '').trim() || '导出配置快照',
    hint: String(exportState.value.buttonHint || '').trim() || '支持让上层决定是下载 JSON、复制到剪贴板，还是生成脱敏备份。',
    tone: 'primary',
    actionName: 'exportConfig',
    disabled: false
  }];
});

function handleRefreshSummary() {
  return invokeAction('refreshSummary', {
    summary: summary.value,
    previewState: previewState.value
  });
}

function handleExport(button) {
  return invokeAction(button.actionName || 'exportConfig', {
    action: button,
    summary: summary.value,
    exportState: exportState.value,
    previewState: previewState.value
  });
}

function handleImportTextInput(event) {
  const value = event?.target?.value ?? '';
  const nextDraft = {
    ...snapshotImportDraft(),
    text: value
  };

  const payload = {
    value,
    patch: { text: value },
    nativeEvent: event,
    draft: nextDraft
  };

  return invokeAction('updateImportText', payload) ?? invokeAction('updateImportDraft', {
    key: 'text',
    ...payload
  });
}

function handleImportSourceLabelInput(event) {
  const value = event?.target?.value ?? '';
  const nextDraft = {
    ...snapshotImportDraft(),
    sourceLabel: value
  };

  return invokeAction('updateImportDraft', {
    key: 'sourceLabel',
    value,
    patch: { sourceLabel: value },
    nativeEvent: event,
    draft: nextDraft
  });
}

function handleChooseFile() {
  if (isBusy.value) return;
  fileInputRef.value?.click();
  invokeAction('openFilePicker', {
    draft: snapshotImportDraft()
  });
}

function handleFileChange(event) {
  const files = Array.from(event?.target?.files || []);
  const file = files[0] || null;
  const nextDraft = {
    ...snapshotImportDraft(),
    file,
    fileName: isNativeFile(file) ? String(file.name || '').trim() : '',
    fileSize: isNativeFile(file) && Number.isFinite(file.size) ? file.size : null
  };

  const payload = {
    file,
    files,
    nativeEvent: event,
    draft: nextDraft,
    patch: {
      file,
      fileName: nextDraft.fileName,
      fileSize: nextDraft.fileSize
    }
  };

  invokeAction('selectFile', payload) ?? invokeAction('updateImportDraft', {
    key: 'file',
    ...payload
  });

  if (fileInputRef.value) fileInputRef.value.value = '';
}

function handleClearSelectedFile() {
  if (fileInputRef.value) fileInputRef.value.value = '';
  const nextDraft = {
    ...snapshotImportDraft(),
    fileName: '',
    fileSize: null
  };

  return invokeAction('clearSelectedFile', {
    draft: nextDraft
  }) ?? invokeAction('updateImportDraft', {
    key: 'file',
    value: null,
    patch: {
      file: null,
      fileName: '',
      fileSize: null
    },
    draft: nextDraft
  });
}

function handlePreviewImport() {
  return invokeAction('previewImport', {
    draft: snapshotImportDraft(),
    summary: summary.value,
    previewState: previewState.value
  });
}

function handleConfirmImport() {
  return invokeAction('confirmImport', {
    draft: snapshotImportDraft(),
    summary: summary.value,
    previewState: previewState.value
  });
}

function handleResetImport() {
  if (fileInputRef.value) fileInputRef.value.value = '';
  const nextDraft = {
    text: '',
    sourceLabel: '',
    fileName: '',
    fileSize: null
  };

  return invokeAction('resetImport', {
    draft: nextDraft
  }) ?? invokeAction('updateImportDraft', {
    key: 'reset',
    value: '',
    patch: {
      text: '',
      sourceLabel: '',
      file: null,
      fileName: '',
      fileSize: null
    },
    draft: nextDraft
  });
}

function snapshotImportDraft() {
  return {
    text: importText.value,
    sourceLabel: importSourceLabel.value,
    fileName: selectedFileName.value,
    fileSize: selectedFileSize.value
  };
}

function invokeAction(name, payload) {
  const handler = props.actions?.[name];
  if (typeof handler !== 'function') return undefined;
  return handler(payload);
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isNativeFile(value) {
  return typeof File !== 'undefined' && value instanceof File;
}

function resolveTone(value) {
  switch (String(value || '').trim().toLowerCase()) {
    case 'success':
      return 'success';
    case 'error':
      return 'error';
    case 'warning':
      return 'warning';
    case 'info':
      return 'info';
    default:
      return 'neutral';
  }
}

function resolveTonePillClass(tone) {
  switch (tone) {
    case 'success':
      return 'border-mint-400/30 bg-mint-400/12 text-mint-200';
    case 'error':
      return 'border-rose-400/30 bg-rose-500/12 text-rose-100';
    case 'warning':
      return 'border-amber-300/30 bg-amber-500/12 text-amber-100';
    case 'info':
      return 'border-ocean-500/30 bg-ocean-500/12 text-ocean-200';
    default:
      return 'border-white/10 bg-white/6 text-slate-200';
  }
}

function resolveFeedbackClass(tone) {
  switch (tone) {
    case 'success':
      return 'border-mint-400/25 bg-mint-400/10 text-mint-50';
    case 'error':
      return 'border-rose-400/25 bg-rose-500/10 text-rose-50';
    case 'warning':
      return 'border-amber-300/25 bg-amber-500/10 text-amber-50';
    case 'info':
      return 'border-ocean-500/25 bg-ocean-500/10 text-ocean-50';
    default:
      return 'border-white/10 bg-white/5 text-slate-100';
  }
}

function resolvePreviewClass(tone) {
  switch (tone) {
    case 'success':
      return 'border-mint-400/20 bg-mint-400/8';
    case 'error':
      return 'border-rose-400/20 bg-rose-500/8';
    case 'warning':
      return 'border-amber-300/20 bg-amber-500/8';
    case 'info':
      return 'border-ocean-500/20 bg-ocean-500/8';
    default:
      return 'border-white/10 bg-slate-950/40';
  }
}

function resolveButtonClass(tone) {
  return tone === 'primary' ? 'primary-btn' : 'secondary-btn';
}

function normalizeSummaryCard(card) {
  if (typeof card === 'string' || typeof card === 'number') {
    return {
      title: '摘要',
      value: String(card),
      note: ''
    };
  }
  if (!isPlainObject(card)) return null;

  return {
    title: String(card.title || '').trim() || '摘要',
    value: formatDisplayValue(card.value, '--'),
    note: String(card.note || '').trim()
  };
}

function normalizeActionButton(button, index) {
  if (!isPlainObject(button)) return null;

  return {
    key: String(button.key || '').trim() || `export-action-${index}`,
    label: String(button.label || '').trim() || '执行动作',
    hint: String(button.hint || '').trim(),
    tone: button.tone === 'primary' ? 'primary' : 'secondary',
    actionName: String(button.actionName || button.name || '').trim() || 'exportConfig',
    disabled: button.disabled === true
  };
}

function normalizeDisplayItems(items) {
  if (!Array.isArray(items)) return [];

  return items
    .map((item, index) => {
      if (typeof item === 'string' || typeof item === 'number') {
        return {
          key: `preview-item-${index}`,
          title: '',
          value: String(item),
          note: ''
        };
      }

      if (!isPlainObject(item)) return null;

      return {
        key: String(item.key || '').trim() || `preview-item-${index}`,
        title: String(item.title || item.label || '').trim(),
        value: formatDisplayValue(item.value, item.title || item.label ? '--' : ''),
        note: String(item.note || item.description || '').trim()
      };
    })
    .filter(Boolean);
}

function normalizeStatItem(item) {
  if (!isPlainObject(item)) return null;

  return {
    label: String(item.label || item.title || '').trim(),
    value: formatDisplayValue(item.value, '--')
  };
}

function normalizeList(value) {
  if (Array.isArray(value)) {
    return value
      .map((item) => String(item || '').trim())
      .filter(Boolean);
  }

  const text = String(value || '').trim();
  return text ? [text] : [];
}

function compactRevision(value) {
  const text = String(value || '').trim();
  if (!text) return '--';
  if (text.length <= 18) return text;
  return `${text.slice(0, 8)}...${text.slice(-6)}`;
}

function formatDateTime(value, fallback = '--') {
  const text = String(value || '').trim();
  if (!text) return fallback;

  const date = new Date(text);
  if (Number.isNaN(date.getTime())) return text;

  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  }).format(date);
}

function formatBytes(value) {
  const size = Number(value);
  if (!Number.isFinite(size) || size < 0) return '';
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

function formatCount(value) {
  const count = Number(value);
  if (!Number.isFinite(count)) return '--';
  return new Intl.NumberFormat('zh-CN').format(count);
}

function coerceCount(value) {
  const count = Number(value);
  return Number.isFinite(count) ? count : null;
}

function formatDisplayValue(value, fallback = '--') {
  if (value === null || value === undefined) return fallback;
  if (typeof value === 'number') return Number.isFinite(value) ? formatCount(value) : fallback;
  if (typeof value === 'boolean') return value ? '是' : '否';
  const text = String(value).trim();
  return text || fallback;
}

function buildImportDraftSummary(draft, text) {
  const summaryParts = [];
  const fileSizeText = formatBytes(selectedFileSize.value);
  if (fileSizeText) summaryParts.push(`文件 ${fileSizeText}`);

  const trimmedText = String(text || '').trim();
  if (trimmedText) summaryParts.push(`文本 ${formatCount(trimmedText.length)} 字符`);

  const note = String(draft.note || '').trim();
  if (note) summaryParts.push(note);

  return summaryParts.join(' · ') || '等待上层提供导入草稿';
}
</script>

<template>
  <SectionCard :eyebrow="eyebrow" :title="title" :description="description">
    <template #meta>
      <div class="flex flex-wrap items-center justify-end gap-3">
        <div class="inline-flex rounded-full border px-3 py-1 text-xs font-semibold" :class="resolveTonePillClass(statusTone)">
          {{ statusLabel }}
        </div>
        <button
          type="button"
          class="secondary-btn"
          :disabled="loadingState.refreshSummary || loadingState.previewImport || loadingState.confirmImport"
          @click="handleRefreshSummary"
        >
          <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loadingState.refreshSummary }" />
          刷新摘要
        </button>
      </div>
    </template>

    <article
      v-if="authRequired"
      class="mb-6 rounded-3xl border border-amber-300/25 bg-amber-500/10 p-5 text-amber-50"
    >
      <div class="flex items-start gap-3">
        <ShieldAlert class="mt-0.5 h-5 w-5 shrink-0 text-amber-200" />
        <div>
          <p class="text-sm font-semibold">当前会话未授权，导出与导入动作应由上层决定是否继续放行</p>
          <p class="mt-2 text-sm leading-6 text-amber-50/85">
            这个子面板不会自己依赖任何全局登录状态，只负责按 props 展示受限态。等上层补齐认证后，直接刷新或重传 `data` 即可。
          </p>
          <a
            v-if="loginHref"
            :href="loginHref"
            class="mt-4 inline-flex rounded-full border border-amber-200/40 px-4 py-2 text-sm font-medium text-amber-50 transition hover:bg-amber-400/10"
          >
            打开登录页
          </a>
        </div>
      </div>
    </article>

    <article
      v-if="feedbackText"
      class="mb-6 rounded-3xl border p-5"
      :class="resolveFeedbackClass(feedbackTone)"
      aria-live="polite"
    >
      <div class="flex items-start gap-3">
        <CheckCircle2 v-if="feedbackTone === 'success'" class="mt-0.5 h-5 w-5 shrink-0" />
        <TriangleAlert v-else-if="feedbackTone === 'error' || feedbackTone === 'warning'" class="mt-0.5 h-5 w-5 shrink-0" />
        <Info v-else class="mt-0.5 h-5 w-5 shrink-0" />
        <div>
          <p v-if="feedbackTitle" class="text-sm font-semibold">{{ feedbackTitle }}</p>
          <p class="text-sm leading-6" :class="{ 'mt-2': feedbackTitle }">{{ feedbackText }}</p>
        </div>
      </div>
    </article>

    <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      <article v-for="card in summaryCards" :key="card.title" class="stat-tile">
        <div class="flex items-center gap-3">
          <Archive class="h-5 w-5 text-brand-300" />
          <p class="text-sm font-medium text-white">{{ card.title }}</p>
        </div>
        <p class="mt-4 break-all text-2xl font-semibold text-brand-300">{{ card.value }}</p>
        <p class="mt-3 text-sm leading-6 text-slate-300">{{ card.note }}</p>
      </article>
    </div>

    <div v-if="summaryTags.length" class="mt-5 flex flex-wrap gap-2">
      <span
        v-for="tag in summaryTags"
        :key="tag"
        class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200"
      >
        {{ tag }}
      </span>
    </div>

    <div class="mt-6 grid gap-4 xl:grid-cols-[0.96fr_1.04fr]">
      <article class="form-card">
        <div class="flex items-start gap-3">
          <Download class="mt-0.5 h-5 w-5 shrink-0 text-brand-300" />
          <div>
            <h3 class="text-sm font-medium text-white">
              {{ exportState.title || '导出配置快照' }}
            </h3>
            <p class="mt-2 text-sm leading-6 text-slate-300">
              {{ exportState.description || '这里不直接实现下载协议，只提供导出入口与上下文展示，方便上层接 Worker、文件系统或剪贴板动作。' }}
            </p>
          </div>
        </div>

        <div class="mt-5 space-y-3 text-sm leading-6 text-slate-300">
          <p class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
            建议把 revision、生成时间、来源标签和必要的脱敏策略一起写入导出元数据，后续回滚和审计会更清晰。
          </p>
          <p class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
            当前组件默认只展示最近一次导出时间和按钮文案，不自行拼接文件名，也不假设后端返回格式。
          </p>
        </div>

        <div class="mt-5 flex flex-wrap gap-2">
          <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
            最近导出 {{ formatDateTime(exportState.lastExportedAt, '尚未导出') }}
          </span>
          <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
            默认格式 {{ exportState.format || 'JSON / 上层决定' }}
          </span>
        </div>

        <div class="mt-6 flex flex-wrap items-center gap-3">
          <button
            v-for="button in exportButtons"
            :key="button.key"
            type="button"
            :class="resolveButtonClass(button.tone)"
            :disabled="button.disabled || loadingState.exportConfig || loadingState.confirmImport"
            @click="handleExport(button)"
          >
            <Download class="h-4 w-4" :class="{ 'animate-pulse': loadingState.exportConfig }" />
            {{ loadingState.exportConfig ? (button.loadingLabel || '处理中') : button.label }}
          </button>
        </div>

        <p v-if="exportButtons.some((button) => button.hint)" class="mt-4 text-sm leading-6 text-slate-400">
          {{ exportButtons.find((button) => button.hint)?.hint }}
        </p>
      </article>

      <article class="form-card">
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div class="max-w-3xl">
            <div class="flex items-start gap-3">
              <Upload class="mt-0.5 h-5 w-5 shrink-0 text-ocean-300" />
              <div>
                <h3 class="text-sm font-medium text-white">导入预检 / 确认导入</h3>
                <p class="mt-2 text-sm leading-6 text-slate-300">
                  先选择文件或粘贴快照，再让上层 action 做 schema 检查、字段兼容判断和风险评估。只有预检通过后才建议放行正式导入。
                </p>
              </div>
            </div>
          </div>

          <div class="flex flex-wrap gap-3">
            <button
              type="button"
              class="secondary-btn"
              :disabled="loadingState.previewImport || loadingState.confirmImport"
              @click="handleResetImport"
            >
              清空草稿
            </button>
            <button
              type="button"
              class="secondary-btn"
              :disabled="!canPreviewImport || loadingState.previewImport || loadingState.confirmImport"
              @click="handlePreviewImport"
            >
              <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loadingState.previewImport }" />
              {{ loadingState.previewImport ? '预检中' : '预检导入' }}
            </button>
          </div>
        </div>

        <input
          ref="fileInputRef"
          type="file"
          class="hidden"
          :accept="importDraft.accept || '.json,application/json'"
          :multiple="false"
          @change="handleFileChange"
        />

        <div class="mt-5 grid gap-4">
          <div class="rounded-3xl border border-dashed border-white/12 bg-slate-950/35 p-5">
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="flex items-center gap-3">
                <FileJson class="h-5 w-5 text-ocean-300" />
                <div>
                  <p class="text-sm font-medium text-white">选择导入文件</p>
                  <p class="mt-1 text-sm leading-6 text-slate-400">
                    建议上传旧版导出的 JSON 快照，或者任何已经由上层约定过结构的配置备份文件。
                  </p>
                </div>
              </div>

              <button
                type="button"
                class="secondary-btn"
                :disabled="loadingState.selectFile || loadingState.previewImport || loadingState.confirmImport"
                @click="handleChooseFile"
              >
                <Upload class="h-4 w-4" />
                {{ selectedFileName ? '重新选择文件' : '选择文件' }}
              </button>
            </div>

            <div v-if="selectedFileName" class="mt-4 flex flex-wrap items-center gap-2">
              <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                {{ selectedFileName }}
              </span>
              <span v-if="formatBytes(selectedFileSize)" class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                {{ formatBytes(selectedFileSize) }}
              </span>
              <button
                type="button"
                class="inline-flex items-center gap-1 rounded-full border border-white/10 px-3 py-1 text-xs text-slate-300 transition hover:border-white/20 hover:bg-white/8"
                :disabled="loadingState.previewImport || loadingState.confirmImport"
                @click="handleClearSelectedFile"
              >
                <X class="h-3.5 w-3.5" />
                移除
              </button>
            </div>
            <p v-else class="mt-4 text-sm leading-6 text-slate-400">
              还没有选择文件。你也可以完全不上传文件，直接在下面粘贴快照文本做预检。
            </p>
          </div>

          <label class="field-shell">
            <span class="field-label">来源标签</span>
            <input
              :value="importSourceLabel"
              type="text"
              class="field-input"
              placeholder="例如 旧版管理台全量备份 / staging 环境快照"
              :disabled="loadingState.previewImport || loadingState.confirmImport"
              @input="handleImportSourceLabelInput"
            />
            <span class="field-hint">可选，用来在预检结果和导入审计里保留来源语义。</span>
          </label>

          <label class="field-shell">
            <span class="field-label">快照文本</span>
            <textarea
              :value="importText"
              rows="10"
              class="field-input field-textarea font-mono text-xs leading-6"
              :placeholder="importTextPlaceholder"
              :disabled="loadingState.previewImport || loadingState.confirmImport"
              @input="handleImportTextInput"
            />
            <span class="field-hint">
              文本内容由上层持有；这个组件不会自行解析 JSON，只会把草稿通过 action 交回去。
            </span>
          </label>
        </div>
      </article>
    </div>

    <article class="mt-6 form-card">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="max-w-3xl">
          <div class="flex items-start gap-3">
            <RefreshCw class="mt-0.5 h-5 w-5 shrink-0 text-brand-300" :class="{ 'animate-spin': loadingState.previewImport }" />
            <div>
              <h3 class="text-sm font-medium text-white">{{ previewTitle }}</h3>
              <p class="mt-2 text-sm leading-6 text-slate-300">{{ previewDescription }}</p>
            </div>
          </div>
        </div>

        <div class="inline-flex rounded-full border px-3 py-1 text-xs font-semibold" :class="resolveTonePillClass(previewTone)">
          {{ previewTone === 'error' ? '阻塞中' : previewReady ? '可确认' : '等待预检' }}
        </div>
      </div>

      <div class="mt-5 rounded-3xl border p-5" :class="resolvePreviewClass(previewTone)">
        <div v-if="previewStats.length" class="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <div
            v-for="item in previewStats"
            :key="`${item.label}-${item.value}`"
            class="rounded-2xl border border-white/8 bg-slate-950/55 px-4 py-3"
          >
            <p class="field-label">{{ item.label }}</p>
            <p class="mt-2 text-xl font-semibold text-white">{{ item.value }}</p>
          </div>
        </div>

        <div v-if="previewHighlights.length" class="mt-5 grid gap-3 md:grid-cols-2">
          <div
            v-for="item in previewHighlights"
            :key="item.key"
            class="rounded-2xl border border-white/8 bg-slate-950/55 px-4 py-3"
          >
            <p v-if="item.title" class="field-label">{{ item.title }}</p>
            <p class="text-sm leading-6 text-slate-100" :class="{ 'mt-2': item.title }">{{ item.value }}</p>
            <p v-if="item.note" class="mt-2 text-xs leading-5 text-slate-400">{{ item.note }}</p>
          </div>
        </div>

        <div v-if="previewWarnings.length" class="mt-5 rounded-2xl border border-amber-300/20 bg-amber-500/8 px-4 py-4 text-amber-50">
          <div class="flex items-start gap-3">
            <TriangleAlert class="mt-0.5 h-5 w-5 shrink-0 text-amber-200" />
            <div>
              <p class="text-sm font-semibold">预检警告</p>
              <ul class="mt-3 space-y-2 text-sm leading-6 text-amber-50/90">
                <li v-for="warning in previewWarnings" :key="warning">{{ warning }}</li>
              </ul>
            </div>
          </div>
        </div>

        <div v-if="previewErrors.length" class="mt-5 rounded-2xl border border-rose-400/20 bg-rose-500/8 px-4 py-4 text-rose-50">
          <div class="flex items-start gap-3">
            <ShieldAlert class="mt-0.5 h-5 w-5 shrink-0 text-rose-200" />
            <div>
              <p class="text-sm font-semibold">阻塞问题</p>
              <ul class="mt-3 space-y-2 text-sm leading-6 text-rose-50/90">
                <li v-for="error in previewErrors" :key="error">{{ error }}</li>
              </ul>
            </div>
          </div>
        </div>

        <p
          v-if="!previewStats.length && !previewHighlights.length && !previewWarnings.length && !previewErrors.length"
          class="text-sm leading-6 text-slate-300"
        >
          这里会显示上层返回的预检摘要，例如 schema 是否通过、预计写入多少项、哪些字段需要迁移、以及是否允许执行确认导入。
        </p>

        <div v-if="previewMeta.length" class="mt-5 flex flex-wrap gap-2">
          <span
            v-for="item in previewMeta"
            :key="item"
            class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200"
          >
            {{ item }}
          </span>
        </div>
      </div>

      <div class="mt-6 flex flex-wrap items-center justify-between gap-3">
        <p class="text-sm leading-6 text-slate-400">
          预检通过后，再由上层决定是否执行真正的导入动作。组件本身不假设接口名、请求路径或回滚策略。
        </p>

        <div class="flex flex-wrap items-center gap-3">
          <button
            type="button"
            class="secondary-btn"
            :disabled="loadingState.confirmImport || loadingState.previewImport"
            @click="handleResetImport"
          >
            重置导入草稿
          </button>
          <button
            type="button"
            class="primary-btn"
            :disabled="!canConfirmImport || loadingState.confirmImport || loadingState.previewImport"
            @click="handleConfirmImport"
          >
            <Upload class="h-4 w-4" />
            {{ loadingState.confirmImport ? '导入中' : '确认导入' }}
          </button>
        </div>
      </div>
    </article>
  </SectionCard>
</template>
