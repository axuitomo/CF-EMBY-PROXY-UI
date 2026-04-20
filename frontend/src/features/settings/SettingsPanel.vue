<script setup>
import { computed, onMounted, reactive, watch } from 'vue';
import {
  BellRing,
  Boxes,
  Cog,
  RefreshCw,
  RotateCcw,
  Save,
  Server,
  ShieldAlert,
  SlidersHorizontal,
  Trash2
} from 'lucide-vue-next';

import SectionCard from '@/components/SectionCard.vue';
import { useUiPreferences } from '@/composables/useUiPreferences';
import ConfigBackupPanel from '@/features/settings/components/ConfigBackupPanel.vue';
import DnsAutoUploadPanel from '@/features/settings/components/DnsAutoUploadPanel.vue';

const props = defineProps({
  adminConsole: {
    type: Object,
    default: null
  }
});

const form = reactive(createEmptyForm());
const feedback = reactive({
  tone: '',
  text: ''
});
const configBackupDraft = reactive(createEmptyConfigBackupDraft());
const configBackupPreview = reactive(createEmptyConfigBackupPreviewState());
const configBackupExportState = reactive(createEmptyConfigBackupExportState());
const configBackupFeedback = reactive(createEmptyPanelFeedback());
const snapshotFeedback = reactive(createEmptyPanelFeedback());
const uiPreferences = useUiPreferences();
const experienceModeSeed = uiPreferences.readSettingsExperienceMode();

const settingsBootstrap = computed(() => props.adminConsole?.settingsBootstrap || {});
const config = computed(() => {
  const rawConfig = settingsBootstrap.value.config;
  return rawConfig && typeof rawConfig === 'object' ? rawConfig : {};
});
const revisions = computed(() => {
  const rawRevisions = settingsBootstrap.value.revisions;
  return rawRevisions && typeof rawRevisions === 'object' ? rawRevisions : {};
});
const loadingSettings = computed(() => Boolean(props.adminConsole?.state?.loading?.settings));
const loadConfigLoading = computed(() => Boolean(props.adminConsole?.state?.loading?.loadConfig));
const previewConfigLoading = computed(() => Boolean(props.adminConsole?.state?.loading?.previewConfig));
const savingConfig = computed(() => Boolean(props.adminConsole?.state?.loading?.saveConfig));
const exportConfigLoading = computed(() => Boolean(props.adminConsole?.state?.loading?.exportConfig));
const exportSettingsLoading = computed(() => Boolean(props.adminConsole?.state?.loading?.exportSettings));
const importFullLoading = computed(() => Boolean(props.adminConsole?.state?.loading?.importFull));
const importSettingsLoading = computed(() => Boolean(props.adminConsole?.state?.loading?.importSettings));
const configSnapshotsLoading = computed(() => Boolean(props.adminConsole?.state?.loading?.configSnapshots));
const clearConfigSnapshotsLoading = computed(() => Boolean(props.adminConsole?.state?.loading?.clearConfigSnapshots));
const restoreConfigSnapshotLoading = computed(() => Boolean(props.adminConsole?.state?.loading?.restoreConfigSnapshot));
const authRequired = computed(() => props.adminConsole?.state?.authRequired === true);
const settingsError = computed(() => String(props.adminConsole?.state?.errors?.settings || '').trim());
const loadConfigError = computed(() => String(props.adminConsole?.state?.errors?.loadConfig || '').trim());
const previewConfigError = computed(() => String(props.adminConsole?.state?.errors?.previewConfig || '').trim());
const saveError = computed(() => String(props.adminConsole?.state?.errors?.saveConfig || '').trim());
const exportConfigError = computed(() => String(props.adminConsole?.state?.errors?.exportConfig || '').trim());
const exportSettingsError = computed(() => String(props.adminConsole?.state?.errors?.exportSettings || '').trim());
const importFullError = computed(() => String(props.adminConsole?.state?.errors?.importFull || '').trim());
const importSettingsError = computed(() => String(props.adminConsole?.state?.errors?.importSettings || '').trim());
const configSnapshotsError = computed(() => String(props.adminConsole?.state?.errors?.configSnapshots || '').trim());
const clearConfigSnapshotsError = computed(() => String(props.adminConsole?.state?.errors?.clearConfigSnapshots || '').trim());
const restoreConfigSnapshotError = computed(() => String(props.adminConsole?.state?.errors?.restoreConfigSnapshot || '').trim());

const baseFormState = computed(() => buildFormFromConfig(config.value));
const hasChanges = computed(() => serializeFormState(form) !== serializeFormState(baseFormState.value));
const anySettingsBusy = computed(() => (
  loadingSettings.value
  || loadConfigLoading.value
  || previewConfigLoading.value
  || savingConfig.value
  || exportConfigLoading.value
  || importFullLoading.value
  || exportSettingsLoading.value
  || importSettingsLoading.value
  || configSnapshotsLoading.value
  || clearConfigSnapshotsLoading.value
  || restoreConfigSnapshotLoading.value
));
const currentNodeCount = computed(() => (
  Array.isArray(settingsBootstrap.value.nodes) ? settingsBootstrap.value.nodes.length : 0
));
const currentSnapshotCount = computed(() => (
  Array.isArray(settingsBootstrap.value.configSnapshots) ? settingsBootstrap.value.configSnapshots.length : 0
));
const configSnapshots = computed(() => (
  Array.isArray(settingsBootstrap.value.configSnapshots) ? settingsBootstrap.value.configSnapshots : []
));
const latestConfigSnapshot = computed(() => (
  configSnapshots.value.length > 0 && isPlainObject(configSnapshots.value[0]) ? configSnapshots.value[0] : null
));
const configBackupPanelData = computed(() => ({
  summary: {
    configRevision: revisions.value.configRevision,
    generatedAt: settingsBootstrap.value.generatedAt,
    tags: [
      `当前节点 ${currentNodeCount.value} 个`,
      `配置快照 ${currentSnapshotCount.value} 份`,
      '通过 Worker /admin action'
    ]
  },
  exportState: {
    ...configBackupExportState,
    title: '完整备份 / 设置备份',
    description: '这里同时承接 Worker 的 `exportConfig / exportSettings`，完整备份包含 config + nodes，设置备份只包含 config。',
    format: 'JSON',
    buttonLabel: '下载完整备份',
    buttonHint: '支持分别导出完整备份和 settings-only 备份。',
    actions: [
      {
        key: 'export-full-config',
        label: '下载完整备份',
        hint: '导出当前 config 与 nodes 的完整快照。',
        tone: 'primary',
        actionName: 'exportConfig',
        disabled: anySettingsBusy.value
      },
      {
        key: 'export-settings-only',
        label: '下载设置备份',
        hint: '只导出 config，不包含 nodes。',
        tone: 'secondary',
        actionName: 'exportSettings',
        disabled: anySettingsBusy.value
      }
    ]
  },
  importDraft: configBackupDraft,
  previewState: configBackupPreview,
  feedback: configBackupFeedback,
  permissions: {
    canPreviewImport: !authRequired.value && !anySettingsBusy.value,
    canConfirmImport: !authRequired.value && !anySettingsBusy.value && configBackupPreview.canConfirm !== false
  },
  authRequired: authRequired.value,
  loginHref: props.adminConsole?.loginUrl || ''
}));
const configBackupPanelLoading = computed(() => ({
  refreshSummary: loadConfigLoading.value,
  exportConfig: exportConfigLoading.value || exportSettingsLoading.value,
  previewImport: previewConfigLoading.value,
  confirmImport: importFullLoading.value || importSettingsLoading.value,
  selectFile: false
}));

const summaryTiles = computed(() => [
  {
    title: '管理域名',
    value: String(settingsBootstrap.value.hostDomain || '未配置').trim() || '未配置',
    note: String(settingsBootstrap.value.legacyHost || '无 legacy host').trim() || '无 legacy host'
  },
  {
    title: '节点与快照',
    value: `${Array.isArray(settingsBootstrap.value.nodes) ? settingsBootstrap.value.nodes.length : 0} / ${Array.isArray(settingsBootstrap.value.configSnapshots) ? settingsBootstrap.value.configSnapshots.length : 0}`,
    note: '节点数 / 配置快照数'
  },
  {
    title: '当前模式',
    value: form.settingsExperienceMode === 'expert' ? 'Expert' : 'Novice',
    note: `协议策略 ${form.protocolStrategy || 'compat'}`
  },
  {
    title: 'Config Revision',
    value: compactRevision(revisions.value.configRevision),
    note: formatDateTime(settingsBootstrap.value.generatedAt)
  }
]);

watch(baseFormState, (nextState) => {
  Object.assign(form, nextState);
}, { immediate: true, deep: true });

watch([
  settingsError,
  saveError,
  loadConfigError,
  previewConfigError,
  exportConfigError,
  exportSettingsError,
  importFullError,
  importSettingsError
], ([
  nextSettingsError,
  nextSaveError,
  nextLoadConfigError,
  nextPreviewConfigError,
  nextExportConfigError,
  nextExportSettingsError,
  nextImportFullError,
  nextImportSettingsError
]) => {
  const nextError = nextImportSettingsError
    || nextImportFullError
    || nextExportSettingsError
    || nextExportConfigError
    || nextPreviewConfigError
    || nextLoadConfigError
    || nextSaveError
    || nextSettingsError;

  if (nextError) {
    feedback.tone = 'error';
    feedback.text = nextError;
    return;
  }
  if (feedback.tone === 'error') {
    feedback.tone = '';
    feedback.text = '';
  }
});

watch(() => form.settingsExperienceMode, (nextMode) => {
  uiPreferences.persistSettingsExperienceMode(nextMode);
});

onMounted(() => {
  if (!props.adminConsole) return;
  if (Object.keys(config.value).length > 0) return;
  void props.adminConsole.hydrateSettings();
});

async function handleRefresh() {
  feedback.tone = '';
  feedback.text = '';
  await props.adminConsole?.hydrateSettings();
}

function handleReset() {
  Object.assign(form, buildFormFromConfig(config.value));
  feedback.tone = 'success';
  feedback.text = '已恢复到最近一次从 Worker 读取到的配置。';
}

async function handleSave() {
  if (!props.adminConsole || savingConfig.value) return;

  feedback.tone = '';
  feedback.text = '';

  const nextConfig = buildConfigPayload(config.value, form);
  const result = await props.adminConsole.saveConfig(nextConfig, {
    section: 'settings',
    source: 'frontend-vue'
  });

  if (!result) return;

  feedback.tone = 'success';
  feedback.text = `设置已保存，时间 ${formatDateTime(result.savedAt)}。`;
}

const configBackupPanelActions = {
  refreshSummary: handleConfigBackupRefresh,
  exportConfig: handleConfigBackupExport,
  exportSettings: handleConfigBackupExport,
  updateImportText: handleConfigBackupImportText,
  updateImportDraft: handleConfigBackupImportDraft,
  selectFile: handleConfigBackupImportFile,
  clearSelectedFile: handleConfigBackupClearSelectedFile,
  previewImport: handleConfigBackupPreview,
  confirmImport: handleConfigBackupConfirm,
  resetImport: handleConfigBackupReset
};

function createEmptyPanelFeedback() {
  return {
    tone: '',
    title: '',
    text: ''
  };
}

function createEmptyConfigBackupDraft() {
  return {
    text: '',
    sourceLabel: '',
    file: null,
    fileName: '',
    fileSize: null,
    accept: '.json,application/json',
    placeholder: '支持上传旧版导出的 JSON，也支持直接粘贴配置快照文本。正式导入前会先走 Worker 预检。'
  };
}

function createEmptyConfigBackupPreviewState() {
  return {
    tone: '',
    title: '',
    description: '',
    warnings: [],
    errors: [],
    items: [],
    stats: [],
    ready: false,
    canConfirm: false,
    importedCount: 0,
    skippedCount: null,
    configRevision: '',
    generatedAt: ''
  };
}

function createEmptyConfigBackupExportState() {
  return {
    lastExportedAt: '',
    note: '导出内容会包含完整 config 和 nodes，方便直接回滚或迁移到新环境。'
  };
}

function resetConfigBackupPreview(nextState = {}) {
  Object.assign(configBackupPreview, createEmptyConfigBackupPreviewState(), nextState);
}

function setConfigBackupFeedback(tone = '', title = '', text = '') {
  Object.assign(configBackupFeedback, {
    tone,
    title,
    text
  });
}

function clearConfigBackupFeedback() {
  Object.assign(configBackupFeedback, createEmptyPanelFeedback());
}

function setSnapshotFeedback(tone = '', title = '', text = '') {
  Object.assign(snapshotFeedback, {
    tone,
    title,
    text
  });
}

function clearSnapshotFeedback() {
  Object.assign(snapshotFeedback, createEmptyPanelFeedback());
}

function applyConfigBackupDraftUpdate(patch = {}, options = {}) {
  const nextPatch = isPlainObject(patch) ? patch : {};
  Object.assign(configBackupDraft, nextPatch);

  if (options.resetPreview !== false) resetConfigBackupPreview();
  if (options.clearFeedback !== false) clearConfigBackupFeedback();
  return true;
}

function handleConfigBackupImportText(payload = {}) {
  return applyConfigBackupDraftUpdate(
    isPlainObject(payload?.patch) ? payload.patch : { text: payload?.value ?? '' }
  );
}

function handleConfigBackupImportDraft(payload = {}) {
  const fallbackPatch = isPlainObject(payload?.patch)
    ? payload.patch
    : (String(payload?.key || '').trim() ? { [payload.key]: payload.value } : {});
  return applyConfigBackupDraftUpdate(fallbackPatch);
}

function handleConfigBackupImportFile(payload = {}) {
  return applyConfigBackupDraftUpdate(isPlainObject(payload?.patch) ? payload.patch : {});
}

function handleConfigBackupClearSelectedFile() {
  return applyConfigBackupDraftUpdate({
    file: null,
    fileName: '',
    fileSize: null
  });
}

function handleConfigBackupReset() {
  return applyConfigBackupDraftUpdate(createEmptyConfigBackupDraft());
}

async function handleConfigBackupRefresh() {
  if (!props.adminConsole?.loadConfig) return null;

  clearConfigBackupFeedback();
  const [configResult, snapshotsResult] = await Promise.all([
    props.adminConsole.loadConfig(),
    typeof props.adminConsole?.getConfigSnapshots === 'function'
      ? props.adminConsole.getConfigSnapshots()
      : Promise.resolve(null)
  ]);
  if (!configResult) {
    if (loadConfigError.value) {
      setConfigBackupFeedback('error', '刷新失败', loadConfigError.value);
    }
    return null;
  }

  setConfigBackupFeedback(
    'success',
    '配置摘要已刷新',
    `已从 Worker 重新读取配置，Revision ${compactRevision(configResult.revisions?.configRevision)}，快照 ${snapshotsResult?.snapshots?.length ?? currentSnapshotCount.value} 份。`
  );
  return {
    config: configResult,
    snapshots: snapshotsResult
  };
}

async function handleConfigBackupExport(payload = {}) {
  const requestedAction = String(payload?.action?.actionName || 'exportConfig').trim();
  const isSettingsOnlyAction = requestedAction === 'exportSettings';
  const exportAction = isSettingsOnlyAction
    ? props.adminConsole?.exportSettings
    : props.adminConsole?.exportConfig;
  if (typeof exportAction !== 'function') return null;

  clearConfigBackupFeedback();
  const exportedPayload = await exportAction();
  if (!exportedPayload) {
    const message = isSettingsOnlyAction
      ? (exportSettingsError.value || '设置备份导出失败')
      : (exportConfigError.value || '完整配置导出失败');
    if (message) {
      setConfigBackupFeedback('error', '导出失败', message);
    }
    return null;
  }

  const exportTime = String(exportedPayload.exportTime || new Date().toISOString()).trim() || new Date().toISOString();
  const backupType = String(exportedPayload.type || requestedAction).trim();
  const isSettingsOnlyBackup = backupType === 'settings-only' || requestedAction === 'exportSettings';
  const versionLabel = String(exportedPayload.version || 'unknown').trim() || 'unknown';
  configBackupExportState.lastExportedAt = exportTime;
  configBackupExportState.note = isSettingsOnlyBackup
    ? `版本 ${versionLabel}，仅包含 config。`
    : `版本 ${versionLabel}，节点 ${Array.isArray(exportedPayload.nodes) ? exportedPayload.nodes.length : 0} 个。`;

  downloadJsonFile(exportedPayload, buildConfigBackupFilename(exportedPayload));
  setConfigBackupFeedback(
    'success',
    '导出成功',
    `${isSettingsOnlyBackup ? '设置备份' : '完整备份'}已下载，导出时间 ${formatDateTime(exportTime)}。`
  );
  return exportedPayload;
}

async function handleConfigBackupPreview() {
  if (!props.adminConsole?.previewConfig) return null;

  clearConfigBackupFeedback();
  const prepared = await parseConfigBackupImportDraft();
  if (prepared.errors.length) {
    resetConfigBackupPreview({
      tone: 'error',
      title: '导入内容无法预检',
      description: '先修正以下问题，再继续调用 Worker 预检。',
      errors: prepared.errors,
      warnings: prepared.warnings,
      stats: [
        { label: '配置键', value: String(prepared.meta.configKeyCount) },
        { label: '节点', value: String(prepared.meta.nodeCount) }
      ],
      items: buildConfigBackupPreviewItems(prepared.meta),
      generatedAt: new Date().toISOString()
    });
    setConfigBackupFeedback('error', '预检失败', prepared.errors[0]);
    return null;
  }

  const preview = await props.adminConsole.previewConfig(prepared.payload.config);
  if (!preview) {
    const message = previewConfigError.value || '配置预检失败';
    resetConfigBackupPreview({
      tone: 'error',
      title: 'Worker 预检失败',
      description: 'Worker 没有接受这份配置草稿，当前不会放行正式导入。',
      errors: [message],
      warnings: prepared.warnings,
      stats: [
        { label: '配置键', value: String(prepared.meta.configKeyCount) },
        { label: '节点', value: String(prepared.meta.nodeCount) }
      ],
      items: buildConfigBackupPreviewItems(prepared.meta),
      generatedAt: new Date().toISOString()
    });
    setConfigBackupFeedback('error', '预检失败', message);
    return null;
  }

  const migration = isPlainObject(preview.migration) ? preview.migration : {};
  const sanitizedConfig = isPlainObject(preview.config) ? preview.config : {};
  const migratedKeys = parseLooseTextList(migration.migratedConfigKeys);
  const legacyKeysPresent = parseLooseTextList(migration.legacyKeysPresent);
  const deletedLegacyFieldCount = Math.max(0, Number.parseInt(migration.deletedLegacyFieldCount, 10) || 0);
  const warnings = [...prepared.warnings];

  if (prepared.meta.nodeCount > 0) {
    warnings.push(`包含 ${prepared.meta.nodeCount} 个节点，节点合法性会在正式导入时继续校验。`);
  }
  if (prepared.meta.nodeCount > 0 && prepared.meta.configKeyCount === 0) {
    warnings.push('这份备份只包含 nodes，config 不会发生变化。');
  }
  if (legacyKeysPresent.length > 0) {
    warnings.push(`检测到旧字段：${legacyKeysPresent.join(', ')}。`);
  }
  if (deletedLegacyFieldCount > 0) {
    warnings.push(`预计会清理 ${deletedLegacyFieldCount} 个遗留字段。`);
  }

  resetConfigBackupPreview({
    tone: warnings.length > 0 ? 'warning' : 'success',
    title: warnings.length > 0 ? '预检完成，请确认警告' : '预检通过，可以导入',
    description: prepared.meta.nodeCount > 0
      ? '配置部分已经通过 Worker 预检，节点会在正式导入时继续校验并在必要时触发回滚。'
      : '这份配置快照已经通过 Worker 预检，可以继续执行正式导入。',
    warnings,
    errors: [],
    items: buildConfigBackupPreviewItems(prepared.meta, {
      sanitizedConfigKeyCount: Object.keys(sanitizedConfig).length,
      migratedKeys,
      legacyKeysPresent
    }),
    stats: [
      { label: '配置键', value: String(Object.keys(sanitizedConfig).length) },
      { label: '节点', value: String(prepared.meta.nodeCount) },
      { label: '迁移键', value: String(migratedKeys.length) },
      { label: '警告', value: String(warnings.length) }
    ],
    ready: true,
    canConfirm: true,
    importedCount: Object.keys(sanitizedConfig).length,
    configRevision: revisions.value.configRevision,
    generatedAt: new Date().toISOString()
  });

  setConfigBackupFeedback(
    warnings.length > 0 ? 'warning' : 'success',
    '预检完成',
    warnings.length > 0 ? '预检已完成，请先确认警告再执行正式导入。' : '预检通过，可以执行正式导入。'
  );
  return preview;
}

async function handleConfigBackupConfirm() {
  clearConfigBackupFeedback();
  const prepared = await parseConfigBackupImportDraft();
  const settingsOnlyImport = prepared.meta.backupType === 'settings-only' || prepared.meta.nodeCount === 0;
  const importAction = settingsOnlyImport
    ? props.adminConsole?.importSettings
    : props.adminConsole?.importFull;
  if (typeof importAction !== 'function') return null;

  if (prepared.errors.length) {
    setConfigBackupFeedback('error', '导入失败', prepared.errors[0]);
    if (!configBackupPreview.ready) {
      resetConfigBackupPreview({
        tone: 'error',
        title: '导入内容无法提交',
        description: '先修正以下问题，再继续导入。',
        errors: prepared.errors,
        warnings: prepared.warnings,
        items: buildConfigBackupPreviewItems(prepared.meta),
        stats: [
          { label: '配置键', value: String(prepared.meta.configKeyCount) },
          { label: '节点', value: String(prepared.meta.nodeCount) }
        ],
        generatedAt: new Date().toISOString()
      });
    }
    return null;
  }

  if (!configBackupPreview.ready) {
    const preview = await handleConfigBackupPreview();
    if (!preview || configBackupPreview.canConfirm !== true) return null;
  }

  const result = await importAction(prepared.payload, {
    section: settingsOnlyImport ? 'settings' : 'all',
    source: 'frontend-vue'
  });
  if (!result) {
    const message = settingsOnlyImport
      ? (importSettingsError.value || '设置备份导入失败')
      : (importFullError.value || '完整配置导入失败');
    resetConfigBackupPreview({
      ...configBackupPreview,
      tone: 'error',
      title: '正式导入失败',
      description: 'Worker 没有接受这次完整导入，请根据错误信息修正后重试。',
      errors: [message],
      canConfirm: true,
      generatedAt: new Date().toISOString()
    });
    setConfigBackupFeedback('error', '导入失败', message);
    return null;
  }

  const resultConfig = isPlainObject(result.config) ? result.config : {};
  const resultRevision = result.revisions?.configRevision || revisions.value.configRevision;
  const resultSnapshotCount = Array.isArray(result.configSnapshots) ? result.configSnapshots.length : currentSnapshotCount.value;
  const generatedAt = result.savedAt || new Date().toISOString();

  if (settingsOnlyImport) {
    resetConfigBackupPreview({
      tone: 'success',
      title: '设置导入完成',
      description: 'Worker 已更新配置，并把新的 revision 与快照历史同步回当前设置页。',
      warnings: [],
      errors: [],
      items: [
        {
          key: 'import-source',
          title: '导入来源',
          value: prepared.meta.sourceLabel,
          note: prepared.meta.version ? `备份版本 ${prepared.meta.version}` : '未携带版本信息'
        },
        {
          key: 'import-revision',
          title: 'Config Revision',
          value: compactRevision(resultRevision),
          note: '新的配置 revision 已写回前端桥接层'
        },
        {
          key: 'import-snapshots',
          title: '快照历史',
          value: String(resultSnapshotCount),
          note: '设置快照历史已经同步刷新'
        }
      ],
      stats: [
        { label: '配置键', value: String(Object.keys(resultConfig).length) },
        { label: 'Revision', value: compactRevision(resultRevision) },
        { label: '快照', value: String(resultSnapshotCount) }
      ],
      ready: true,
      canConfirm: false,
      importedCount: Object.keys(resultConfig).length,
      configRevision: resultRevision,
      backupType: 'settings-only',
      generatedAt
    });

    setConfigBackupFeedback(
      'success',
      '导入成功',
      `设置备份已导入，当前 Revision ${compactRevision(resultRevision)}。`
    );
    return result;
  }

  resetConfigBackupPreview({
    tone: 'success',
    title: '导入完成',
    description: 'Worker 已更新配置与节点，并把新的 revision 回写到了前端桥接层。',
    warnings: [],
    errors: [],
    items: [
      {
        key: 'import-source',
        title: '导入来源',
        value: prepared.meta.sourceLabel,
        note: prepared.meta.version ? `备份版本 ${prepared.meta.version}` : '未携带版本信息'
      },
      {
        key: 'import-revision',
        title: 'Config Revision',
        value: compactRevision(result.revisions?.configRevision),
        note: '新的 bootstrap 已同步到当前页面'
      },
      {
        key: 'import-nodes',
        title: '节点数量',
        value: String(Array.isArray(result.nodes) ? result.nodes.length : prepared.meta.nodeCount),
        note: '节点列表已经与 Worker 返回结果对齐'
      }
    ],
    stats: [
      { label: '配置键', value: String(Object.keys(resultConfig).length) },
      { label: '节点', value: String(Array.isArray(result.nodes) ? result.nodes.length : prepared.meta.nodeCount) },
      { label: 'Revision', value: compactRevision(resultRevision) }
    ],
    ready: true,
    canConfirm: false,
    importedCount: Object.keys(resultConfig).length,
    configRevision: resultRevision,
    generatedAt
  });

  setConfigBackupFeedback(
    'success',
    '导入成功',
    `完整配置与节点已导入，当前节点 ${Array.isArray(result.nodes) ? result.nodes.length : prepared.meta.nodeCount} 个。`
  );
  return result;
}

async function handleRefreshConfigSnapshots() {
  if (!props.adminConsole?.getConfigSnapshots) return null;

  clearSnapshotFeedback();
  const result = await props.adminConsole.getConfigSnapshots();
  if (!result) {
    if (configSnapshotsError.value) {
      setSnapshotFeedback('error', '刷新失败', configSnapshotsError.value);
    }
    return null;
  }

  setSnapshotFeedback('success', '快照已刷新', `当前共 ${result.snapshots.length} 份配置快照。`);
  return result;
}

async function handleClearConfigSnapshots() {
  if (!props.adminConsole?.clearConfigSnapshots || clearConfigSnapshotsLoading.value) return null;
  if (typeof window !== 'undefined') {
    const confirmed = window.confirm('确认清空所有配置快照吗？当前生效配置不会被删除。');
    if (!confirmed) return null;
  }

  clearSnapshotFeedback();
  const result = await props.adminConsole.clearConfigSnapshots();
  if (!result) {
    if (clearConfigSnapshotsError.value) {
      setSnapshotFeedback('error', '清空失败', clearConfigSnapshotsError.value);
    }
    return null;
  }

  setSnapshotFeedback('success', '快照已清空', 'Worker 中记录的配置快照已清空，当前生效配置保持不变。');
  return result;
}

async function handleRestoreConfigSnapshot(snapshot = {}) {
  if (!props.adminConsole?.restoreConfigSnapshot || restoreConfigSnapshotLoading.value) return null;

  const snapshotId = String(snapshot?.id || '').trim();
  if (!snapshotId) return null;
  if (typeof window !== 'undefined') {
    const confirmed = window.confirm(
      `确认恢复 ${formatDateTime(snapshot.createdAt)} 的配置快照吗？这会覆盖当前生效配置。`
    );
    if (!confirmed) return null;
  }

  clearSnapshotFeedback();
  const result = await props.adminConsole.restoreConfigSnapshot(snapshotId);
  if (!result) {
    if (restoreConfigSnapshotError.value) {
      setSnapshotFeedback('error', '恢复失败', restoreConfigSnapshotError.value);
    }
    return null;
  }

  feedback.tone = 'success';
  feedback.text = `已从配置快照恢复，时间 ${formatDateTime(snapshot.createdAt)}。`;
  setSnapshotFeedback(
    'success',
    '恢复完成',
    `已恢复到历史快照，当前 Revision ${compactRevision(result.revisions?.configRevision)}。`
  );
  return result;
}

async function parseConfigBackupImportDraft() {
  const meta = {
    sourceLabel: String(configBackupDraft.sourceLabel || configBackupDraft.fileName || '手动输入').trim() || '手动输入',
    version: '',
    exportTime: '',
    backupType: '',
    configKeyCount: 0,
    nodeCount: 0
  };

  let rawText = '';
  try {
    rawText = await readConfigBackupDraftText();
  } catch (error) {
    return {
      payload: null,
      warnings: [],
      errors: [getLocalErrorMessage(error, '读取备份文件失败')],
      meta
    };
  }

  if (!rawText.trim()) {
    return {
      payload: null,
      warnings: [],
      errors: ['请先选择备份文件或粘贴 JSON 文本。'],
      meta
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch (error) {
    return {
      payload: null,
      warnings: [],
      errors: [getLocalErrorMessage(error, '导入内容不是有效 JSON。')],
      meta
    };
  }

  if (!isPlainObject(parsed)) {
    return {
      payload: null,
      warnings: [],
      errors: ['导入内容必须是 JSON 对象。'],
      meta
    };
  }

  const hasWrappedBackup = Object.prototype.hasOwnProperty.call(parsed, 'config') || Array.isArray(parsed.nodes);
  const rawNodes = hasWrappedBackup && Array.isArray(parsed.nodes) ? parsed.nodes : [];
  const nodes = rawNodes.filter(isPlainObject);
  const warnings = [];
  if (rawNodes.length !== nodes.length) {
    warnings.push(`检测到 ${rawNodes.length - nodes.length} 个非对象节点，正式导入时会自动忽略。`);
  }

  const configPayload = hasWrappedBackup
    ? (isPlainObject(parsed.config) ? parsed.config : {})
    : parsed;
  const errors = [];
  if (!isPlainObject(configPayload)) {
    errors.push('配置部分必须是 JSON 对象。');
  }

  meta.version = String(parsed.version || '').trim();
  meta.exportTime = String(parsed.exportTime || '').trim();
  const explicitBackupType = String(parsed.type || '').trim().toLowerCase();
  meta.backupType = explicitBackupType === 'settings-only'
    ? 'settings-only'
    : (nodes.length > 0 ? 'full-backup' : 'settings-only');
  meta.configKeyCount = isPlainObject(configPayload) ? Object.keys(configPayload).length : 0;
  meta.nodeCount = nodes.length;

  if (meta.configKeyCount === 0 && meta.nodeCount === 0) {
    errors.push('导入内容里没有可用的 config 或 nodes。');
  }

  return {
    payload: {
      config: isPlainObject(configPayload) ? configPayload : {},
      nodes
    },
    warnings,
    errors,
    meta
  };
}

async function readConfigBackupDraftText() {
  const text = String(configBackupDraft.text || '');
  if (text.trim()) return text;

  const file = configBackupDraft.file;
  if (file && typeof file.text === 'function') {
    return file.text();
  }

  return '';
}

function buildConfigBackupPreviewItems(meta = {}, extras = {}) {
  const backupType = String(meta.backupType || '').trim().toLowerCase();
  const items = [
    {
      key: 'import-kind',
      title: '导入类型',
      value: backupType === 'settings-only'
        ? '设置备份'
        : Number(meta.nodeCount) > 0
          ? '完整备份'
          : '配置快照',
      note: String(meta.sourceLabel || '未标记来源').trim() || '未标记来源'
    },
    {
      key: 'config-keys',
      title: '配置键数',
      value: String(extras.sanitizedConfigKeyCount ?? meta.configKeyCount ?? 0),
      note: `原始输入 ${meta.configKeyCount ?? 0} 个键`
    }
  ];

  if (Number(meta.nodeCount) > 0) {
    items.push({
      key: 'nodes',
      title: '节点数量',
      value: String(meta.nodeCount),
      note: '节点会在正式导入阶段继续校验'
    });
  }

  if (String(meta.version || '').trim() || String(meta.exportTime || '').trim()) {
    items.push({
      key: 'snapshot-meta',
      title: '备份元数据',
      value: String(meta.version || '未标版本').trim() || '未标版本',
      note: String(meta.exportTime || '').trim() ? `导出时间 ${formatDateTime(meta.exportTime)}` : '未携带导出时间'
    });
  }

  const migratedKeys = Array.isArray(extras.migratedKeys) ? extras.migratedKeys : [];
  if (migratedKeys.length > 0) {
    items.push({
      key: 'migrated-keys',
      title: '迁移字段',
      value: migratedKeys.join(', '),
      note: '这些字段已经被 Worker 识别为需要迁移'
    });
  }

  const legacyKeysPresent = Array.isArray(extras.legacyKeysPresent) ? extras.legacyKeysPresent : [];
  if (legacyKeysPresent.length > 0) {
    items.push({
      key: 'legacy-keys',
      title: '旧字段',
      value: legacyKeysPresent.join(', '),
      note: '正式导入时会按 Worker 的兼容逻辑处理'
    });
  }

  return items;
}

function buildConfigBackupFilename(payload = {}) {
  const type = String(payload.type || '').trim().toLowerCase();
  const version = sanitizeFilenamePart(String(payload.version || 'snapshot').trim() || 'snapshot');
  const prefix = type === 'settings-only' ? 'cf-emby-proxy-settings' : 'cf-emby-proxy-backup';
  return `${prefix}-${version}-${formatFileTimestamp(payload.exportTime)}.json`;
}

function formatFileTimestamp(value = '') {
  const date = new Date(String(value || '').trim() || Date.now());
  if (Number.isNaN(date.getTime())) return 'snapshot';

  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const hour = String(date.getHours()).padStart(2, '0');
  const minute = String(date.getMinutes()).padStart(2, '0');
  const second = String(date.getSeconds()).padStart(2, '0');
  return `${year}${month}${day}-${hour}${minute}${second}`;
}

function sanitizeFilenamePart(value = '') {
  return String(value || '').trim()
    .replace(/[^a-zA-Z0-9._-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '') || 'snapshot';
}

function downloadJsonFile(payload, fileName = 'config-backup.json') {
  if (typeof window === 'undefined' || typeof document === 'undefined') return;

  const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], {
    type: 'application/json;charset=utf-8'
  });
  const objectUrl = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = objectUrl;
  anchor.download = fileName;
  anchor.click();
  window.setTimeout(() => window.URL.revokeObjectURL(objectUrl), 0);
}

function getLocalErrorMessage(error, fallbackMessage = '未知错误') {
  return String(error?.message || fallbackMessage).trim() || fallbackMessage;
}

function createEmptyForm() {
  return {
    settingsExperienceMode: 'novice',
    uiRadiusPx: '10',
    protocolStrategy: 'compat',
    routingDecisionMode: 'legacy',
    defaultPlaybackInfoMode: 'passthrough',
    defaultRealClientIpMode: 'forward',
    defaultMediaAuthMode: 'auto',
    enableHostPrefixProxy: false,
    enablePrewarm: true,
    prewarmDepth: 'poster',
    prewarmCacheTtl: '120',
    prewarmPrefetchBytes: '4194304',
    disablePrewarmPrefetch: false,
    playbackInfoCacheEnabled: true,
    playbackInfoCacheTtlSec: '60',
    videoProgressForwardEnabled: true,
    videoProgressForwardIntervalSec: '3',
    directStaticAssets: false,
    directHlsDash: false,
    multiLinkCopyPanelEnabled: false,
    dashboardShowD1WriteHotspot: false,
    dashboardShowKvD1Status: false,
    pingTimeout: '5000',
    pingCacheMinutes: '10',
    upstreamTimeoutMs: '8000',
    upstreamRetryAttempts: '0',
    geoAllowlist: '',
    geoBlocklist: '',
    ipBlacklist: '',
    rateLimitRpm: '0',
    cacheTtlImages: '30',
    corsOrigins: '',
    jwtExpiryDays: '30',
    hedgeFailoverEnabled: false,
    hedgeProbePath: '/emby/system/ping',
    hedgeProbeTimeoutMs: '2500',
    hedgeProbeParallelism: '2',
    hedgeWaitTimeoutMs: '3000',
    hedgeLockTtlMs: '5000',
    hedgePreferredTtlSec: '300',
    hedgeFailureCooldownSec: '30',
    hedgeWakeJitterMs: '200',
    sourceDirectNodes: '',
    logEnabled: true,
    logSearchMode: 'fts',
    logWriteMode: 'info',
    logWriteClientIp: true,
    logWriteColo: true,
    logWriteUa: true,
    logDisplayClientIp: true,
    logDisplayColo: true,
    logDisplayUa: true,
    logWriteImagePoster: false,
    logWriteMediaMetadata: false,
    logRetentionDays: '7',
    logWriteDelayMinutes: '20',
    logFlushCountThreshold: '50',
    logBatchChunkSize: '50',
    logBatchRetryCount: '2',
    logBatchRetryBackoffMs: '75',
    scheduledLeaseMs: '300000',
    scheduleUtcOffsetMinutes: '480',
    dnsAutoUploadEnabled: false,
    dnsAutoUploadScheduleMode: 'clock_queue',
    dnsAutoUploadClockTimes: '03:00',
    dnsAutoUploadIntervalMinutes: '60',
    dnsAutoUploadWindowStartTime: '00:00',
    dnsAutoUploadWindowEndTime: '23:59',
    dnsAutoUploadTopN: '10',
    dnsAutoUploadCountryCodes: '',
    dnsAutoUploadRecordTypes: 'A',
    dnsAutoUploadNotifyEnabled: false,
    dnsAutoUploadNotifyDelayMinutes: '5',
    tgDailyReportEnabled: false,
    tgDailyReportSummaryEnabled: false,
    tgDailyReportKvEnabled: false,
    tgDailyReportD1Enabled: false,
    tgDailyReportClockTimes: '09:00',
    tgAlertDroppedBatchThreshold: '0',
    tgAlertFlushRetryThreshold: '0',
    tgAlertOnScheduledFailure: false,
    tgAlertKvUsageEnabled: false,
    tgAlertKvUsageThresholdPercent: '80',
    tgAlertD1UsageEnabled: false,
    tgAlertD1UsageThresholdPercent: '80',
    tgAlertCooldownMinutes: '30',
    cfQuotaPlanOverride: '',
    cfQuotaPlanCacheMinutes: '60',
    cfAccountId: '',
    cfZoneId: '',
    cfApiToken: '',
    cfKvNamespaceId: '',
    cfD1DatabaseId: '',
    dnsDefaultFallbackCname: '',
    tgBotToken: '',
    tgChatId: ''
  };
}

function buildFormFromConfig(rawConfig = {}) {
  const currentConfig = rawConfig && typeof rawConfig === 'object' ? rawConfig : {};
  const hasExplicitDailyReportKinds = [
    'tgDailyReportSummaryEnabled',
    'tgDailyReportKvEnabled',
    'tgDailyReportD1Enabled'
  ].some((key) => Object.prototype.hasOwnProperty.call(currentConfig, key));
  const hasExplicitExperienceMode = Object.prototype.hasOwnProperty.call(currentConfig, 'settingsExperienceMode');

  return {
    settingsExperienceMode: resolveSelectValue(
      currentConfig.settingsExperienceMode,
      hasExplicitExperienceMode ? 'novice' : experienceModeSeed
    ),
    uiRadiusPx: formatIntegerInput(currentConfig.uiRadiusPx, 10),
    protocolStrategy: resolveSelectValue(currentConfig.protocolStrategy, 'compat'),
    routingDecisionMode: resolveSelectValue(currentConfig.routingDecisionMode, 'legacy'),
    defaultPlaybackInfoMode: resolveSelectValue(currentConfig.defaultPlaybackInfoMode, 'passthrough'),
    defaultRealClientIpMode: resolveSelectValue(currentConfig.defaultRealClientIpMode, 'forward'),
    defaultMediaAuthMode: resolveSelectValue(currentConfig.defaultMediaAuthMode, 'auto'),
    enableHostPrefixProxy: currentConfig.enableHostPrefixProxy === true,
    enablePrewarm: currentConfig.enablePrewarm !== false,
    prewarmDepth: resolveSelectValue(currentConfig.prewarmDepth, 'poster'),
    prewarmCacheTtl: formatIntegerInput(currentConfig.prewarmCacheTtl, 120),
    prewarmPrefetchBytes: formatIntegerInput(currentConfig.prewarmPrefetchBytes, 4194304),
    disablePrewarmPrefetch: currentConfig.disablePrewarmPrefetch === true,
    playbackInfoCacheEnabled: currentConfig.playbackInfoCacheEnabled !== false,
    playbackInfoCacheTtlSec: formatIntegerInput(currentConfig.playbackInfoCacheTtlSec, 60),
    videoProgressForwardEnabled: currentConfig.videoProgressForwardEnabled !== false,
    videoProgressForwardIntervalSec: formatIntegerInput(currentConfig.videoProgressForwardIntervalSec, 3),
    directStaticAssets: currentConfig.directStaticAssets === true,
    directHlsDash: currentConfig.directHlsDash === true,
    multiLinkCopyPanelEnabled: currentConfig.multiLinkCopyPanelEnabled === true,
    dashboardShowD1WriteHotspot: currentConfig.dashboardShowD1WriteHotspot === true,
    dashboardShowKvD1Status: currentConfig.dashboardShowKvD1Status === true,
    pingTimeout: formatIntegerInput(currentConfig.pingTimeout, 5000),
    pingCacheMinutes: formatIntegerInput(currentConfig.pingCacheMinutes, 10),
    upstreamTimeoutMs: formatIntegerInput(currentConfig.upstreamTimeoutMs, 8000),
    upstreamRetryAttempts: formatIntegerInput(currentConfig.upstreamRetryAttempts, 0),
    geoAllowlist: joinTextList(parseRegionCodeList(currentConfig.geoAllowlist)),
    geoBlocklist: joinTextList(parseRegionCodeList(currentConfig.geoBlocklist)),
    ipBlacklist: joinTextList(parseLooseTextList(currentConfig.ipBlacklist)),
    rateLimitRpm: formatIntegerInput(currentConfig.rateLimitRpm, 0),
    cacheTtlImages: formatIntegerInput(currentConfig.cacheTtlImages, 30),
    corsOrigins: joinTextList(parseLooseTextList(currentConfig.corsOrigins)),
    jwtExpiryDays: formatIntegerInput(currentConfig.jwtExpiryDays, 30),
    hedgeFailoverEnabled: currentConfig.hedgeFailoverEnabled === true,
    hedgeProbePath: resolveSelectValue(currentConfig.hedgeProbePath, '/emby/system/ping'),
    hedgeProbeTimeoutMs: formatIntegerInput(currentConfig.hedgeProbeTimeoutMs, 2500),
    hedgeProbeParallelism: formatIntegerInput(currentConfig.hedgeProbeParallelism, 2),
    hedgeWaitTimeoutMs: formatIntegerInput(currentConfig.hedgeWaitTimeoutMs, 3000),
    hedgeLockTtlMs: formatIntegerInput(currentConfig.hedgeLockTtlMs, 5000),
    hedgePreferredTtlSec: formatIntegerInput(currentConfig.hedgePreferredTtlSec, 300),
    hedgeFailureCooldownSec: formatIntegerInput(currentConfig.hedgeFailureCooldownSec, 30),
    hedgeWakeJitterMs: formatIntegerInput(currentConfig.hedgeWakeJitterMs, 200),
    sourceDirectNodes: joinTextList(currentConfig.sourceDirectNodes),
    logEnabled: currentConfig.logEnabled !== false,
    logSearchMode: resolveSelectValue(currentConfig.logSearchMode, 'fts'),
    logWriteMode: resolveSelectValue(currentConfig.logWriteMode, 'info'),
    logWriteClientIp: currentConfig.logWriteClientIp !== false,
    logWriteColo: currentConfig.logWriteColo !== false,
    logWriteUa: currentConfig.logWriteUa !== false,
    logDisplayClientIp: currentConfig.logDisplayClientIp !== false,
    logDisplayColo: currentConfig.logDisplayColo !== false,
    logDisplayUa: currentConfig.logDisplayUa !== false,
    logWriteImagePoster: currentConfig.logWriteImagePoster === true,
    logWriteMediaMetadata: currentConfig.logWriteMediaMetadata === true,
    logRetentionDays: formatIntegerInput(currentConfig.logRetentionDays, 7),
    logWriteDelayMinutes: formatNumberInput(currentConfig.logWriteDelayMinutes, 20),
    logFlushCountThreshold: formatIntegerInput(currentConfig.logFlushCountThreshold, 50),
    logBatchChunkSize: formatIntegerInput(currentConfig.logBatchChunkSize, 50),
    logBatchRetryCount: formatIntegerInput(currentConfig.logBatchRetryCount, 2),
    logBatchRetryBackoffMs: formatIntegerInput(currentConfig.logBatchRetryBackoffMs, 75),
    scheduledLeaseMs: formatIntegerInput(currentConfig.scheduledLeaseMs, 300000),
    scheduleUtcOffsetMinutes: formatIntegerInput(currentConfig.scheduleUtcOffsetMinutes, 480),
    dnsAutoUploadEnabled: currentConfig.dnsAutoUploadEnabled === true,
    dnsAutoUploadScheduleMode: resolveSelectValue(currentConfig.dnsAutoUploadScheduleMode, 'clock_queue'),
    dnsAutoUploadClockTimes: joinTextList(currentConfig.dnsAutoUploadClockTimes || ['03:00']),
    dnsAutoUploadIntervalMinutes: formatIntegerInput(currentConfig.dnsAutoUploadIntervalMinutes, 60),
    dnsAutoUploadWindowStartTime: resolveSelectValue(currentConfig.dnsAutoUploadWindowStartTime, '00:00'),
    dnsAutoUploadWindowEndTime: resolveSelectValue(currentConfig.dnsAutoUploadWindowEndTime, '23:59'),
    dnsAutoUploadTopN: formatIntegerInput(currentConfig.dnsAutoUploadTopN, 10),
    dnsAutoUploadCountryCodes: joinTextList(parseRegionCodeList(currentConfig.dnsAutoUploadCountryCodes)),
    dnsAutoUploadRecordTypes: joinTextList(parseLooseTextList(currentConfig.dnsAutoUploadRecordTypes || ['A'])),
    dnsAutoUploadNotifyEnabled: currentConfig.dnsAutoUploadNotifyEnabled === true,
    dnsAutoUploadNotifyDelayMinutes: formatIntegerInput(currentConfig.dnsAutoUploadNotifyDelayMinutes, 5),
    tgDailyReportEnabled: currentConfig.tgDailyReportEnabled === true,
    tgDailyReportSummaryEnabled: hasExplicitDailyReportKinds
      ? currentConfig.tgDailyReportSummaryEnabled === true
      : currentConfig.tgDailyReportEnabled === true,
    tgDailyReportKvEnabled: currentConfig.tgDailyReportKvEnabled === true,
    tgDailyReportD1Enabled: currentConfig.tgDailyReportD1Enabled === true,
    tgDailyReportClockTimes: joinTextList(currentConfig.tgDailyReportClockTimes || ['09:00']),
    tgAlertDroppedBatchThreshold: formatIntegerInput(currentConfig.tgAlertDroppedBatchThreshold, 0),
    tgAlertFlushRetryThreshold: formatIntegerInput(currentConfig.tgAlertFlushRetryThreshold, 0),
    tgAlertOnScheduledFailure: currentConfig.tgAlertOnScheduledFailure === true,
    tgAlertKvUsageEnabled: currentConfig.tgAlertKvUsageEnabled === true,
    tgAlertKvUsageThresholdPercent: formatIntegerInput(currentConfig.tgAlertKvUsageThresholdPercent, 80),
    tgAlertD1UsageEnabled: currentConfig.tgAlertD1UsageEnabled === true,
    tgAlertD1UsageThresholdPercent: formatIntegerInput(currentConfig.tgAlertD1UsageThresholdPercent, 80),
    tgAlertCooldownMinutes: formatIntegerInput(currentConfig.tgAlertCooldownMinutes, 30),
    cfQuotaPlanOverride: resolveSelectValue(currentConfig.cfQuotaPlanOverride, ''),
    cfQuotaPlanCacheMinutes: formatIntegerInput(currentConfig.cfQuotaPlanCacheMinutes, 60),
    cfAccountId: String(currentConfig.cfAccountId || '').trim(),
    cfZoneId: String(currentConfig.cfZoneId || '').trim(),
    cfApiToken: String(currentConfig.cfApiToken || '').trim(),
    cfKvNamespaceId: String(currentConfig.cfKvNamespaceId || '').trim(),
    cfD1DatabaseId: String(currentConfig.cfD1DatabaseId || '').trim(),
    dnsDefaultFallbackCname: String(currentConfig.dnsDefaultFallbackCname || '').trim(),
    tgBotToken: String(currentConfig.tgBotToken || '').trim(),
    tgChatId: String(currentConfig.tgChatId || '').trim()
  };
}

function buildConfigPayload(currentConfig = {}, currentForm = {}) {
  const fallbackConfig = currentConfig && typeof currentConfig === 'object' ? currentConfig : {};

  return {
    ...fallbackConfig,
    settingsExperienceMode: resolveSelectValue(currentForm.settingsExperienceMode, 'novice'),
    uiRadiusPx: parseIntegerValue(currentForm.uiRadiusPx, fallbackConfig.uiRadiusPx, 10),
    protocolStrategy: resolveSelectValue(currentForm.protocolStrategy, 'compat'),
    routingDecisionMode: resolveSelectValue(currentForm.routingDecisionMode, 'legacy'),
    defaultPlaybackInfoMode: resolveSelectValue(currentForm.defaultPlaybackInfoMode, 'passthrough'),
    defaultRealClientIpMode: resolveSelectValue(currentForm.defaultRealClientIpMode, 'forward'),
    defaultMediaAuthMode: resolveSelectValue(currentForm.defaultMediaAuthMode, 'auto'),
    enableHostPrefixProxy: currentForm.enableHostPrefixProxy === true,
    enablePrewarm: currentForm.enablePrewarm !== false,
    prewarmDepth: resolveSelectValue(currentForm.prewarmDepth, 'poster'),
    prewarmCacheTtl: parseIntegerValue(currentForm.prewarmCacheTtl, fallbackConfig.prewarmCacheTtl, 120),
    prewarmPrefetchBytes: parseIntegerValue(currentForm.prewarmPrefetchBytes, fallbackConfig.prewarmPrefetchBytes, 4194304),
    disablePrewarmPrefetch: currentForm.disablePrewarmPrefetch === true,
    playbackInfoCacheEnabled: currentForm.playbackInfoCacheEnabled !== false,
    playbackInfoCacheTtlSec: parseIntegerValue(currentForm.playbackInfoCacheTtlSec, fallbackConfig.playbackInfoCacheTtlSec, 60),
    videoProgressForwardEnabled: currentForm.videoProgressForwardEnabled !== false,
    videoProgressForwardIntervalSec: parseIntegerValue(currentForm.videoProgressForwardIntervalSec, fallbackConfig.videoProgressForwardIntervalSec, 3),
    directStaticAssets: currentForm.directStaticAssets === true,
    directHlsDash: currentForm.directHlsDash === true,
    multiLinkCopyPanelEnabled: currentForm.multiLinkCopyPanelEnabled === true,
    dashboardShowD1WriteHotspot: currentForm.dashboardShowD1WriteHotspot === true,
    dashboardShowKvD1Status: currentForm.dashboardShowKvD1Status === true,
    pingTimeout: parseIntegerValue(currentForm.pingTimeout, fallbackConfig.pingTimeout, 5000),
    pingCacheMinutes: parseIntegerValue(currentForm.pingCacheMinutes, fallbackConfig.pingCacheMinutes, 10),
    upstreamTimeoutMs: parseIntegerValue(currentForm.upstreamTimeoutMs, fallbackConfig.upstreamTimeoutMs, 8000),
    upstreamRetryAttempts: parseIntegerValue(currentForm.upstreamRetryAttempts, fallbackConfig.upstreamRetryAttempts, 0),
    geoAllowlist: joinCommaSeparatedList(parseRegionCodeList(currentForm.geoAllowlist)),
    geoBlocklist: joinCommaSeparatedList(parseRegionCodeList(currentForm.geoBlocklist)),
    ipBlacklist: joinCommaSeparatedList(parseLooseTextList(currentForm.ipBlacklist)),
    rateLimitRpm: parseIntegerValue(currentForm.rateLimitRpm, fallbackConfig.rateLimitRpm, 0),
    cacheTtlImages: parseIntegerValue(currentForm.cacheTtlImages, fallbackConfig.cacheTtlImages, 30),
    corsOrigins: joinCommaSeparatedList(parseLooseTextList(currentForm.corsOrigins)),
    jwtExpiryDays: parseIntegerValue(currentForm.jwtExpiryDays, fallbackConfig.jwtExpiryDays, 30),
    hedgeFailoverEnabled: currentForm.hedgeFailoverEnabled === true,
    hedgeProbePath: resolveSelectValue(currentForm.hedgeProbePath, '/emby/system/ping'),
    hedgeProbeTimeoutMs: parseIntegerValue(currentForm.hedgeProbeTimeoutMs, fallbackConfig.hedgeProbeTimeoutMs, 2500),
    hedgeProbeParallelism: parseIntegerValue(currentForm.hedgeProbeParallelism, fallbackConfig.hedgeProbeParallelism, 2),
    hedgeWaitTimeoutMs: parseIntegerValue(currentForm.hedgeWaitTimeoutMs, fallbackConfig.hedgeWaitTimeoutMs, 3000),
    hedgeLockTtlMs: parseIntegerValue(currentForm.hedgeLockTtlMs, fallbackConfig.hedgeLockTtlMs, 5000),
    hedgePreferredTtlSec: parseIntegerValue(currentForm.hedgePreferredTtlSec, fallbackConfig.hedgePreferredTtlSec, 300),
    hedgeFailureCooldownSec: parseIntegerValue(currentForm.hedgeFailureCooldownSec, fallbackConfig.hedgeFailureCooldownSec, 30),
    hedgeWakeJitterMs: parseIntegerValue(currentForm.hedgeWakeJitterMs, fallbackConfig.hedgeWakeJitterMs, 200),
    sourceDirectNodes: parseTextList(currentForm.sourceDirectNodes),
    logEnabled: currentForm.logEnabled !== false,
    logSearchMode: resolveSelectValue(currentForm.logSearchMode, 'fts'),
    logWriteMode: resolveSelectValue(currentForm.logWriteMode, 'info'),
    logWriteClientIp: currentForm.logWriteClientIp !== false,
    logWriteColo: currentForm.logWriteColo !== false,
    logWriteUa: currentForm.logWriteUa !== false,
    logDisplayClientIp: currentForm.logDisplayClientIp !== false,
    logDisplayColo: currentForm.logDisplayColo !== false,
    logDisplayUa: currentForm.logDisplayUa !== false,
    logWriteImagePoster: currentForm.logWriteImagePoster === true,
    logWriteMediaMetadata: currentForm.logWriteMediaMetadata === true,
    logRetentionDays: parseIntegerValue(currentForm.logRetentionDays, fallbackConfig.logRetentionDays, 7),
    logWriteDelayMinutes: parseNumberValue(currentForm.logWriteDelayMinutes, fallbackConfig.logWriteDelayMinutes, 20),
    logFlushCountThreshold: parseIntegerValue(currentForm.logFlushCountThreshold, fallbackConfig.logFlushCountThreshold, 50),
    logBatchChunkSize: parseIntegerValue(currentForm.logBatchChunkSize, fallbackConfig.logBatchChunkSize, 50),
    logBatchRetryCount: parseIntegerValue(currentForm.logBatchRetryCount, fallbackConfig.logBatchRetryCount, 2),
    logBatchRetryBackoffMs: parseIntegerValue(currentForm.logBatchRetryBackoffMs, fallbackConfig.logBatchRetryBackoffMs, 75),
    scheduledLeaseMs: parseIntegerValue(currentForm.scheduledLeaseMs, fallbackConfig.scheduledLeaseMs, 300000),
    scheduleUtcOffsetMinutes: parseIntegerValue(currentForm.scheduleUtcOffsetMinutes, fallbackConfig.scheduleUtcOffsetMinutes, 480),
    dnsAutoUploadEnabled: currentForm.dnsAutoUploadEnabled === true,
    dnsAutoUploadScheduleMode: resolveSelectValue(currentForm.dnsAutoUploadScheduleMode, 'clock_queue'),
    dnsAutoUploadClockTimes: parseTextList(currentForm.dnsAutoUploadClockTimes),
    dnsAutoUploadIntervalMinutes: parseIntegerValue(currentForm.dnsAutoUploadIntervalMinutes, fallbackConfig.dnsAutoUploadIntervalMinutes, 60),
    dnsAutoUploadWindowStartTime: resolveSelectValue(currentForm.dnsAutoUploadWindowStartTime, '00:00'),
    dnsAutoUploadWindowEndTime: resolveSelectValue(currentForm.dnsAutoUploadWindowEndTime, '23:59'),
    dnsAutoUploadTopN: parseIntegerValue(currentForm.dnsAutoUploadTopN, fallbackConfig.dnsAutoUploadTopN, 10),
    dnsAutoUploadCountryCodes: joinCommaSeparatedList(parseRegionCodeList(currentForm.dnsAutoUploadCountryCodes)),
    dnsAutoUploadRecordTypes: parseLooseTextList(currentForm.dnsAutoUploadRecordTypes),
    dnsAutoUploadNotifyEnabled: currentForm.dnsAutoUploadNotifyEnabled === true,
    dnsAutoUploadNotifyDelayMinutes: parseIntegerValue(currentForm.dnsAutoUploadNotifyDelayMinutes, fallbackConfig.dnsAutoUploadNotifyDelayMinutes, 5),
    tgDailyReportEnabled: currentForm.tgDailyReportEnabled === true,
    tgDailyReportSummaryEnabled: currentForm.tgDailyReportSummaryEnabled === true,
    tgDailyReportKvEnabled: currentForm.tgDailyReportKvEnabled === true,
    tgDailyReportD1Enabled: currentForm.tgDailyReportD1Enabled === true,
    tgDailyReportClockTimes: parseTextList(currentForm.tgDailyReportClockTimes),
    tgAlertDroppedBatchThreshold: parseIntegerValue(currentForm.tgAlertDroppedBatchThreshold, fallbackConfig.tgAlertDroppedBatchThreshold, 0),
    tgAlertFlushRetryThreshold: parseIntegerValue(currentForm.tgAlertFlushRetryThreshold, fallbackConfig.tgAlertFlushRetryThreshold, 0),
    tgAlertOnScheduledFailure: currentForm.tgAlertOnScheduledFailure === true,
    tgAlertKvUsageEnabled: currentForm.tgAlertKvUsageEnabled === true,
    tgAlertKvUsageThresholdPercent: parseIntegerValue(currentForm.tgAlertKvUsageThresholdPercent, fallbackConfig.tgAlertKvUsageThresholdPercent, 80),
    tgAlertD1UsageEnabled: currentForm.tgAlertD1UsageEnabled === true,
    tgAlertD1UsageThresholdPercent: parseIntegerValue(currentForm.tgAlertD1UsageThresholdPercent, fallbackConfig.tgAlertD1UsageThresholdPercent, 80),
    tgAlertCooldownMinutes: parseIntegerValue(currentForm.tgAlertCooldownMinutes, fallbackConfig.tgAlertCooldownMinutes, 30),
    cfQuotaPlanOverride: resolveSelectValue(currentForm.cfQuotaPlanOverride, ''),
    cfQuotaPlanCacheMinutes: parseIntegerValue(currentForm.cfQuotaPlanCacheMinutes, fallbackConfig.cfQuotaPlanCacheMinutes, 60),
    cfAccountId: String(currentForm.cfAccountId || '').trim(),
    cfZoneId: String(currentForm.cfZoneId || '').trim(),
    cfApiToken: String(currentForm.cfApiToken || '').trim(),
    cfKvNamespaceId: String(currentForm.cfKvNamespaceId || '').trim(),
    cfD1DatabaseId: String(currentForm.cfD1DatabaseId || '').trim(),
    dnsDefaultFallbackCname: String(currentForm.dnsDefaultFallbackCname || '').trim(),
    tgBotToken: String(currentForm.tgBotToken || '').trim(),
    tgChatId: String(currentForm.tgChatId || '').trim()
  };
}

function resolveSelectValue(value, fallback = '') {
  return String(value ?? fallback).trim();
}

function formatIntegerInput(value, fallbackValue) {
  const nextValue = Number.parseInt(String(value ?? '').trim(), 10);
  return String(Number.isFinite(nextValue) ? nextValue : fallbackValue);
}

function formatNumberInput(value, fallbackValue) {
  const nextValue = Number.parseFloat(String(value ?? '').trim());
  return String(Number.isFinite(nextValue) ? nextValue : fallbackValue);
}

function parseIntegerValue(value, fallback, defaultValue) {
  const nextValue = Number.parseInt(String(value ?? '').trim(), 10);
  if (Number.isFinite(nextValue)) return nextValue;

  const fallbackValue = Number.parseInt(String(fallback ?? '').trim(), 10);
  if (Number.isFinite(fallbackValue)) return fallbackValue;
  return defaultValue;
}

function parseNumberValue(value, fallback, defaultValue) {
  const nextValue = Number.parseFloat(String(value ?? '').trim());
  if (Number.isFinite(nextValue)) return nextValue;

  const fallbackValue = Number.parseFloat(String(fallback ?? '').trim());
  if (Number.isFinite(fallbackValue)) return fallbackValue;
  return defaultValue;
}

function parseTextList(value = '') {
  return [...new Set(
    String(value || '')
      .split(/[\r\n,，;；|]+/)
      .map((entry) => entry.trim())
      .filter(Boolean)
  )];
}

function parseLooseTextList(value = '') {
  if (Array.isArray(value)) {
    return [...new Set(
      value
        .map((entry) => String(entry || '').trim())
        .filter(Boolean)
    )];
  }
  return parseTextList(value);
}

function parseRegionCodeList(value = '') {
  return [...new Set(
    parseLooseTextList(value)
      .map((entry) => String(entry || '').trim().toUpperCase())
      .filter(Boolean)
  )];
}

function joinCommaSeparatedList(values = []) {
  return parseLooseTextList(values).join(',');
}

function joinTextList(values = []) {
  return (Array.isArray(values) ? values : [])
    .map((entry) => String(entry || '').trim())
    .filter(Boolean)
    .join('\n');
}

function serializeFormState(value = {}) {
  return JSON.stringify({
    settingsExperienceMode: resolveSelectValue(value.settingsExperienceMode, 'novice'),
    uiRadiusPx: String(value.uiRadiusPx || '').trim(),
    protocolStrategy: resolveSelectValue(value.protocolStrategy, 'compat'),
    routingDecisionMode: resolveSelectValue(value.routingDecisionMode, 'legacy'),
    defaultPlaybackInfoMode: resolveSelectValue(value.defaultPlaybackInfoMode, 'passthrough'),
    defaultRealClientIpMode: resolveSelectValue(value.defaultRealClientIpMode, 'forward'),
    defaultMediaAuthMode: resolveSelectValue(value.defaultMediaAuthMode, 'auto'),
    enableHostPrefixProxy: value.enableHostPrefixProxy === true,
    enablePrewarm: value.enablePrewarm !== false,
    prewarmDepth: resolveSelectValue(value.prewarmDepth, 'poster'),
    prewarmCacheTtl: String(value.prewarmCacheTtl || '').trim(),
    prewarmPrefetchBytes: String(value.prewarmPrefetchBytes || '').trim(),
    disablePrewarmPrefetch: value.disablePrewarmPrefetch === true,
    playbackInfoCacheEnabled: value.playbackInfoCacheEnabled !== false,
    playbackInfoCacheTtlSec: String(value.playbackInfoCacheTtlSec || '').trim(),
    videoProgressForwardEnabled: value.videoProgressForwardEnabled !== false,
    videoProgressForwardIntervalSec: String(value.videoProgressForwardIntervalSec || '').trim(),
    directStaticAssets: value.directStaticAssets === true,
    directHlsDash: value.directHlsDash === true,
    multiLinkCopyPanelEnabled: value.multiLinkCopyPanelEnabled === true,
    dashboardShowD1WriteHotspot: value.dashboardShowD1WriteHotspot === true,
    dashboardShowKvD1Status: value.dashboardShowKvD1Status === true,
    pingTimeout: String(value.pingTimeout || '').trim(),
    pingCacheMinutes: String(value.pingCacheMinutes || '').trim(),
    upstreamTimeoutMs: String(value.upstreamTimeoutMs || '').trim(),
    upstreamRetryAttempts: String(value.upstreamRetryAttempts || '').trim(),
    geoAllowlist: parseRegionCodeList(value.geoAllowlist),
    geoBlocklist: parseRegionCodeList(value.geoBlocklist),
    ipBlacklist: parseLooseTextList(value.ipBlacklist),
    rateLimitRpm: String(value.rateLimitRpm || '').trim(),
    cacheTtlImages: String(value.cacheTtlImages || '').trim(),
    corsOrigins: parseLooseTextList(value.corsOrigins),
    jwtExpiryDays: String(value.jwtExpiryDays || '').trim(),
    hedgeFailoverEnabled: value.hedgeFailoverEnabled === true,
    hedgeProbePath: resolveSelectValue(value.hedgeProbePath, '/emby/system/ping'),
    hedgeProbeTimeoutMs: String(value.hedgeProbeTimeoutMs || '').trim(),
    hedgeProbeParallelism: String(value.hedgeProbeParallelism || '').trim(),
    hedgeWaitTimeoutMs: String(value.hedgeWaitTimeoutMs || '').trim(),
    hedgeLockTtlMs: String(value.hedgeLockTtlMs || '').trim(),
    hedgePreferredTtlSec: String(value.hedgePreferredTtlSec || '').trim(),
    hedgeFailureCooldownSec: String(value.hedgeFailureCooldownSec || '').trim(),
    hedgeWakeJitterMs: String(value.hedgeWakeJitterMs || '').trim(),
    sourceDirectNodes: parseTextList(value.sourceDirectNodes),
    logEnabled: value.logEnabled !== false,
    logSearchMode: resolveSelectValue(value.logSearchMode, 'fts'),
    logWriteMode: resolveSelectValue(value.logWriteMode, 'info'),
    logWriteClientIp: value.logWriteClientIp !== false,
    logWriteColo: value.logWriteColo !== false,
    logWriteUa: value.logWriteUa !== false,
    logDisplayClientIp: value.logDisplayClientIp !== false,
    logDisplayColo: value.logDisplayColo !== false,
    logDisplayUa: value.logDisplayUa !== false,
    logWriteImagePoster: value.logWriteImagePoster === true,
    logWriteMediaMetadata: value.logWriteMediaMetadata === true,
    logRetentionDays: String(value.logRetentionDays || '').trim(),
    logWriteDelayMinutes: String(value.logWriteDelayMinutes || '').trim(),
    logFlushCountThreshold: String(value.logFlushCountThreshold || '').trim(),
    logBatchChunkSize: String(value.logBatchChunkSize || '').trim(),
    logBatchRetryCount: String(value.logBatchRetryCount || '').trim(),
    logBatchRetryBackoffMs: String(value.logBatchRetryBackoffMs || '').trim(),
    scheduledLeaseMs: String(value.scheduledLeaseMs || '').trim(),
    scheduleUtcOffsetMinutes: String(value.scheduleUtcOffsetMinutes || '').trim(),
    dnsAutoUploadEnabled: value.dnsAutoUploadEnabled === true,
    dnsAutoUploadScheduleMode: resolveSelectValue(value.dnsAutoUploadScheduleMode, 'clock_queue'),
    dnsAutoUploadClockTimes: parseTextList(value.dnsAutoUploadClockTimes),
    dnsAutoUploadIntervalMinutes: String(value.dnsAutoUploadIntervalMinutes || '').trim(),
    dnsAutoUploadWindowStartTime: resolveSelectValue(value.dnsAutoUploadWindowStartTime, '00:00'),
    dnsAutoUploadWindowEndTime: resolveSelectValue(value.dnsAutoUploadWindowEndTime, '23:59'),
    dnsAutoUploadTopN: String(value.dnsAutoUploadTopN || '').trim(),
    dnsAutoUploadCountryCodes: parseRegionCodeList(value.dnsAutoUploadCountryCodes),
    dnsAutoUploadRecordTypes: parseLooseTextList(value.dnsAutoUploadRecordTypes),
    dnsAutoUploadNotifyEnabled: value.dnsAutoUploadNotifyEnabled === true,
    dnsAutoUploadNotifyDelayMinutes: String(value.dnsAutoUploadNotifyDelayMinutes || '').trim(),
    tgDailyReportEnabled: value.tgDailyReportEnabled === true,
    tgDailyReportSummaryEnabled: value.tgDailyReportSummaryEnabled === true,
    tgDailyReportKvEnabled: value.tgDailyReportKvEnabled === true,
    tgDailyReportD1Enabled: value.tgDailyReportD1Enabled === true,
    tgDailyReportClockTimes: parseTextList(value.tgDailyReportClockTimes),
    tgAlertDroppedBatchThreshold: String(value.tgAlertDroppedBatchThreshold || '').trim(),
    tgAlertFlushRetryThreshold: String(value.tgAlertFlushRetryThreshold || '').trim(),
    tgAlertOnScheduledFailure: value.tgAlertOnScheduledFailure === true,
    tgAlertKvUsageEnabled: value.tgAlertKvUsageEnabled === true,
    tgAlertKvUsageThresholdPercent: String(value.tgAlertKvUsageThresholdPercent || '').trim(),
    tgAlertD1UsageEnabled: value.tgAlertD1UsageEnabled === true,
    tgAlertD1UsageThresholdPercent: String(value.tgAlertD1UsageThresholdPercent || '').trim(),
    tgAlertCooldownMinutes: String(value.tgAlertCooldownMinutes || '').trim(),
    cfQuotaPlanOverride: resolveSelectValue(value.cfQuotaPlanOverride, ''),
    cfQuotaPlanCacheMinutes: String(value.cfQuotaPlanCacheMinutes || '').trim(),
    cfAccountId: String(value.cfAccountId || '').trim(),
    cfZoneId: String(value.cfZoneId || '').trim(),
    cfApiToken: String(value.cfApiToken || '').trim(),
    cfKvNamespaceId: String(value.cfKvNamespaceId || '').trim(),
    cfD1DatabaseId: String(value.cfD1DatabaseId || '').trim(),
    dnsDefaultFallbackCname: String(value.dnsDefaultFallbackCname || '').trim(),
    tgBotToken: String(value.tgBotToken || '').trim(),
    tgChatId: String(value.tgChatId || '').trim()
  });
}

function compactRevision(rawValue = '') {
  const value = String(rawValue || '').trim();
  if (!value) return '未生成';
  return value.length > 14 ? `${value.slice(0, 14)}...` : value;
}

function formatDateTime(rawValue = '') {
  const value = String(rawValue || '').trim();
  if (!value) return '未提供';

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  }).format(date);
}

function resolveStatusTone() {
  if (authRequired.value) return 'border-amber-400/30 bg-amber-500/12 text-amber-200';
  if (
    settingsError.value
    || saveError.value
    || loadConfigError.value
    || previewConfigError.value
    || exportConfigError.value
    || exportSettingsError.value
    || importFullError.value
    || importSettingsError.value
    || configSnapshotsError.value
    || clearConfigSnapshotsError.value
    || restoreConfigSnapshotError.value
  ) return 'border-rose-400/30 bg-rose-500/12 text-rose-200';
  if (savingConfig.value || importFullLoading.value || importSettingsLoading.value || restoreConfigSnapshotLoading.value) {
    return 'border-brand-400/30 bg-brand-500/12 text-brand-200';
  }
  if (
    loadingSettings.value
    || loadConfigLoading.value
    || previewConfigLoading.value
    || exportConfigLoading.value
    || exportSettingsLoading.value
    || configSnapshotsLoading.value
    || clearConfigSnapshotsLoading.value
  ) {
    return 'border-ocean-500/30 bg-ocean-500/12 text-ocean-300';
  }
  return 'border-mint-400/30 bg-mint-400/12 text-mint-300';
}

function resolveStatusLabel() {
  if (authRequired.value) return '需要登录';
  if (
    settingsError.value
    || saveError.value
    || loadConfigError.value
    || previewConfigError.value
    || exportConfigError.value
    || exportSettingsError.value
    || importFullError.value
    || importSettingsError.value
    || configSnapshotsError.value
    || clearConfigSnapshotsError.value
    || restoreConfigSnapshotError.value
  ) return '设置异常';
  if (restoreConfigSnapshotLoading.value) return '正在恢复快照';
  if (importFullLoading.value || importSettingsLoading.value) return '正在导入';
  if (exportConfigLoading.value || exportSettingsLoading.value) return '正在导出';
  if (clearConfigSnapshotsLoading.value) return '正在清空快照';
  if (configSnapshotsLoading.value) return '正在同步快照';
  if (previewConfigLoading.value) return '正在预检';
  if (savingConfig.value) return '正在保存';
  if (loadingSettings.value || loadConfigLoading.value) return '正在加载';
  return '设置已接通';
}

function formatConfigSnapshotReason(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'save_config') return '保存配置';
  if (normalized === 'restore_snapshot') return '恢复快照';
  if (normalized === 'import_settings') return '导入设置';
  if (normalized === 'import_full') return '完整导入';
  if (normalized === 'tidy_kv_data_pre_migration') return 'KV 整理前快照';
  return String(value || '未标记').trim() || '未标记';
}

function formatConfigSnapshotSection(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'settings') return 'settings';
  if (normalized === 'all') return 'all';
  return String(value || 'unknown').trim() || 'unknown';
}

function summarizeConfigSnapshotChangedKeys(changedKeys = []) {
  const normalized = parseLooseTextList(changedKeys);
  if (!normalized.length) return '未记录字段差异';
  const preview = normalized.slice(0, 6).join(', ');
  return normalized.length > 6 ? `${preview} 等 ${normalized.length} 项` : preview;
}
</script>

<template>
  <SectionCard
    eyebrow="Settings Bridge"
    title="设置页已经开始从旧版内嵌管理台迁到独立前端"
    description="这一版先接管最核心的全局配置读写，继续沿用 Worker 的 `getSettingsBootstrap` 与 `saveConfig`，不新造第二套协议。"
  >
    <template #meta>
      <div class="flex flex-wrap items-center justify-end gap-3">
        <div class="inline-flex rounded-full border px-3 py-1 text-xs font-semibold" :class="resolveStatusTone()">
          {{ resolveStatusLabel() }}
        </div>
        <button
          type="button"
          class="secondary-btn"
          :disabled="anySettingsBusy"
          @click="handleRefresh"
        >
          <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loadingSettings }" />
          刷新设置
        </button>
        <button
          type="button"
          class="primary-btn"
          :disabled="authRequired || anySettingsBusy || !hasChanges"
          @click="handleSave"
        >
          <Save class="h-4 w-4" />
          保存设置
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
          <p class="text-sm font-semibold">当前会话尚未授权，设置页无法读取或保存真实配置</p>
          <p class="mt-2 text-sm leading-6 text-amber-50/85">
            先在 Worker 管理台完成登录，再回来刷新这一页。这里仍然复用原有 `POST /admin/login` 与 `POST /admin`。
          </p>
          <a
            :href="props.adminConsole?.loginUrl"
            class="mt-4 inline-flex rounded-full border border-amber-200/40 px-4 py-2 text-sm font-medium text-amber-50 transition hover:bg-amber-400/10"
          >
            打开 Worker 登录页
          </a>
        </div>
      </div>
    </article>

    <article
      v-if="feedback.text"
      class="mb-6 rounded-3xl border p-5"
      :class="feedback.tone === 'success'
        ? 'border-mint-400/25 bg-mint-400/10 text-mint-100'
        : 'border-rose-400/25 bg-rose-500/10 text-rose-100'"
    >
      <p class="text-sm leading-6">{{ feedback.text }}</p>
    </article>

    <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      <article v-for="tile in summaryTiles" :key="tile.title" class="stat-tile">
        <div class="flex items-center gap-3">
          <Cog class="h-5 w-5 text-brand-300" />
          <p class="text-sm font-medium text-white">{{ tile.title }}</p>
        </div>
        <p class="mt-4 break-all text-2xl font-semibold text-brand-300">{{ tile.value }}</p>
        <p class="mt-3 text-sm leading-6 text-slate-300">{{ tile.note }}</p>
      </article>
    </div>

    <div class="mt-6 grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
      <article class="form-card">
        <div class="flex items-center gap-3">
          <SlidersHorizontal class="h-5 w-5 text-brand-300" />
          <h3 class="text-sm font-medium text-white">基础体验与代理策略</h3>
        </div>

        <div class="mt-5 grid gap-4 md:grid-cols-2">
          <label class="field-shell">
            <span class="field-label">界面模式</span>
            <select v-model="form.settingsExperienceMode" class="field-input">
              <option value="novice">Novice</option>
              <option value="expert">Expert</option>
            </select>
            <span class="field-hint">继续沿用旧面板的 novice / expert 模式。</span>
          </label>

          <label class="field-shell">
            <span class="field-label">界面圆角</span>
            <input v-model="form.uiRadiusPx" type="number" min="0" max="48" class="field-input" />
            <span class="field-hint">对应 `uiRadiusPx`。</span>
          </label>

          <label class="field-shell">
            <span class="field-label">协议策略</span>
            <select v-model="form.protocolStrategy" class="field-input">
              <option value="compat">compat</option>
              <option value="balanced">balanced</option>
              <option value="aggressive">aggressive</option>
            </select>
          </label>

          <label class="field-shell">
            <span class="field-label">路由决策模式</span>
            <select v-model="form.routingDecisionMode" class="field-input">
              <option value="legacy">legacy</option>
              <option value="simplified">simplified</option>
            </select>
          </label>

          <label class="field-shell">
            <span class="field-label">PlaybackInfo 默认模式</span>
            <select v-model="form.defaultPlaybackInfoMode" class="field-input">
              <option value="passthrough">passthrough</option>
              <option value="rewrite">rewrite</option>
            </select>
          </label>

          <label class="field-shell">
            <span class="field-label">真实客户端 IP</span>
            <select v-model="form.defaultRealClientIpMode" class="field-input">
              <option value="forward">forward</option>
              <option value="strip">strip</option>
              <option value="disable">disable</option>
            </select>
          </label>

          <label class="field-shell">
            <span class="field-label">媒体鉴权策略</span>
            <select v-model="form.defaultMediaAuthMode" class="field-input">
              <option value="auto">auto</option>
              <option value="emby">emby</option>
              <option value="jellyfin">jellyfin</option>
              <option value="passthrough">passthrough</option>
            </select>
          </label>

          <label class="field-shell">
            <span class="field-label">预热深度</span>
            <select v-model="form.prewarmDepth" class="field-input">
              <option value="poster">poster</option>
              <option value="poster_manifest">poster_manifest</option>
            </select>
          </label>

          <label class="field-shell">
            <span class="field-label">Ping 超时 (ms)</span>
            <input v-model="form.pingTimeout" type="number" min="1000" max="180000" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">上游超时 (ms)</span>
            <input v-model="form.upstreamTimeoutMs" type="number" min="0" max="180000" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">上游重试次数</span>
            <input v-model="form.upstreamRetryAttempts" type="number" min="0" max="3" class="field-input" />
          </label>

          <div class="field-shell md:col-span-2">
            <span class="field-label">直连节点名单</span>
            <textarea
              v-model="form.sourceDirectNodes"
              rows="4"
              class="field-input field-textarea"
              placeholder="每行一个节点名"
            />
            <span class="field-hint">会写回 `sourceDirectNodes`，使用换行或逗号分隔都可以。</span>
          </div>
        </div>

        <div class="mt-5 grid gap-3 md:grid-cols-2">
          <label class="toggle-card">
            <input v-model="form.enableHostPrefixProxy" type="checkbox" class="h-4 w-4 rounded" />
            <span>启用 host prefix 代理</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.enablePrewarm" type="checkbox" class="h-4 w-4 rounded" />
            <span>启用预热</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.directStaticAssets" type="checkbox" class="h-4 w-4 rounded" />
            <span>静态资源直连</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.directHlsDash" type="checkbox" class="h-4 w-4 rounded" />
            <span>HLS / DASH 直连</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.multiLinkCopyPanelEnabled" type="checkbox" class="h-4 w-4 rounded" />
            <span>多链接复制面板</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.dashboardShowD1WriteHotspot" type="checkbox" class="h-4 w-4 rounded" />
            <span>仪表盘显示 D1 热点</span>
          </label>
          <label class="toggle-card md:col-span-2">
            <input v-model="form.dashboardShowKvD1Status" type="checkbox" class="h-4 w-4 rounded" />
            <span>仪表盘显示 KV / D1 状态卡片</span>
          </label>
        </div>
      </article>

      <article class="form-card">
        <div class="flex items-center gap-3">
          <Server class="h-5 w-5 text-ocean-300" />
          <h3 class="text-sm font-medium text-white">Cloudflare 与 Telegram</h3>
        </div>

        <div class="mt-5 grid gap-4">
          <label class="field-shell">
            <span class="field-label">配额计划覆盖</span>
            <select v-model="form.cfQuotaPlanOverride" class="field-input">
              <option value="">自动识别</option>
              <option value="free">free</option>
              <option value="paid">paid</option>
            </select>
          </label>

          <label class="field-shell">
            <span class="field-label">配额缓存分钟</span>
            <input v-model="form.cfQuotaPlanCacheMinutes" type="number" min="1" max="1440" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">Cloudflare Account ID</span>
            <input v-model="form.cfAccountId" type="text" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">Cloudflare Zone ID</span>
            <input v-model="form.cfZoneId" type="text" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">Cloudflare API Token</span>
            <input v-model="form.cfApiToken" type="password" class="field-input" autocomplete="new-password" />
          </label>

          <label class="field-shell">
            <span class="field-label">KV Namespace ID</span>
            <input v-model="form.cfKvNamespaceId" type="text" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">D1 Database ID</span>
            <input v-model="form.cfD1DatabaseId" type="text" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">DNS fallback CNAME</span>
            <input
              v-model="form.dnsDefaultFallbackCname"
              type="text"
              class="field-input"
              placeholder="cdn.example.com"
            />
            <span class="field-hint">自动上传或兜底解析需要 CNAME 时会写回 `dnsDefaultFallbackCname`。</span>
          </label>

          <label class="field-shell">
            <span class="field-label">Telegram Bot Token</span>
            <input v-model="form.tgBotToken" type="password" class="field-input" autocomplete="new-password" />
          </label>

          <label class="field-shell">
            <span class="field-label">Telegram Chat ID</span>
            <input v-model="form.tgChatId" type="text" class="field-input" />
          </label>
        </div>
      </article>
    </div>

    <div class="mt-4 grid gap-4 xl:grid-cols-2">
      <article class="form-card">
        <div class="flex items-center gap-3">
          <SlidersHorizontal class="h-5 w-5 text-ocean-300" />
          <h3 class="text-sm font-medium text-white">预热、Playback 与进度转发</h3>
        </div>

        <p class="mt-4 rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3 text-sm leading-6 text-slate-300">
          这里补的是预热缓存、PlaybackInfo 缓存和播放进度转发的细粒度参数；主开关 `enablePrewarm` 仍保留在上面的基础代理卡片里。
        </p>

        <div class="mt-5 grid gap-4 md:grid-cols-2">
          <label class="field-shell">
            <span class="field-label">预热缓存 TTL (sec)</span>
            <input v-model="form.prewarmCacheTtl" type="number" min="0" max="3600" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">预热预取字节数</span>
            <input v-model="form.prewarmPrefetchBytes" type="number" min="0" max="67108864" class="field-input" />
            <span class="field-hint">默认 4194304，等于 4 MiB。</span>
          </label>

          <label class="field-shell">
            <span class="field-label">PlaybackInfo 缓存 TTL (sec)</span>
            <input v-model="form.playbackInfoCacheTtlSec" type="number" min="0" max="60" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">播放进度转发间隔 (sec)</span>
            <input v-model="form.videoProgressForwardIntervalSec" type="number" min="0" max="60" class="field-input" />
          </label>

          <label class="field-shell md:col-span-2">
            <span class="field-label">Ping 结果缓存 (分钟)</span>
            <input v-model="form.pingCacheMinutes" type="number" min="0" max="1440" class="field-input" />
          </label>
        </div>

        <div class="mt-5 grid gap-3 md:grid-cols-2">
          <label class="toggle-card">
            <input v-model="form.disablePrewarmPrefetch" type="checkbox" class="h-4 w-4 rounded" />
            <span>禁用预热预取</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.playbackInfoCacheEnabled" type="checkbox" class="h-4 w-4 rounded" />
            <span>启用 PlaybackInfo 缓存</span>
          </label>
          <label class="toggle-card md:col-span-2">
            <input v-model="form.videoProgressForwardEnabled" type="checkbox" class="h-4 w-4 rounded" />
            <span>启用播放进度转发</span>
          </label>
        </div>
      </article>

      <article class="form-card">
        <div class="flex items-center gap-3">
          <Server class="h-5 w-5 text-brand-300" />
          <h3 class="text-sm font-medium text-white">Hedge / Failover</h3>
        </div>

        <p class="mt-4 rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3 text-sm leading-6 text-slate-300">
          上面的 `upstreamTimeoutMs / upstreamRetryAttempts` 负责基础回源重试，这里继续接管探活路径、并行度和故障冷却等 failover 细节。
        </p>

        <div class="mt-5 grid gap-4 md:grid-cols-2">
          <label class="field-shell md:col-span-2">
            <span class="field-label">探活路径</span>
            <input v-model="form.hedgeProbePath" type="text" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">探活超时 (ms)</span>
            <input v-model="form.hedgeProbeTimeoutMs" type="number" min="250" max="10000" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">探活并行度</span>
            <input v-model="form.hedgeProbeParallelism" type="number" min="1" max="2" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">等待超时 (ms)</span>
            <input v-model="form.hedgeWaitTimeoutMs" type="number" min="250" max="10000" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">锁 TTL (ms)</span>
            <input v-model="form.hedgeLockTtlMs" type="number" min="1000" max="10000" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">偏好保留 (sec)</span>
            <input v-model="form.hedgePreferredTtlSec" type="number" min="30" max="3600" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">失败冷却 (sec)</span>
            <input v-model="form.hedgeFailureCooldownSec" type="number" min="1" max="300" class="field-input" />
          </label>

          <label class="field-shell md:col-span-2">
            <span class="field-label">唤醒抖动 (ms)</span>
            <input v-model="form.hedgeWakeJitterMs" type="number" min="0" max="1000" class="field-input" />
          </label>
        </div>

        <div class="mt-5 grid gap-3">
          <label class="toggle-card">
            <input v-model="form.hedgeFailoverEnabled" type="checkbox" class="h-4 w-4 rounded" />
            <span>启用 Hedge / Failover</span>
          </label>
        </div>
      </article>
    </div>

    <article class="form-card mt-4">
      <div class="flex items-center gap-3">
        <ShieldAlert class="h-5 w-5 text-amber-300" />
        <h3 class="text-sm font-medium text-white">安全、访问控制与缓存</h3>
      </div>

      <p class="mt-4 rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3 text-sm leading-6 text-slate-300">
        这一组继续沿用 Worker 的 `saveConfig` 字段语义，覆盖登录态有效期、按 IP 限流、图片缓存，以及地理区域、来源域和黑名单等访问控制规则。
      </p>

      <div class="mt-5 grid gap-4 md:grid-cols-2">
        <label class="field-shell">
          <span class="field-label">登录态有效期 (天)</span>
          <input v-model="form.jwtExpiryDays" type="number" min="1" class="field-input" />
          <span class="field-hint">对应 `jwtExpiryDays`，默认 30 天。</span>
        </label>

        <label class="field-shell">
          <span class="field-label">每分钟限流 (RPM)</span>
          <input v-model="form.rateLimitRpm" type="number" min="0" class="field-input" />
          <span class="field-hint">对应 `rateLimitRpm`，填 0 表示关闭按 IP 的限流。</span>
        </label>

        <label class="field-shell">
          <span class="field-label">图片缓存 TTL (天)</span>
          <input v-model="form.cacheTtlImages" type="number" min="0" max="365" class="field-input" />
          <span class="field-hint">对应 `cacheTtlImages`，Worker 会换算成图片响应缓存时长。</span>
        </label>

        <div class="field-shell md:col-span-2">
          <span class="field-label">CORS Origins</span>
          <textarea
            v-model="form.corsOrigins"
            rows="4"
            class="field-input field-textarea"
            placeholder="https://app.example.com"
          />
          <span class="field-hint">每行一个来源，保存时会写回逗号分隔的 `corsOrigins`。</span>
        </div>

        <div class="field-shell">
          <span class="field-label">地域白名单</span>
          <textarea
            v-model="form.geoAllowlist"
            rows="4"
            class="field-input field-textarea"
            placeholder="CN&#10;HK"
          />
          <span class="field-hint">对应 `geoAllowlist`，建议填写 ISO 国家代码，每行一个。</span>
        </div>

        <div class="field-shell">
          <span class="field-label">地域黑名单</span>
          <textarea
            v-model="form.geoBlocklist"
            rows="4"
            class="field-input field-textarea"
            placeholder="US&#10;SG"
          />
          <span class="field-hint">对应 `geoBlocklist`，保存时会自动转成大写并去重。</span>
        </div>

        <div class="field-shell md:col-span-2">
          <span class="field-label">IP 黑名单</span>
          <textarea
            v-model="form.ipBlacklist"
            rows="4"
            class="field-input field-textarea"
            placeholder="203.0.113.10&#10;2001:db8::1"
          />
          <span class="field-hint">对应 `ipBlacklist`，支持 IPv4 / IPv6，每行一个地址。</span>
        </div>
      </div>
    </article>

    <div class="mt-4 grid gap-4 lg:grid-cols-[1.05fr_0.95fr]">
      <article class="form-card">
        <div class="flex items-center gap-3">
          <BellRing class="h-5 w-5 text-mint-300" />
          <h3 class="text-sm font-medium text-white">日志写入、展示与批处理</h3>
        </div>

        <div class="mt-5 grid gap-4 md:grid-cols-2">
          <label class="field-shell">
            <span class="field-label">日志搜索模式</span>
            <select v-model="form.logSearchMode" class="field-input">
              <option value="fts">fts</option>
              <option value="like">like</option>
            </select>
          </label>

          <label class="field-shell">
            <span class="field-label">日志写入模式</span>
            <select v-model="form.logWriteMode" class="field-input">
              <option value="info">info</option>
              <option value="error">error</option>
            </select>
          </label>

          <label class="field-shell">
            <span class="field-label">日志保留天数</span>
            <input v-model="form.logRetentionDays" type="number" min="1" max="365" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">日志写入延迟 (分钟)</span>
            <input v-model="form.logWriteDelayMinutes" type="number" min="0" max="1440" step="0.5" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">落盘阈值 (条)</span>
            <input v-model="form.logFlushCountThreshold" type="number" min="1" max="5000" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">批次分块大小</span>
            <input v-model="form.logBatchChunkSize" type="number" min="1" max="100" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">批次重试次数</span>
            <input v-model="form.logBatchRetryCount" type="number" min="0" max="5" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">重试回退 (ms)</span>
            <input v-model="form.logBatchRetryBackoffMs" type="number" min="0" max="5000" class="field-input" />
          </label>
        </div>

        <div class="mt-5 grid gap-3 md:grid-cols-2">
          <label class="toggle-card">
            <input v-model="form.logEnabled" type="checkbox" class="h-4 w-4 rounded" />
            <span>启用日志</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.logWriteClientIp" type="checkbox" class="h-4 w-4 rounded" />
            <span>写入 Client IP</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.logWriteColo" type="checkbox" class="h-4 w-4 rounded" />
            <span>写入 Colo</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.logWriteUa" type="checkbox" class="h-4 w-4 rounded" />
            <span>写入 UA</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.logDisplayClientIp" type="checkbox" class="h-4 w-4 rounded" />
            <span>展示 Client IP</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.logDisplayColo" type="checkbox" class="h-4 w-4 rounded" />
            <span>展示 Colo</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.logDisplayUa" type="checkbox" class="h-4 w-4 rounded" />
            <span>展示 UA</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.logWriteImagePoster" type="checkbox" class="h-4 w-4 rounded" />
            <span>写入海报命中</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.logWriteMediaMetadata" type="checkbox" class="h-4 w-4 rounded" />
            <span>写入媒体元数据</span>
          </label>
        </div>
      </article>

      <article class="form-card">
        <div class="flex items-center gap-3">
          <BellRing class="h-5 w-5 text-brand-300" />
          <h3 class="text-sm font-medium text-white">调度、日报与告警</h3>
        </div>

        <div class="mt-5 grid gap-4 md:grid-cols-2">
          <label class="field-shell">
            <span class="field-label">调度租约 (ms)</span>
            <input v-model="form.scheduledLeaseMs" type="number" min="30000" max="900000" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">时区偏移 (分钟)</span>
            <input v-model="form.scheduleUtcOffsetMinutes" type="number" min="-720" max="840" class="field-input" />
            <span class="field-hint">例如北京时间使用 480。</span>
          </label>

          <div class="field-shell md:col-span-2">
            <span class="field-label">日报时刻</span>
            <textarea
              v-model="form.tgDailyReportClockTimes"
              rows="4"
              class="field-input field-textarea"
              placeholder="09:00"
            />
            <span class="field-hint">会写回 `tgDailyReportClockTimes`，每行一个时间。</span>
          </div>

          <label class="field-shell">
            <span class="field-label">丢批次告警阈值</span>
            <input v-model="form.tgAlertDroppedBatchThreshold" type="number" min="0" max="5000" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">刷写重试告警阈值</span>
            <input v-model="form.tgAlertFlushRetryThreshold" type="number" min="0" max="10" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">KV 用量告警百分比</span>
            <input v-model="form.tgAlertKvUsageThresholdPercent" type="number" min="1" max="100" class="field-input" />
          </label>

          <label class="field-shell">
            <span class="field-label">D1 用量告警百分比</span>
            <input v-model="form.tgAlertD1UsageThresholdPercent" type="number" min="1" max="100" class="field-input" />
          </label>

          <label class="field-shell md:col-span-2">
            <span class="field-label">告警冷却 (分钟)</span>
            <input v-model="form.tgAlertCooldownMinutes" type="number" min="1" max="1440" class="field-input" />
          </label>
        </div>

        <div class="mt-5 grid gap-3 md:grid-cols-2">
          <label class="toggle-card">
            <input v-model="form.tgDailyReportEnabled" type="checkbox" class="h-4 w-4 rounded" />
            <span>启用 Telegram 日报</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.tgDailyReportSummaryEnabled" type="checkbox" class="h-4 w-4 rounded" />
            <span>日报包含 Summary</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.tgDailyReportKvEnabled" type="checkbox" class="h-4 w-4 rounded" />
            <span>日报包含 KV 指标</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.tgDailyReportD1Enabled" type="checkbox" class="h-4 w-4 rounded" />
            <span>日报包含 D1 指标</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.tgAlertOnScheduledFailure" type="checkbox" class="h-4 w-4 rounded" />
            <span>调度失败时告警</span>
          </label>
          <label class="toggle-card">
            <input v-model="form.tgAlertKvUsageEnabled" type="checkbox" class="h-4 w-4 rounded" />
            <span>启用 KV 用量告警</span>
          </label>
          <label class="toggle-card md:col-span-2">
            <input v-model="form.tgAlertD1UsageEnabled" type="checkbox" class="h-4 w-4 rounded" />
            <span>启用 D1 用量告警</span>
          </label>
        </div>
      </article>
    </div>

    <div class="mt-4 grid gap-4">
      <DnsAutoUploadPanel
        :form="form"
        :disabled="authRequired || anySettingsBusy"
        title="DNS 自动上传调度与通知"
        description="这部分正式承接旧版 `dnsAutoUpload*` 字段，不再只停留在说明文案。保存设置时会和其他全局配置一起走 Worker 的 `saveConfig`。"
        @update:form="Object.assign(form, $event)"
      />

      <ConfigBackupPanel
        :data="configBackupPanelData"
        :loading="configBackupPanelLoading"
        :actions="configBackupPanelActions"
        description="这里已经直接接到 Worker 的 `loadConfig / getConfigSnapshots / previewConfig / exportConfig / exportSettings / importFull / importSettings`。导入会先做预检，再决定走完整备份还是 settings-only。"
      />

      <article class="form-card">
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div class="max-w-3xl">
            <div class="flex items-center gap-3">
              <Boxes class="h-5 w-5 text-ocean-300" />
              <h3 class="text-sm font-medium text-white">配置快照历史</h3>
            </div>
            <p class="mt-3 text-sm leading-6 text-slate-300">
              这里直接消费 Worker 返回的 `configSnapshots` 摘要列表，并接通刷新、恢复、清空三条真实链路。恢复时只覆盖配置，不会删除当前节点列表。
            </p>
          </div>

          <div class="flex flex-wrap items-center gap-3">
            <button
              type="button"
              class="secondary-btn"
              :disabled="authRequired || anySettingsBusy"
              @click="handleRefreshConfigSnapshots"
            >
              <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': configSnapshotsLoading }" />
              {{ configSnapshotsLoading ? '刷新中' : '刷新历史' }}
            </button>
            <button
              type="button"
              class="secondary-btn"
              :disabled="authRequired || anySettingsBusy || !configSnapshots.length"
              @click="handleClearConfigSnapshots"
            >
              <Trash2 class="h-4 w-4" />
              {{ clearConfigSnapshotsLoading ? '清空中' : '清空历史' }}
            </button>
          </div>
        </div>

        <div class="mt-5 grid gap-4 md:grid-cols-3">
          <div class="rounded-2xl border border-white/10 bg-slate-950/45 px-4 py-3">
            <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">快照数量</p>
            <p class="mt-2 text-2xl font-semibold text-white">{{ currentSnapshotCount }}</p>
            <p class="mt-2 text-sm leading-6 text-slate-400">当前 settings bootstrap 中已经同步到的快照总数。</p>
          </div>
          <div class="rounded-2xl border border-white/10 bg-slate-950/45 px-4 py-3">
            <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">最近快照</p>
            <p class="mt-2 text-base font-semibold text-white">{{ formatDateTime(latestConfigSnapshot?.createdAt) }}</p>
            <p class="mt-2 text-sm leading-6 text-slate-400">
              {{ latestConfigSnapshot ? formatConfigSnapshotReason(latestConfigSnapshot.reason) : '还没有历史快照。' }}
            </p>
          </div>
          <div class="rounded-2xl border border-white/10 bg-slate-950/45 px-4 py-3">
            <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">最近差异</p>
            <p class="mt-2 text-base font-semibold text-white">
              {{ latestConfigSnapshot ? `${latestConfigSnapshot.changeCount || latestConfigSnapshot.changedKeys?.length || 0} 项` : '0 项' }}
            </p>
            <p class="mt-2 text-sm leading-6 text-slate-400">
              {{ latestConfigSnapshot ? summarizeConfigSnapshotChangedKeys(latestConfigSnapshot.changedKeys) : '等待首次保存或导入后生成。' }}
            </p>
          </div>
        </div>

        <article
          v-if="snapshotFeedback.text"
          class="mt-5 rounded-3xl border p-5"
          :class="snapshotFeedback.tone === 'success'
            ? 'border-mint-400/25 bg-mint-400/10 text-mint-100'
            : 'border-rose-400/25 bg-rose-500/10 text-rose-100'"
        >
          <p v-if="snapshotFeedback.title" class="text-sm font-semibold">{{ snapshotFeedback.title }}</p>
          <p class="text-sm leading-6" :class="{ 'mt-2': snapshotFeedback.title }">{{ snapshotFeedback.text }}</p>
        </article>

        <div
          v-if="configSnapshots.length"
          class="mt-5 space-y-3"
        >
          <article
            v-for="snapshot in configSnapshots"
            :key="snapshot.id"
            class="rounded-3xl border border-white/10 bg-slate-950/45 px-5 py-4"
          >
            <div class="flex flex-wrap items-start justify-between gap-4">
              <div class="min-w-0 flex-1">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="inline-flex rounded-full border border-ocean-500/25 bg-ocean-500/10 px-3 py-1 text-xs text-ocean-100">
                    {{ formatConfigSnapshotReason(snapshot.reason) }}
                  </span>
                  <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                    {{ formatConfigSnapshotSection(snapshot.section) }}
                  </span>
                  <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-300">
                    {{ snapshot.source || 'unknown source' }}
                  </span>
                </div>
                <p class="mt-3 text-sm font-medium text-white">
                  {{ formatDateTime(snapshot.createdAt) }}
                </p>
                <p class="mt-2 text-sm leading-6 text-slate-300">
                  {{ snapshot.note || '这份快照没有附加说明。' }}
                </p>
              </div>

              <button
                type="button"
                class="secondary-btn"
                :disabled="authRequired || anySettingsBusy"
                @click="handleRestoreConfigSnapshot(snapshot)"
              >
                <RotateCcw class="h-4 w-4" />
                {{ restoreConfigSnapshotLoading ? '恢复中' : '恢复此快照' }}
              </button>
            </div>

            <div class="mt-4 grid gap-3 md:grid-cols-3">
              <div class="rounded-2xl border border-white/8 bg-white/5 px-4 py-3">
                <p class="text-xs uppercase tracking-[0.12em] text-slate-400">变更项数</p>
                <p class="mt-2 text-lg font-semibold text-white">{{ snapshot.changeCount || snapshot.changedKeys?.length || 0 }}</p>
              </div>
              <div class="rounded-2xl border border-white/8 bg-white/5 px-4 py-3">
                <p class="text-xs uppercase tracking-[0.12em] text-slate-400">Actor</p>
                <p class="mt-2 text-lg font-semibold text-white">{{ snapshot.actor || 'admin' }}</p>
              </div>
              <div class="rounded-2xl border border-white/8 bg-white/5 px-4 py-3">
                <p class="text-xs uppercase tracking-[0.12em] text-slate-400">Snapshot ID</p>
                <p class="mt-2 truncate text-sm font-medium text-slate-200">{{ snapshot.id }}</p>
              </div>
            </div>

            <div class="mt-4 flex flex-wrap gap-2">
              <span
                v-for="changedKey in (Array.isArray(snapshot.changedKeys) ? snapshot.changedKeys.slice(0, 8) : [])"
                :key="`${snapshot.id}-${changedKey}`"
                class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200"
              >
                {{ changedKey }}
              </span>
              <span
                v-if="Array.isArray(snapshot.changedKeys) && snapshot.changedKeys.length > 8"
                class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-400"
              >
                +{{ snapshot.changedKeys.length - 8 }} 项
              </span>
            </div>
          </article>
        </div>

        <div
          v-else
          class="mt-5 rounded-3xl border border-dashed border-white/12 bg-slate-950/30 px-5 py-6 text-sm leading-6 text-slate-400"
        >
          当前还没有配置快照历史。首次保存设置、导入设置备份或执行完整导入后，Worker 会在这里返回新的快照摘要。
        </div>
      </article>
    </div>

    <article class="form-card mt-4">
      <div class="flex items-center gap-3">
        <Boxes class="h-5 w-5 text-brand-300" />
        <h3 class="text-sm font-medium text-white">这次迁移已经接管的真实边界</h3>
      </div>

      <div class="mt-5 space-y-3 text-sm leading-6 text-slate-300">
        <p class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
          当前设置页已经不再只是说明文案，而是直接读取 Worker 返回的 `config / revisions / nodes / configSnapshots`。
        </p>
        <p class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
          保存时仍然走原有 `saveConfig`，并把 `meta.section=settings` 带回 Worker，便于后端沿用既有快照与审计语义。
        </p>
        <p class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
          这一轮已经把预热、Playback/进度转发、Hedge/Failover、日志写入细粒度、批处理阈值、调度时区和 Telegram 告警阈值搬进独立前端；日志检索工作台、节点治理和 DNS 工具台仍可继续从旧版 Worker UI 逐块拆出。
        </p>
      </div>

      <div class="mt-5 flex flex-wrap gap-3">
        <button
          type="button"
          class="secondary-btn"
          :disabled="savingConfig"
          @click="handleReset"
        >
          <RotateCcw class="h-4 w-4" />
          恢复本次读取结果
        </button>
        <button
          type="button"
          class="primary-btn"
          :disabled="authRequired || loadingSettings || savingConfig || !hasChanges"
          @click="handleSave"
        >
          <Save class="h-4 w-4" />
          保存到 Worker
        </button>
      </div>
    </article>
  </SectionCard>
</template>
