<script setup>
import { computed, onMounted, reactive, watch } from 'vue';
import {
  ArrowDown,
  ArrowUp,
  ArrowUpRight,
  Database,
  Globe,
  Link2,
  Network,
  Plus,
  RefreshCw,
  Save,
  ShieldAlert,
  Trash2,
  Waypoints
} from 'lucide-vue-next';

import SectionCard from '@/components/SectionCard.vue';
import { buildDnsWorkspaceSeed } from '@/features/dns/dnsWorkspaceSeed.js';

const props = defineProps({
  adminConsole: {
    type: Object,
    default: null
  }
});

let sourceDraftSequence = 0;
let dnsRecordDraftSequence = 0;

const authRequired = computed(() => props.adminConsole?.state?.authRequired === true);
const loadingWorkspace = computed(() => Boolean(props.adminConsole?.state?.loading?.dnsWorkspace));
const loadingSources = computed(() => Boolean(props.adminConsole?.state?.loading?.dnsPoolSources));
const loadingSaveSources = computed(() => Boolean(props.adminConsole?.state?.loading?.saveDnsPoolSources));
const loadingRefreshSources = computed(() => Boolean(props.adminConsole?.state?.loading?.refreshDnsPoolSources));
const loadingImportPreview = computed(() => Boolean(props.adminConsole?.state?.loading?.importDnsIpPoolItems));
const loadingDnsRecords = computed(() => Boolean(props.adminConsole?.state?.loading?.dnsRecords));
const loadingSaveDnsRecords = computed(() => Boolean(props.adminConsole?.state?.loading?.saveDnsRecords));
const loadingUpdateDnsRecord = computed(() => Boolean(props.adminConsole?.state?.loading?.updateDnsRecord));
const workspaceError = computed(() => String(props.adminConsole?.state?.errors?.dnsWorkspace || '').trim());
const sourcesError = computed(() => String(props.adminConsole?.state?.errors?.dnsPoolSources || '').trim());
const saveSourcesError = computed(() => String(props.adminConsole?.state?.errors?.saveDnsPoolSources || '').trim());
const refreshSourcesError = computed(() => String(props.adminConsole?.state?.errors?.refreshDnsPoolSources || '').trim());
const importPreviewError = computed(() => String(props.adminConsole?.state?.errors?.importDnsIpPoolItems || '').trim());
const dnsRecordsError = computed(() => String(props.adminConsole?.state?.errors?.dnsRecords || '').trim());
const saveDnsRecordsError = computed(() => String(props.adminConsole?.state?.errors?.saveDnsRecords || '').trim());
const updateDnsRecordError = computed(() => String(props.adminConsole?.state?.errors?.updateDnsRecord || '').trim());
const workspace = computed(() => props.adminConsole?.dnsWorkspace || createEmptyWorkspace());
const sourcesState = computed(() => props.adminConsole?.dnsPoolSourcesState || createEmptySourcesState());
const refreshState = computed(() => props.adminConsole?.dnsPoolRefreshState || createEmptyRefreshState());
const importPreviewState = computed(() => props.adminConsole?.dnsImportPreviewState || createEmptyImportPreviewState());
const dnsRecordsState = computed(() => props.adminConsole?.dnsRecordsState || createEmptyDnsRecordState());
const summary = computed(() => props.adminConsole?.dnsSummary || createEmptySummary());
const sourceList = computed(() => (
  Array.isArray(props.adminConsole?.dnsSourceList) ? props.adminConsole.dnsSourceList : []
));
const currentHostItems = computed(() => (
  Array.isArray(props.adminConsole?.dnsCurrentHostItems) ? props.adminConsole.dnsCurrentHostItems : []
));
const sharedPoolItems = computed(() => (
  Array.isArray(props.adminConsole?.dnsSharedPoolItems) ? props.adminConsole.dnsSharedPoolItems : []
));
const preferredDomainLinks = computed(() => (
  Array.isArray(props.adminConsole?.dnsPreferredDomainLinks) ? props.adminConsole.dnsPreferredDomainLinks : []
));
const preferredIpLinks = computed(() => (
  Array.isArray(props.adminConsole?.dnsPreferredIpLinks) ? props.adminConsole.dnsPreferredIpLinks : []
));
const builtInSourceOptions = computed(() => (
  Array.isArray(props.adminConsole?.dnsBuiltInSourceOptions) ? props.adminConsole.dnsBuiltInSourceOptions : []
));
const presetList = computed(() => (
  Array.isArray(props.adminConsole?.dnsPresetList) ? props.adminConsole.dnsPresetList : []
));
const dnsRevision = computed(() => String(props.adminConsole?.dnsIpPoolRevision || '').trim());
const activeDnsHost = computed(() => String(dnsRecordsState.value.currentHost || workspace.value.host || '').trim());
const anyBusy = computed(() => (
  loadingWorkspace.value
  || loadingSources.value
  || loadingSaveSources.value
  || loadingRefreshSources.value
  || loadingImportPreview.value
  || loadingDnsRecords.value
  || loadingSaveDnsRecords.value
  || loadingUpdateDnsRecord.value
));
const hasErrors = computed(() => Boolean(
  workspaceError.value
  || sourcesError.value
  || saveSourcesError.value
  || refreshSourcesError.value
  || importPreviewError.value
  || dnsRecordsError.value
  || saveDnsRecordsError.value
  || updateDnsRecordError.value
));
const hasWorkspaceData = computed(() => {
  return sourceList.value.length > 0
    || currentHostItems.value.length > 0
    || sharedPoolItems.value.length > 0
    || builtInSourceOptions.value.length > 0
    || presetList.value.length > 0
    || preferredDomainLinks.value.length > 0
    || preferredIpLinks.value.length > 0
    || Boolean(workspace.value.generatedAt)
    || Boolean(dnsRevision.value);
});
const sourceResults = computed(() => (
  Array.isArray(refreshState.value.sourceResults) ? refreshState.value.sourceResults : []
));
const refreshPreviewItems = computed(() => (
  Array.isArray(refreshState.value.items) ? refreshState.value.items.slice(0, 6) : []
));
const importPreviewItems = computed(() => (
  Array.isArray(importPreviewState.value.items) ? importPreviewState.value.items.slice(0, 8) : []
));
const dnsRecordHistoryEntries = computed(() => (
  Array.isArray(dnsRecordsState.value.history) ? dnsRecordsState.value.history.slice(0, 8) : []
));
const dnsRecordSyncSummaryRows = computed(() => buildDnsRecordSyncSummaryRows(dnsRecordsState.value.syncSummary));
const workspaceSeed = computed(() => buildDnsWorkspaceSeed());
const hasRenderableWorkspaceShell = computed(() => {
  return hasWorkspaceData.value
    || Boolean(String(importEditor.text || '').trim())
    || importPreviewItems.value.length > 0
    || Boolean(importPreviewState.value.lastImportedAt);
});

const sourceEditor = reactive({
  visible: false,
  drafts: [],
  baseline: '',
  feedbackTone: '',
  feedbackText: ''
});
const importEditor = reactive({
  text: '',
  sourceKind: 'manual',
  sourceLabel: '',
  feedbackTone: '',
  feedbackText: ''
});
const dnsRecordEditor = reactive({
  mode: 'a',
  drafts: [],
  baseline: '',
  feedbackTone: '',
  feedbackText: ''
});

const overviewRows = computed(() => [
  ['Zone ID', workspace.value.zoneId || '未返回'],
  ['Host', workspace.value.host || '当前工作区未绑定 host'],
  ['请求入口 Colo', workspace.value.requestColo || '未返回'],
  ['Probe Entry Colo', workspace.value.probeEntryColo || '未返回'],
  ['请求国家', resolveCountryText(workspace.value.requestCountryCode, workspace.value.requestCountryName)],
  ['Probe 数据源', resolveProbeDataSourceLabel(workspace.value.probeDataSource)],
  ['抓取快照状态', resolveSnapshotStatusLabel(workspace.value.sourceSnapshotStatus)],
  ['抓取源数量', `${sourceList.value.length} 条`],
  ['国家数', `${Number(summary.value.combined?.countryCount) || 0}`],
  ['Colo 数', `${Number(summary.value.combined?.coloCount) || 0}`]
]);

const summaryCards = computed(() => [
  buildSummaryCard('Current Host', summary.value.currentHost, currentHostItems.value.length, '当前 host 的独立池条目'),
  buildSummaryCard('Shared Pool', summary.value.sharedPool, sharedPoolItems.value.length, '共享池可直接用于预览的条目'),
  buildSummaryCard('Combined', summary.value.combined, currentHostItems.value.length + sharedPoolItems.value.length, '当前前端首版汇总口径')
]);

const metaRows = computed(() => [
  ['DNS Revision', compactRevision(dnsRevision.value)],
  ['Workspace Generated At', formatDateTime(workspace.value.generatedAt)],
  ['Workspace Last Fetched', formatDateTime(workspace.value.lastFetchedAt)],
  ['Source Last Fetched', formatDateTime(sourcesState.value.lastFetchedAt)],
  ['Background Refresh', workspace.value.backgroundRefreshQueued ? '后台刷新已排队' : '当前未排队']
]);

const currentHostPreview = computed(() => currentHostItems.value.slice(0, 6));
const sharedPoolPreview = computed(() => sharedPoolItems.value.slice(0, 8));
const sourceCards = computed(() => sourceList.value.map((source, index) => ({
  ...source,
  orderLabel: `#${index + 1}`,
  fetchStatusLabel: resolveFetchStatusLabel(source.lastFetchStatus),
  fetchStatusTone: resolveFetchStatusTone(source.lastFetchStatus)
})));

const optionCards = computed(() => builtInSourceOptions.value.map((option) => ({
  ...option,
  targetValue: option.value
})));

const presetCards = computed(() => presetList.value.map((preset) => ({
  ...preset,
  targetValue: preset.value
})));
const hasSourceDraftChanges = computed(() => serializeSourceDrafts(sourceEditor.drafts) !== sourceEditor.baseline);
const hasDnsRecordDraftChanges = computed(() => serializeDnsRecordDrafts(dnsRecordEditor.drafts, dnsRecordEditor.mode) !== dnsRecordEditor.baseline);
const dnsRecordModeOptions = computed(() => ([
  { value: 'a', label: 'A / AAAA 池' },
  { value: 'cname', label: '单 CNAME' }
]));

onMounted(() => {
  if (!props.adminConsole) return;
  if (anyBusy.value) return;
  if (!hasWorkspaceData.value && !authRequired.value) {
    void props.adminConsole.hydrateDnsPanel();
  }
});

watch(activeDnsHost, (nextHost) => {
  if (!props.adminConsole || !nextHost || authRequired.value) return;
  if (loadingDnsRecords.value || dnsRecordsState.value.lastFetchedAt) return;
  void props.adminConsole.getDnsRecords();
}, { immediate: true });

watch(sourceList, (nextList) => {
  if (!sourceEditor.visible || !hasSourceDraftChanges.value) {
    hydrateSourceDrafts(nextList);
  }
}, { immediate: true, deep: true });

watch(dnsRecordsState, (nextState) => {
  if (!hasDnsRecordDraftChanges.value || dnsRecordEditor.drafts.length === 0) {
    hydrateDnsRecordDrafts(nextState);
  }
}, { immediate: true, deep: true });

watch(
  [workspaceError, sourcesError, saveSourcesError, refreshSourcesError],
  ([nextWorkspaceError, nextSourcesError, nextSaveError, nextRefreshError]) => {
    const nextError = nextSaveError || nextRefreshError || nextWorkspaceError || nextSourcesError;
    if (nextError) {
      sourceEditor.feedbackTone = 'error';
      sourceEditor.feedbackText = nextError;
      return;
    }

    if (sourceEditor.feedbackTone === 'error') {
      sourceEditor.feedbackTone = '';
      sourceEditor.feedbackText = '';
    }
  }
);

watch(importPreviewError, (nextError) => {
  if (nextError) {
    importEditor.feedbackTone = 'error';
    importEditor.feedbackText = nextError;
    return;
  }

  if (importEditor.feedbackTone === 'error') {
    importEditor.feedbackTone = '';
    importEditor.feedbackText = '';
  }
});

watch([dnsRecordsError, saveDnsRecordsError, updateDnsRecordError], ([nextReadError, nextSaveError, nextUpdateError]) => {
  const nextError = nextUpdateError || nextSaveError || nextReadError;
  if (nextError) {
    dnsRecordEditor.feedbackTone = 'error';
    dnsRecordEditor.feedbackText = nextError;
    return;
  }

  if (dnsRecordEditor.feedbackTone === 'error') {
    dnsRecordEditor.feedbackTone = '';
    dnsRecordEditor.feedbackText = '';
  }
});

async function handleRefresh() {
  if (!props.adminConsole) return;
  await props.adminConsole.refreshDnsPanel({ forceRefresh: true });
}

async function handlePreviewImport() {
  if (!props.adminConsole || loadingImportPreview.value) return;
  if (!String(importEditor.text || '').trim()) {
    importEditor.feedbackTone = 'error';
    importEditor.feedbackText = '请先粘贴要预览的 IP / 域名文本。';
    return;
  }

  importEditor.feedbackTone = '';
  importEditor.feedbackText = '';

  const result = await props.adminConsole.importDnsIpPoolItems(importEditor.text, {
    sourceKind: importEditor.sourceKind,
    sourceLabel: importEditor.sourceLabel
  });
  if (!result) return;

  importEditor.feedbackTone = 'success';
  importEditor.feedbackText = `已预览 ${result.importedCount} 条条目，可继续对照工作区判断是否要落到 DNS 记录侧。`;
}

function handleResetImportEditor() {
  importEditor.text = '';
  importEditor.sourceKind = 'manual';
  importEditor.sourceLabel = '';
  importEditor.feedbackTone = '';
  importEditor.feedbackText = '';
}

function handleHydrateSeedIntoImportEditor() {
  const seed = workspaceSeed.value;
  if (!seed.hasSeed || !seed.importText) return;

  importEditor.text = seed.importText;
  importEditor.sourceKind = 'manual';
  importEditor.sourceLabel = seed.sourceLabel;
  importEditor.feedbackTone = 'success';
  importEditor.feedbackText = `已填入 ${seed.items.length} 条本地热启动候选数据，请继续点击“预览导入”走 Worker 真链路。`;
}

async function handleRefreshDnsRecords() {
  if (!props.adminConsole || loadingDnsRecords.value) return;

  dnsRecordEditor.feedbackTone = '';
  dnsRecordEditor.feedbackText = '';

  const result = await props.adminConsole.getDnsRecords();
  if (!result) return;

  if (!hasDnsRecordDraftChanges.value) {
    hydrateDnsRecordDrafts(result);
  }

  dnsRecordEditor.feedbackTone = 'success';
  dnsRecordEditor.feedbackText = `已读取 ${result.currentHost || workspace.value.host || '当前 Host'} 的 ${result.records.length} 条可编辑记录。`;
}

function handleOpenSourceEditor() {
  sourceEditor.visible = true;
  if (!hasSourceDraftChanges.value) {
    hydrateSourceDrafts(sourceList.value);
  }
}

function handleCloseSourceEditor() {
  sourceEditor.visible = false;
}

function handleResetSourceEditor() {
  hydrateSourceDrafts(sourceList.value);
  sourceEditor.feedbackTone = 'success';
  sourceEditor.feedbackText = '已回填到当前 Worker 返回的抓取源配置。';
}

function hydrateSourceDrafts(rawSources = []) {
  const nextDrafts = (Array.isArray(rawSources) ? rawSources : [])
    .map((source, index) => createSourceDraft(source, index))
    .filter(Boolean);

  sourceEditor.drafts.splice(0, sourceEditor.drafts.length, ...nextDrafts);
  sourceEditor.baseline = serializeSourceDrafts(nextDrafts);
}

function handleAddSourceDraft(kind = 'custom') {
  const firstBuiltIn = builtInSourceOptions.value[0] || null;
  const firstPreset = presetList.value[0] || null;
  const nextIndex = sourceEditor.drafts.length;

  const initialDraft = createSourceDraft({
    sourceKind: kind,
    sourceType: kind === 'preset'
      ? normalizeDraftSourceType(firstPreset?.sourceType || 'url')
      : normalizeDraftSourceType(firstBuiltIn?.sourceType || 'url'),
    builtinId: kind === 'builtin' ? String(firstBuiltIn?.id || '').trim() : '',
    presetId: kind === 'preset' ? String(firstPreset?.id || '').trim() : '',
    name: kind === 'builtin'
      ? String(firstBuiltIn?.label || '').trim()
      : kind === 'preset'
        ? String(firstPreset?.label || '').trim()
        : ''
  }, nextIndex);

  sourceEditor.visible = true;
  sourceEditor.drafts.push(initialDraft);
}

function handleRemoveSourceDraft(uid = '') {
  const normalizedUid = String(uid || '').trim();
  if (!normalizedUid) return;

  const nextDrafts = sourceEditor.drafts.filter((draft) => String(draft.uid || '').trim() !== normalizedUid);
  sourceEditor.drafts.splice(0, sourceEditor.drafts.length, ...nextDrafts);
}

function handleMoveSourceDraft(index = 0, direction = 0) {
  const sourceIndex = Number(index);
  const offset = Number(direction);
  if (!Number.isInteger(sourceIndex) || !Number.isInteger(offset) || offset === 0) return;

  const targetIndex = sourceIndex + offset;
  if (sourceIndex < 0 || sourceIndex >= sourceEditor.drafts.length) return;
  if (targetIndex < 0 || targetIndex >= sourceEditor.drafts.length) return;

  const nextDrafts = [...sourceEditor.drafts];
  const [movedDraft] = nextDrafts.splice(sourceIndex, 1);
  nextDrafts.splice(targetIndex, 0, movedDraft);
  sourceEditor.drafts.splice(0, sourceEditor.drafts.length, ...nextDrafts);
}

async function handleSaveSourceEditor() {
  if (!props.adminConsole || loadingSaveSources.value) return;

  sourceEditor.feedbackTone = '';
  sourceEditor.feedbackText = '';

  const result = await props.adminConsole.saveDnsIpPoolSources(
    sourceEditor.drafts.map((draft) => buildDraftPayload(draft))
  );

  if (!result) return;

  hydrateSourceDrafts(result.sourceList);
  sourceEditor.feedbackTone = 'success';
  sourceEditor.feedbackText = `抓取源已保存，共 ${result.sourceList.length} 条。`;
}

async function handleRefreshFromSources() {
  if (!props.adminConsole || loadingRefreshSources.value) return;

  sourceEditor.feedbackTone = '';
  sourceEditor.feedbackText = '';

  const result = await props.adminConsole.refreshDnsIpPoolFromSources();
  if (!result) return;

  sourceEditor.feedbackTone = 'success';
  sourceEditor.feedbackText = `已刷新抓取结果，导入 ${result.importedCount} 条，共 ${sourceResults.value.length} 个抓取源返回状态。`;
}

function hydrateDnsRecordDrafts(nextState = dnsRecordsState.value) {
  const normalizedMode = normalizeDnsRecordMode(nextState?.mode);
  const records = Array.isArray(nextState?.records) && nextState.records.length
    ? nextState.records
    : [createDnsRecordDraft({}, 0, normalizedMode)];

  dnsRecordEditor.mode = normalizedMode;
  dnsRecordEditor.drafts.splice(0, dnsRecordEditor.drafts.length, ...records.map((record, index) => createDnsRecordDraft(record, index, normalizedMode)));
  dnsRecordEditor.baseline = serializeDnsRecordDrafts(dnsRecordEditor.drafts, dnsRecordEditor.mode);
}

function createDnsRecordDraft(record = {}, index = 0, mode = 'a') {
  dnsRecordDraftSequence += 1;
  const normalizedMode = normalizeDnsRecordMode(mode);
  const fallbackType = normalizedMode === 'cname' ? 'CNAME' : 'A';
  const normalizedType = normalizeDnsRecordType(record.type, fallbackType);
  return {
    uid: `dns-record-draft-${dnsRecordDraftSequence}`,
    recordId: String(record.id || record.recordId || '').trim(),
    type: normalizedMode === 'cname'
      ? 'CNAME'
      : normalizedType === 'AAAA'
        ? 'AAAA'
        : 'A',
    content: String(record.content || '').trim(),
    name: String(record.name || activeDnsHost.value || '').trim(),
    ttl: String(Math.max(1, parseInt(record.ttl, 10) || 1)),
    proxied: record.proxied === true
  };
}

function normalizeDnsRecordMode(value = '') {
  return String(value || '').trim().toLowerCase() === 'cname' ? 'cname' : 'a';
}

function normalizeDnsRecordType(value = '', fallbackType = 'A') {
  const normalized = String(value || fallbackType || '').trim().toUpperCase();
  if (normalized === 'AAAA') return 'AAAA';
  if (normalized === 'CNAME') return 'CNAME';
  return normalized === 'A' ? 'A' : String(fallbackType || 'A').trim().toUpperCase();
}

function serializeDnsRecordDrafts(drafts = [], mode = 'a') {
  const normalizedMode = normalizeDnsRecordMode(mode);
  const normalizedDrafts = normalizeDnsRecordDraftsForSave(drafts, normalizedMode);
  return JSON.stringify({
    mode: normalizedMode,
    drafts: normalizedDrafts
  });
}

function normalizeDnsRecordDraftsForSave(drafts = [], mode = 'a') {
  const normalizedMode = normalizeDnsRecordMode(mode);
  const baseDrafts = (Array.isArray(drafts) ? drafts : [])
    .map((draft) => ({
      recordId: String(draft.recordId || '').trim(),
      type: normalizeDnsRecordType(draft.type, normalizedMode === 'cname' ? 'CNAME' : 'A'),
      content: String(draft.content || '').trim()
    }))
    .filter((draft) => draft.content);

  if (normalizedMode === 'cname') {
    const firstDraft = baseDrafts[0];
    return firstDraft ? [{ ...firstDraft, type: 'CNAME' }] : [];
  }

  return baseDrafts.filter((draft) => ['A', 'AAAA'].includes(draft.type));
}

function handleChangeDnsRecordMode(nextMode = 'a') {
  const normalizedMode = normalizeDnsRecordMode(nextMode);
  dnsRecordEditor.mode = normalizedMode;

  if (normalizedMode === 'cname') {
    const firstDraft = dnsRecordEditor.drafts[0] || createDnsRecordDraft({}, 0, 'cname');
    dnsRecordEditor.drafts.splice(0, dnsRecordEditor.drafts.length, {
      ...firstDraft,
      type: 'CNAME'
    });
    return;
  }

  if (!dnsRecordEditor.drafts.length) {
    dnsRecordEditor.drafts.push(createDnsRecordDraft({}, 0, 'a'));
    return;
  }

  dnsRecordEditor.drafts.splice(
    0,
    dnsRecordEditor.drafts.length,
    ...dnsRecordEditor.drafts.map((draft, index) => ({
      ...draft,
      type: normalizeDnsRecordType(draft.type, 'A') === 'AAAA' ? 'AAAA' : 'A'
    }))
  );
}

function handleAddDnsRecordDraft() {
  if (dnsRecordEditor.mode === 'cname') {
    if (!dnsRecordEditor.drafts.length) {
      dnsRecordEditor.drafts.push(createDnsRecordDraft({}, 0, 'cname'));
    }
    return;
  }

  dnsRecordEditor.drafts.push(createDnsRecordDraft({}, dnsRecordEditor.drafts.length, dnsRecordEditor.mode));
}

function handleRemoveDnsRecordDraft(uid = '') {
  const normalizedUid = String(uid || '').trim();
  if (!normalizedUid) return;

  const nextDrafts = dnsRecordEditor.drafts.filter((draft) => draft.uid !== normalizedUid);
  if (!nextDrafts.length) {
    dnsRecordEditor.drafts.splice(0, dnsRecordEditor.drafts.length, createDnsRecordDraft({}, 0, dnsRecordEditor.mode));
    return;
  }

  dnsRecordEditor.drafts.splice(0, dnsRecordEditor.drafts.length, ...nextDrafts);
}

async function handleSaveDnsRecords() {
  if (!props.adminConsole || loadingSaveDnsRecords.value || !activeDnsHost.value) return;

  const records = normalizeDnsRecordDraftsForSave(dnsRecordEditor.drafts, dnsRecordEditor.mode);
  if (!records.length) {
    dnsRecordEditor.feedbackTone = 'error';
    dnsRecordEditor.feedbackText = dnsRecordEditor.mode === 'cname'
      ? 'CNAME 模式至少需要 1 条有效记录。'
      : 'A / AAAA 模式至少需要 1 条有效记录。';
    return;
  }

  dnsRecordEditor.feedbackTone = '';
  dnsRecordEditor.feedbackText = '';

  const result = await props.adminConsole.saveDnsRecords({
    host: activeDnsHost.value,
    mode: dnsRecordEditor.mode,
    records
  });
  if (!result) return;

  hydrateDnsRecordDrafts(result);
  dnsRecordEditor.feedbackTone = 'success';
  dnsRecordEditor.feedbackText = `已保存 ${activeDnsHost.value} 的 ${result.records.length} 条 DNS 记录。`;
}

async function handleSaveSingleDnsRecord(draft = {}) {
  if (!props.adminConsole || loadingUpdateDnsRecord.value || !activeDnsHost.value) return;

  const content = String(draft.content || '').trim();
  if (!content) {
    dnsRecordEditor.feedbackTone = 'error';
    dnsRecordEditor.feedbackText = '单条保存前请先填写记录内容。';
    return;
  }

  const isExistingRecord = Boolean(String(draft.recordId || '').trim());
  const result = await props.adminConsole.updateDnsRecord({
    recordId: String(draft.recordId || '').trim(),
    type: normalizeDnsRecordType(draft.type, dnsRecordEditor.mode === 'cname' ? 'CNAME' : 'A'),
    content
  }, {
    host: activeDnsHost.value
  });
  if (!result?.record) return;

  draft.recordId = String(result.record.id || draft.recordId || '').trim();
  draft.type = normalizeDnsRecordType(result.record.type, draft.type);
  draft.content = String(result.record.content || draft.content || '').trim();
  draft.name = String(result.record.name || activeDnsHost.value).trim();

  dnsRecordEditor.feedbackTone = 'success';
  dnsRecordEditor.feedbackText = isExistingRecord ? 'DNS 记录已同步到 Cloudflare。' : 'DNS 记录已创建。';
}

function createEmptySummaryBlock() {
  return {
    ipCount: 0,
    ipv4Count: 0,
    ipv6Count: 0,
    countryCount: 0,
    coloCount: 0
  };
}

function createEmptySummary() {
  return {
    currentHost: createEmptySummaryBlock(),
    sharedPool: createEmptySummaryBlock(),
    combined: createEmptySummaryBlock()
  };
}

function createEmptyWorkspace() {
  return {
    zoneId: '',
    host: '',
    requestColo: '',
    probeEntryColo: '',
    requestCountryCode: '',
    requestCountryName: '',
    probeDataSource: 'cache',
    sourceSnapshotStatus: 'empty',
    backgroundRefreshQueued: false,
    generatedAt: '',
    lastFetchedAt: ''
  };
}

function createEmptySourcesState() {
  return {
    lastFetchedAt: ''
  };
}

function createEmptyRefreshState() {
  return {
    sourceResults: [],
    items: [],
    importedCount: 0,
    cacheStatus: '',
    backgroundRefreshQueued: false,
    cachedAt: '',
    expiresAt: ''
  };
}

function createEmptyImportPreviewState() {
  return {
    sourceKind: 'manual',
    sourceLabel: '',
    importedCount: 0,
    items: [],
    lastImportedAt: ''
  };
}

function createEmptyDnsRecordState() {
  return {
    zoneId: '',
    zoneName: '',
    currentHost: '',
    totalRecords: 0,
    editableRecordCount: 0,
    filteredCount: 0,
    records: [],
    history: [],
    mode: 'a',
    syncSummary: null,
    rollbackAttempted: false,
    rollbackSucceeded: false,
    rollbackError: '',
    lastFetchedAt: ''
  };
}

function buildSummaryCard(title, block, previewCount, note) {
  const summaryBlock = block && typeof block === 'object' ? block : createEmptySummaryBlock();
  return {
    title,
    value: `${Math.max(0, Number(summaryBlock.ipCount) || 0)} 条`,
    note,
    previewCount,
    secondary: [
      `IPv4 ${Math.max(0, Number(summaryBlock.ipv4Count) || 0)}`,
      `IPv6 ${Math.max(0, Number(summaryBlock.ipv6Count) || 0)}`,
      `国家 ${Math.max(0, Number(summaryBlock.countryCount) || 0)}`,
      `Colo ${Math.max(0, Number(summaryBlock.coloCount) || 0)}`
    ]
  };
}

function formatDateTime(rawValue = '') {
  const value = String(rawValue || '').trim();
  if (!value) return '未返回';

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

function compactRevision(rawValue = '') {
  const value = String(rawValue || '').trim();
  if (!value) return '未生成';
  return value.length > 18 ? `${value.slice(0, 18)}...` : value;
}

function resolveCountryText(code = '', name = '') {
  const normalizedCode = String(code || '').trim().toUpperCase();
  const normalizedName = String(name || '').trim();
  if (normalizedCode && normalizedName) return `${normalizedCode} / ${normalizedName}`;
  return normalizedCode || normalizedName || '未返回';
}

function resolveProbeDataSourceLabel(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'live_sync') return '实时同步探测';
  if (normalized === 'live_deferred') return '延迟后台探测';
  return '缓存探测结果';
}

function resolveSnapshotStatusLabel(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'live_sync') return '实时同步抓取';
  if (normalized === 'live_deferred') return '后台排队抓取';
  if (normalized === 'cache') return '命中缓存';
  return '当前没有可用快照';
}

function resolveFetchStatusLabel(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'success') return '抓取成功';
  if (normalized === 'failed') return '抓取失败';
  if (normalized === 'empty') return '结果为空';
  return '尚未抓取';
}

function resolveFetchStatusTone(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'success') return 'border-mint-400/30 bg-mint-400/12 text-mint-300';
  if (normalized === 'failed') return 'border-rose-400/30 bg-rose-500/12 text-rose-200';
  if (normalized === 'empty') return 'border-amber-400/30 bg-amber-500/12 text-amber-200';
  return 'border-white/12 bg-white/6 text-slate-200';
}

function resolveProbeStatusLabel(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'ok') return '探测通过';
  if (normalized === 'pending') return '等待探测';
  if (normalized === 'cf_header_missing') return '缺少 CF Header';
  if (normalized === 'non_cloudflare') return '非 Cloudflare 路径';
  if (normalized === 'timeout') return '探测超时';
  if (normalized === 'network_error') return '网络异常';
  return '未探测';
}

function createSourceDraft(source = {}, index = 0) {
  sourceDraftSequence += 1;
  return {
    uid: String(source.uid || `dns-source-draft-${sourceDraftSequence}`),
    id: String(source.id || '').trim(),
    name: String(source.name || '').trim(),
    sourceKind: normalizeDraftSourceKind(source.sourceKind || source.source_kind),
    sourceType: normalizeDraftSourceType(source.sourceType || source.source_type),
    url: String(source.url || '').trim(),
    domain: String(source.domain || '').trim(),
    builtinId: String(source.builtinId || source.builtin_id || '').trim(),
    presetId: String(source.presetId || source.preset_id || '').trim(),
    enabled: source.enabled !== false,
    ipLimit: String(Math.max(1, parseInt(source.ipLimit ?? source.ip_limit, 10) || 5)),
    sortOrder: Math.max(0, parseInt(source.sortOrder ?? source.sort_order, 10) || index)
  };
}

function buildDraftPayload(draft = {}) {
  return {
    ...(String(draft.id || '').trim() ? { id: String(draft.id || '').trim() } : {}),
    name: String(draft.name || '').trim(),
    sourceKind: normalizeDraftSourceKind(draft.sourceKind),
    sourceType: normalizeDraftSourceType(draft.sourceType),
    url: String(draft.url || '').trim(),
    domain: String(draft.domain || '').trim(),
    builtinId: String(draft.builtinId || '').trim(),
    presetId: String(draft.presetId || '').trim(),
    enabled: draft.enabled === true,
    ipLimit: Math.max(1, parseInt(draft.ipLimit, 10) || 5)
  };
}

function normalizeDraftSourceKind(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'builtin') return 'builtin';
  if (normalized === 'preset') return 'preset';
  return 'custom';
}

function normalizeDraftSourceType(value = '') {
  return String(value || '').trim().toLowerCase() === 'domain' ? 'domain' : 'url';
}

function resolveSourceKindLabel(value = '') {
  const normalized = normalizeDraftSourceKind(value);
  if (normalized === 'builtin') return '内置源';
  if (normalized === 'preset') return '预设源';
  return '自定义源';
}

function resolveSourceKindTone(value = '') {
  const normalized = normalizeDraftSourceKind(value);
  if (normalized === 'builtin') return 'border-brand-400/25 bg-brand-500/12 text-brand-100';
  if (normalized === 'preset') return 'border-ocean-500/30 bg-ocean-500/12 text-ocean-200';
  return 'border-white/10 bg-white/6 text-slate-200';
}

function resolveSourceDraftTarget(draft = {}) {
  const sourceKind = normalizeDraftSourceKind(draft.sourceKind);
  if (sourceKind === 'builtin') {
    return resolveSourceOptionValue(builtInSourceOptions.value, draft.builtinId);
  }
  if (sourceKind === 'preset') {
    return resolveSourceOptionValue(presetList.value, draft.presetId);
  }
  return normalizeDraftSourceType(draft.sourceType) === 'domain'
    ? String(draft.domain || '').trim()
    : String(draft.url || '').trim();
}

function resolveSourceOptionLabel(options = [], id = '') {
  const normalizedId = String(id || '').trim();
  if (!normalizedId) return '';
  return String((Array.isArray(options) ? options : []).find((item) => item.id === normalizedId)?.label || '').trim();
}

function resolveSourceOptionValue(options = [], id = '') {
  const normalizedId = String(id || '').trim();
  if (!normalizedId) return '';
  return String((Array.isArray(options) ? options : []).find((item) => item.id === normalizedId)?.value || '').trim();
}

function serializeSourceDrafts(drafts = []) {
  return JSON.stringify((Array.isArray(drafts) ? drafts : []).map((draft, index) => ({
    id: String(draft.id || '').trim(),
    name: String(draft.name || '').trim(),
    sourceKind: normalizeDraftSourceKind(draft.sourceKind),
    sourceType: normalizeDraftSourceType(draft.sourceType),
    url: String(draft.url || '').trim(),
    domain: String(draft.domain || '').trim(),
    builtinId: String(draft.builtinId || '').trim(),
    presetId: String(draft.presetId || '').trim(),
    enabled: draft.enabled === true,
    ipLimit: Math.max(1, parseInt(draft.ipLimit, 10) || 5),
    sortOrder: index
  })));
}

function resolveRefreshCacheStatusLabel(value = '') {
  return String(value || '').trim().toLowerCase() === 'live' ? '实时抓取' : '命中缓存 / D1';
}

function resolveRefreshCacheStatusTone(value = '') {
  return String(value || '').trim().toLowerCase() === 'live'
    ? 'border-mint-400/30 bg-mint-400/12 text-mint-300'
    : 'border-ocean-500/30 bg-ocean-500/12 text-ocean-200';
}

function buildDnsRecordSyncSummaryRows(summary = null) {
  if (!summary || typeof summary !== 'object') return [];

  return [
    ['模式', normalizeDnsRecordMode(summary.mode) === 'cname' ? 'CNAME' : 'A / AAAA'],
    ['目标条数', String(Math.max(0, Number(summary.desiredCount) || 0))],
    ['未变化', String(Math.max(0, Number(summary.identicalCount) || 0))],
    ['已更新', String(Math.max(0, Number(summary.updatedCount) || 0))],
    ['已创建', String(Math.max(0, Number(summary.createdCount) || 0))],
    ['已删除', String(Math.max(0, Number(summary.deletedCount) || 0))]
  ];
}
</script>

<template>
  <SectionCard
    eyebrow="DNS Workspace"
    title="DNS / IP 池工作区已经接通真实抓取源管理"
    description="这一屏继续接管 `getDnsIpWorkspace`、`getDnsIpPoolSources`、`saveDnsIpPoolSources` 和 `refreshDnsIpPoolFromSources`，把抓取源编辑与手动刷新闭环从旧版 Worker UI 迁到独立前端。"
  >
    <template #meta>
      <div class="flex flex-wrap items-center justify-end gap-3">
        <div
          class="inline-flex rounded-full border px-3 py-1 text-xs font-semibold"
          :class="authRequired
            ? 'border-amber-400/30 bg-amber-500/12 text-amber-200'
            : hasErrors
              ? 'border-rose-400/30 bg-rose-500/12 text-rose-200'
              : anyBusy
                ? 'border-ocean-500/30 bg-ocean-500/12 text-ocean-300'
                : 'border-mint-400/30 bg-mint-400/12 text-mint-300'"
        >
          {{
            authRequired
              ? '需要登录'
              : hasErrors
                ? '部分读取失败'
                : anyBusy
                  ? '正在同步'
                  : 'DNS 已接通'
          }}
        </div>
        <button
          type="button"
          class="secondary-btn"
          :disabled="anyBusy"
          @click="handleRefresh"
        >
          <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': anyBusy }" />
          刷新 DNS
        </button>
        <button
          type="button"
          class="secondary-btn"
          :disabled="authRequired || loadingRefreshSources"
          @click="handleRefreshFromSources"
        >
          <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loadingRefreshSources }" />
          刷新抓取结果
        </button>
        <button
          type="button"
          class="secondary-btn"
          :disabled="authRequired || loadingSaveSources"
          @click="sourceEditor.visible ? handleCloseSourceEditor() : handleOpenSourceEditor()"
        >
          {{ sourceEditor.visible ? '收起源编辑器' : '管理抓取源' }}
        </button>
      </div>
    </template>

    <article
      v-if="authRequired"
      class="rounded-3xl border border-amber-300/25 bg-amber-500/10 p-5 text-amber-50"
    >
      <div class="flex items-start gap-3">
        <ShieldAlert class="mt-0.5 h-5 w-5 shrink-0 text-amber-200" />
        <div>
          <p class="text-sm font-semibold">当前 DNS 工作区需要复用 Worker 已登录会话</p>
          <p class="mt-2 text-sm leading-6 text-amber-50/85">
            独立前端不会新造一套鉴权。先在 Worker 管理台完成登录，再回来刷新这一屏，`getDnsIpWorkspace` 和 `getDnsIpPoolSources`
            就会继续复用现有 Cookie 会话。
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
      v-else-if="!hasWorkspaceData && anyBusy"
      class="rounded-3xl border border-white/10 bg-white/5 p-5"
    >
      <div class="flex items-start gap-3">
        <RefreshCw class="mt-0.5 h-5 w-5 shrink-0 animate-spin text-ocean-300" />
        <div>
          <p class="text-sm font-semibold text-white">正在从 Worker 拉取 DNS / IP 池工作区</p>
          <p class="mt-2 text-sm leading-6 text-slate-300">
            当前会并行读取工作区快照与抓取源配置，成功后会展示 summary、sourceList、preferred links 和只读预览。
          </p>
        </div>
      </div>
    </article>

    <div v-else class="space-y-6">
      <article
        v-if="workspaceError || sourcesError || saveSourcesError || refreshSourcesError"
        class="rounded-3xl border border-rose-400/25 bg-rose-500/10 p-5 text-rose-50"
      >
        <div class="flex items-start gap-3">
          <ShieldAlert class="mt-0.5 h-5 w-5 shrink-0 text-rose-200" />
          <div class="space-y-2">
            <p class="text-sm font-semibold">DNS 面板有部分数据未成功读取</p>
            <p v-if="workspaceError" class="text-sm leading-6 text-rose-50/85">Workspace：{{ workspaceError }}</p>
            <p v-if="sourcesError" class="text-sm leading-6 text-rose-50/85">Sources：{{ sourcesError }}</p>
            <p v-if="saveSourcesError" class="text-sm leading-6 text-rose-50/85">Save Sources：{{ saveSourcesError }}</p>
            <p v-if="refreshSourcesError" class="text-sm leading-6 text-rose-50/85">Refresh Sources：{{ refreshSourcesError }}</p>
          </div>
        </div>
      </article>

      <article
        v-if="sourceEditor.feedbackText"
        class="rounded-3xl border p-5"
        :class="sourceEditor.feedbackTone === 'error'
          ? 'border-rose-400/25 bg-rose-500/10 text-rose-50'
          : 'border-mint-400/25 bg-mint-400/10 text-mint-50'"
      >
        <p class="text-sm font-semibold">
          {{ sourceEditor.feedbackTone === 'error' ? '抓取源操作失败' : '抓取源操作已完成' }}
        </p>
        <p class="mt-2 text-sm leading-6 opacity-90">
          {{ sourceEditor.feedbackText }}
        </p>
      </article>

      <div v-if="!hasRenderableWorkspaceShell && !anyBusy" class="rounded-3xl border border-dashed border-white/12 bg-white/4 p-8 text-center">
        <p class="text-base font-semibold text-white">当前还没有可展示的 DNS 工作区内容</p>
        <p class="mt-3 text-sm leading-6 text-slate-300">
          后端暂时没有返回 sourceList、summary 或 preview 条目。可以稍后再试，或者在 Worker 侧先准备抓取源与共享池数据。
        </p>

        <div
          v-if="workspaceSeed.hasSeed"
          class="mx-auto mt-6 max-w-5xl rounded-3xl border border-ocean-500/20 bg-ocean-500/8 p-5 text-left"
        >
          <div class="flex flex-wrap items-start justify-between gap-4">
            <div class="max-w-3xl">
              <div class="flex items-center gap-3">
                <Database class="h-5 w-5 text-ocean-300" />
                <p class="text-sm font-semibold text-white">本地热启动候选数据</p>
              </div>
              <p class="mt-3 text-sm leading-6 text-slate-200">
                {{ workspaceSeed.description }}
              </p>
              <p class="mt-2 text-xs text-slate-400">
                来源标签：{{ workspaceSeed.sourceLabel }}
                <span v-if="workspaceSeed.updatedAt">
                  · 最近更新时间 {{ formatDateTime(workspaceSeed.updatedAt) }}
                </span>
              </p>
            </div>

            <button
              type="button"
              class="secondary-btn"
              :disabled="loadingImportPreview"
              @click="handleHydrateSeedIntoImportEditor"
            >
              填入导入区
            </button>
          </div>

          <div class="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div class="rounded-2xl border border-white/10 bg-slate-950/45 px-4 py-3">
              <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">候选条目</p>
              <p class="mt-2 text-xl font-semibold text-white">{{ workspaceSeed.summary.ipCount }}</p>
            </div>
            <div class="rounded-2xl border border-white/10 bg-slate-950/45 px-4 py-3">
              <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">IPv4 / IPv6</p>
              <p class="mt-2 text-xl font-semibold text-white">
                {{ workspaceSeed.summary.ipv4Count }} / {{ workspaceSeed.summary.ipv6Count }}
              </p>
            </div>
            <div class="rounded-2xl border border-white/10 bg-slate-950/45 px-4 py-3">
              <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">抓取源缓存</p>
              <p class="mt-2 text-xl font-semibold text-white">{{ workspaceSeed.sourceCount }}</p>
            </div>
            <div class="rounded-2xl border border-white/10 bg-slate-950/45 px-4 py-3">
              <p class="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">国家 / Colo</p>
              <p class="mt-2 text-xl font-semibold text-white">
                {{ workspaceSeed.summary.countryCount }} / {{ workspaceSeed.summary.coloCount }}
              </p>
            </div>
          </div>

          <div v-if="workspaceSeed.sourcePreviewLabels.length" class="mt-4 flex flex-wrap gap-2">
            <span
              v-for="label in workspaceSeed.sourcePreviewLabels"
              :key="label"
              class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200"
            >
              {{ label }}
            </span>
          </div>

          <div v-if="workspaceSeed.previewItems.length" class="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            <div
              v-for="item in workspaceSeed.previewItems"
              :key="item.id"
              class="rounded-2xl border border-white/10 bg-slate-950/45 px-4 py-3"
            >
              <div class="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p class="font-mono text-sm text-slate-100">{{ item.ip }}</p>
                  <p class="mt-1 text-xs text-slate-400">
                    {{ item.ipType }} · {{ item.lineLabel || item.countryCode || '未标记' }}
                  </p>
                </div>
                <span
                  v-if="item.probeStatus"
                  class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200"
                >
                  {{ resolveProbeStatusLabel(item.probeStatus) }}
                </span>
              </div>
              <p class="mt-3 text-xs text-slate-400">
                {{ item.coloCode || '未返回 Colo' }}
                <span v-if="item.latencyMs !== null"> · {{ item.latencyMs }} ms</span>
                <span v-if="item.sourceLabel"> · {{ item.sourceLabel }}</span>
              </p>
            </div>
          </div>

          <p class="mt-4 text-xs leading-6 text-slate-400">
            {{ workspaceSeed.note }}
          </p>
        </div>
      </div>

      <template v-else>
        <div class="grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
          <article class="stat-tile">
            <div class="flex items-center gap-3">
              <Network class="h-5 w-5 text-brand-300" />
              <h3 class="text-sm font-medium text-white">Workspace 概览</h3>
            </div>
            <div class="mt-5 grid gap-3 sm:grid-cols-2">
              <div
                v-for="row in overviewRows"
                :key="row[0]"
                class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3"
              >
                <p class="text-xs uppercase tracking-[0.16em] text-slate-400">{{ row[0] }}</p>
                <p class="mt-3 break-all text-sm font-medium leading-6 text-slate-100">{{ row[1] }}</p>
              </div>
            </div>
          </article>

          <article class="stat-tile">
            <div class="flex items-center gap-3">
              <Database class="h-5 w-5 text-ocean-300" />
              <h3 class="text-sm font-medium text-white">Revision / 时间信息</h3>
            </div>
            <div class="mt-5 space-y-3">
              <div
                v-for="row in metaRows"
                :key="row[0]"
                class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3"
              >
                <p class="text-xs uppercase tracking-[0.16em] text-slate-400">{{ row[0] }}</p>
                <p class="mt-3 break-all text-sm font-medium leading-6 text-slate-100">{{ row[1] }}</p>
              </div>
            </div>
          </article>
        </div>

        <div class="grid gap-4 md:grid-cols-3">
          <article v-for="card in summaryCards" :key="card.title" class="stat-tile">
            <div class="flex items-center gap-3">
              <Waypoints class="h-5 w-5 text-mint-300" />
              <h3 class="text-sm font-medium text-white">{{ card.title }}</h3>
            </div>
            <p class="mt-4 text-2xl font-semibold text-brand-300">{{ card.value }}</p>
            <p class="mt-2 text-sm leading-6 text-slate-300">{{ card.note }}</p>
            <p class="mt-2 text-xs uppercase tracking-[0.16em] text-slate-400">Preview {{ card.previewCount }} 条</p>
            <div class="mt-4 flex flex-wrap gap-2">
              <span
                v-for="item in card.secondary"
                :key="item"
                class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200"
              >
                {{ item }}
              </span>
            </div>
          </article>
        </div>

        <div class="grid gap-4 xl:grid-cols-2">
          <article class="stat-tile">
            <div class="flex items-center gap-3">
              <Globe class="h-5 w-5 text-brand-300" />
              <h3 class="text-sm font-medium text-white">Current Host Preview</h3>
            </div>
            <div v-if="currentHostPreview.length" class="mt-5 space-y-3">
              <div
                v-for="item in currentHostPreview"
                :key="item.id"
                class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3"
              >
                <div class="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p class="font-mono text-sm text-slate-100">{{ item.ip }}</p>
                    <p class="mt-1 text-xs text-slate-400">{{ item.ipType }} · {{ item.lineLabel || '未标记线路' }}</p>
                  </div>
                  <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                    {{ resolveProbeStatusLabel(item.probeStatus) }}
                  </span>
                </div>
              </div>
            </div>
            <p v-else class="mt-5 text-sm leading-6 text-slate-300">
              后端当前返回的 `currentHostItems` 为空，说明这一版前端还没有拿到当前 host 独立池条目。
            </p>
          </article>

          <article class="stat-tile">
            <div class="flex items-center gap-3">
              <Network class="h-5 w-5 text-ocean-300" />
              <h3 class="text-sm font-medium text-white">Shared Pool Preview</h3>
            </div>
            <div v-if="sharedPoolPreview.length" class="mt-5 space-y-3">
              <div
                v-for="item in sharedPoolPreview"
                :key="item.id"
                class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3"
              >
                <div class="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p class="font-mono text-sm text-slate-100">{{ item.ip }}</p>
                    <p class="mt-1 text-xs text-slate-400">
                      {{ item.ipType }} · {{ item.countryCode || 'UNKNOWN' }} / {{ item.countryName || '未知' }}
                    </p>
                  </div>
                  <div class="text-right text-xs text-slate-400">
                    <p>{{ item.coloCode || '未返回 Colo' }}</p>
                    <p class="mt-1">{{ item.latencyMs === null ? '无延迟数据' : `${item.latencyMs} ms` }}</p>
                  </div>
                </div>
                <p class="mt-3 text-xs text-slate-400">
                  {{ resolveProbeStatusLabel(item.probeStatus) }} · {{ formatDateTime(item.probedAt) }}
                </p>
              </div>
            </div>
            <p v-else class="mt-5 text-sm leading-6 text-slate-300">
              共享池当前没有可展示的 preview 条目，或者抓取结果还没有进入可读快照。
            </p>
          </article>
        </div>

        <div class="grid gap-4 xl:grid-cols-[0.95fr_1.05fr]">
          <article class="stat-tile">
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="flex items-center gap-3">
                <Network class="h-5 w-5 text-ocean-300" />
                <div>
                  <h3 class="text-sm font-medium text-white">手动导入预览</h3>
                  <p class="mt-2 text-sm leading-6 text-slate-300">
                    直接调用 Worker 的 `importDnsIpPoolItems`，先把粘贴文本解析成预览条目，不落库、不 mock。
                  </p>
                </div>
              </div>

              <div class="flex flex-wrap gap-3">
                <button
                  type="button"
                  class="secondary-btn"
                  :disabled="loadingImportPreview"
                  @click="handleResetImportEditor"
                >
                  清空
                </button>
                <button
                  type="button"
                  class="secondary-btn"
                  :disabled="authRequired || loadingImportPreview"
                  @click="handlePreviewImport"
                >
                  <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loadingImportPreview }" />
                  {{ loadingImportPreview ? '预览中' : '预览导入' }}
                </button>
              </div>
            </div>

            <div class="mt-5 grid gap-4">
              <label class="field-shell">
                <span class="field-label">文本内容</span>
                <textarea
                  v-model="importEditor.text"
                  rows="8"
                  class="field-input field-textarea font-mono text-xs leading-6"
                  placeholder="粘贴 IP、域名或混合文本，Worker 会按真实解析规则提取。"
                  :disabled="loadingImportPreview"
                />
              </label>

              <div class="grid gap-4 md:grid-cols-2">
                <label class="field-shell">
                  <span class="field-label">来源类型</span>
                  <select v-model="importEditor.sourceKind" class="field-input" :disabled="loadingImportPreview">
                    <option value="manual">manual</option>
                    <option value="file">file</option>
                  </select>
                </label>

                <label class="field-shell">
                  <span class="field-label">来源标签</span>
                  <input
                    v-model="importEditor.sourceLabel"
                    type="text"
                    class="field-input"
                    placeholder="例如 旧版节点导出的 IP 文本"
                    :disabled="loadingImportPreview"
                  />
                </label>
              </div>
            </div>

            <article
              v-if="importEditor.feedbackText"
              class="mt-5 rounded-2xl border px-4 py-4 text-sm leading-6"
              :class="importEditor.feedbackTone === 'error'
                ? 'border-rose-400/25 bg-rose-500/10 text-rose-50'
                : 'border-mint-400/25 bg-mint-400/10 text-mint-50'"
            >
              {{ importEditor.feedbackText }}
            </article>

            <div class="mt-5 flex flex-wrap gap-2">
              <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                预览 {{ importPreviewState.importedCount || 0 }} 条
              </span>
              <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                来源 {{ importPreviewState.sourceKind || 'manual' }}
              </span>
              <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                预览时间 {{ formatDateTime(importPreviewState.lastImportedAt) }}
              </span>
            </div>

            <div v-if="importPreviewItems.length" class="mt-5 grid gap-3 md:grid-cols-2">
              <div
                v-for="item in importPreviewItems"
                :key="`import-preview-${item.id}`"
                class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3"
              >
                <p class="font-mono text-sm text-slate-100">{{ item.ip }}</p>
                <p class="mt-2 text-xs text-slate-400">
                  {{ item.ipType }} · {{ item.countryCode || 'UNKNOWN' }} / {{ item.countryName || '未知' }}
                </p>
                <p class="mt-2 text-xs text-slate-400">
                  {{ item.sourceLabel || importPreviewState.sourceLabel || '手动导入' }}
                </p>
              </div>
            </div>
            <p v-else class="mt-5 text-sm leading-6 text-slate-300">
              这里会展示 Worker 解析后的预览条目，方便先核对文本质量再继续治理。
            </p>
          </article>

          <article class="stat-tile">
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="flex items-center gap-3">
                <Database class="h-5 w-5 text-brand-300" />
                <div>
                  <h3 class="text-sm font-medium text-white">当前 Host DNS 记录</h3>
                  <p class="mt-2 text-sm leading-6 text-slate-300">
                    这里继续接管 `listDnsRecords`、`saveDnsRecords` 和单条 `updateDnsRecord / createDnsRecord`。
                  </p>
                </div>
              </div>

              <div class="flex flex-wrap gap-3">
                <button
                  type="button"
                  class="secondary-btn"
                  :disabled="authRequired || loadingDnsRecords"
                  @click="handleRefreshDnsRecords"
                >
                  <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loadingDnsRecords }" />
                  {{ loadingDnsRecords ? '读取中' : '读取当前 Host' }}
                </button>
                <button
                  type="button"
                  class="secondary-btn"
                  :disabled="authRequired || loadingSaveDnsRecords || !activeDnsHost"
                  @click="handleAddDnsRecordDraft"
                >
                  <Plus class="h-4 w-4" />
                  新增记录
                </button>
                <button
                  type="button"
                  class="secondary-btn"
                  :disabled="authRequired || loadingSaveDnsRecords || !activeDnsHost"
                  @click="handleSaveDnsRecords"
                >
                  <Save class="h-4 w-4" />
                  {{ loadingSaveDnsRecords ? '保存中' : '保存当前 Host' }}
                </button>
              </div>
            </div>

            <div v-if="activeDnsHost" class="mt-5 flex flex-wrap gap-2">
              <span class="inline-flex rounded-full border border-brand-400/25 bg-brand-500/12 px-3 py-1 text-xs text-brand-100">
                Host {{ activeDnsHost }}
              </span>
              <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                Zone {{ dnsRecordsState.zoneName || dnsRecordsState.zoneId || workspace.zoneId || '未返回' }}
              </span>
              <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                当前模式 {{ dnsRecordEditor.mode === 'cname' ? 'CNAME' : 'A / AAAA' }}
              </span>
              <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                可编辑 {{ dnsRecordsState.filteredCount || dnsRecordsState.records.length || 0 }} 条
              </span>
            </div>
            <p v-else class="mt-5 text-sm leading-6 text-slate-300">
              当前工作区还没有返回 Host，上面的按钮会在拿到真实 Host 后继续复用 Worker 会话。
            </p>

            <label class="field-shell mt-5">
              <span class="field-label">记录模式</span>
              <select
                :value="dnsRecordEditor.mode"
                class="field-input"
                :disabled="loadingSaveDnsRecords || loadingUpdateDnsRecord"
                @change="handleChangeDnsRecordMode($event.target.value)"
              >
                <option v-for="option in dnsRecordModeOptions" :key="option.value" :value="option.value">
                  {{ option.label }}
                </option>
              </select>
              <span class="field-hint">
                `saveDnsRecords` 会按当前模式整体对齐当前 Host；单条保存则直接命中 Cloudflare DNS 记录。
              </span>
            </label>

            <article
              v-if="dnsRecordEditor.feedbackText"
              class="mt-5 rounded-2xl border px-4 py-4 text-sm leading-6"
              :class="dnsRecordEditor.feedbackTone === 'error'
                ? 'border-rose-400/25 bg-rose-500/10 text-rose-50'
                : 'border-mint-400/25 bg-mint-400/10 text-mint-50'"
            >
              {{ dnsRecordEditor.feedbackText }}
            </article>

            <div class="mt-5 space-y-3">
              <article
                v-for="(draft, index) in dnsRecordEditor.drafts"
                :key="draft.uid"
                class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-4"
              >
                <div class="flex flex-wrap items-center justify-between gap-3">
                  <div class="flex flex-wrap gap-2">
                    <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                      #{{ index + 1 }}
                    </span>
                    <span
                      v-if="draft.recordId"
                      class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200"
                    >
                      {{ draft.recordId }}
                    </span>
                    <span
                      v-else
                      class="inline-flex rounded-full border border-amber-400/25 bg-amber-500/12 px-3 py-1 text-xs text-amber-100"
                    >
                      新建记录
                    </span>
                  </div>

                  <div class="flex flex-wrap gap-2">
                    <button
                      type="button"
                      class="secondary-btn"
                      :disabled="authRequired || loadingUpdateDnsRecord || !activeDnsHost"
                      @click="handleSaveSingleDnsRecord(draft)"
                    >
                      <Save class="h-4 w-4" />
                      {{ loadingUpdateDnsRecord ? '同步中' : '单条保存' }}
                    </button>
                    <button
                      type="button"
                      class="secondary-btn"
                      :disabled="loadingSaveDnsRecords || loadingUpdateDnsRecord"
                      @click="handleRemoveDnsRecordDraft(draft.uid)"
                    >
                      <Trash2 class="h-4 w-4" />
                      删除草稿
                    </button>
                  </div>
                </div>

                <div class="mt-4 grid gap-4 md:grid-cols-[0.8fr_1.2fr]">
                  <label v-if="dnsRecordEditor.mode === 'a'" class="field-shell">
                    <span class="field-label">类型</span>
                    <select v-model="draft.type" class="field-input" :disabled="loadingSaveDnsRecords || loadingUpdateDnsRecord">
                      <option value="A">A</option>
                      <option value="AAAA">AAAA</option>
                    </select>
                  </label>

                  <div v-else class="rounded-2xl border border-white/8 bg-slate-950/60 px-4 py-3">
                    <p class="text-xs uppercase tracking-[0.16em] text-slate-500">类型</p>
                    <p class="mt-3 text-sm font-medium text-slate-100">CNAME</p>
                  </div>

                  <label class="field-shell">
                    <span class="field-label">内容</span>
                    <input
                      v-model="draft.content"
                      type="text"
                      class="field-input"
                      :placeholder="dnsRecordEditor.mode === 'cname' ? 'target.example.com' : '例如 1.1.1.1 / 2606:4700::1111'"
                      :disabled="loadingSaveDnsRecords || loadingUpdateDnsRecord"
                    />
                  </label>
                </div>
              </article>
            </div>

            <div class="mt-5 grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
              <article class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-4">
                <p class="text-xs uppercase tracking-[0.16em] text-slate-500">同步摘要</p>
                <div v-if="dnsRecordSyncSummaryRows.length" class="mt-4 grid gap-3 sm:grid-cols-2">
                  <div
                    v-for="row in dnsRecordSyncSummaryRows"
                    :key="row[0]"
                    class="rounded-2xl border border-white/8 bg-white/4 px-4 py-3"
                  >
                    <p class="text-xs uppercase tracking-[0.16em] text-slate-500">{{ row[0] }}</p>
                    <p class="mt-3 text-sm font-medium text-slate-100">{{ row[1] }}</p>
                  </div>
                </div>
                <p v-else class="mt-4 text-sm leading-6 text-slate-300">
                  读取到当前 Host 后，这里会显示 Worker 返回的 DNS 对齐摘要。
                </p>
              </article>

              <article class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-4">
                <p class="text-xs uppercase tracking-[0.16em] text-slate-500">CNAME 历史</p>
                <div v-if="dnsRecordHistoryEntries.length" class="mt-4 space-y-3">
                  <div
                    v-for="entry in dnsRecordHistoryEntries"
                    :key="entry.id"
                    class="rounded-2xl border border-white/8 bg-white/4 px-4 py-3"
                  >
                    <p class="break-all text-sm font-medium text-slate-100">{{ entry.content }}</p>
                    <p class="mt-2 text-xs text-slate-400">
                      {{ entry.actor }} / {{ entry.source }} · {{ formatDateTime(entry.savedAt) }}
                    </p>
                    <p v-if="entry.requestHost" class="mt-1 text-xs text-slate-500">
                      requestHost: {{ entry.requestHost }}
                    </p>
                  </div>
                </div>
                <p v-else class="mt-4 text-sm leading-6 text-slate-300">
                  当前没有可展示的 CNAME 历史记录，只有切到 CNAME 并发生保存时才会逐步积累。
                </p>
              </article>
            </div>
          </article>
        </div>

        <article class="stat-tile">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="flex items-center gap-3">
              <Database class="h-5 w-5 text-brand-300" />
              <h3 class="text-sm font-medium text-white">抓取源 Source List</h3>
            </div>
            <div class="flex flex-wrap gap-3">
              <button
                type="button"
                class="secondary-btn"
                :disabled="authRequired || loadingRefreshSources"
                @click="handleRefreshFromSources"
              >
                <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loadingRefreshSources }" />
                刷新抓取
              </button>
              <button
                type="button"
                class="secondary-btn"
                :disabled="authRequired || loadingSaveSources"
                @click="sourceEditor.visible ? handleCloseSourceEditor() : handleOpenSourceEditor()"
              >
                <Save class="h-4 w-4" />
                {{ sourceEditor.visible ? '收起编辑器' : '编辑抓取源' }}
              </button>
            </div>
          </div>
          <div v-if="sourceCards.length" class="mt-5 grid gap-3 xl:grid-cols-2">
            <div
              v-for="source in sourceCards"
              :key="source.id"
              class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-4"
            >
              <div class="flex flex-wrap items-start justify-between gap-3">
                <div class="min-w-0">
                  <div class="flex flex-wrap items-center gap-2">
                    <p class="text-sm font-semibold text-white">{{ source.name }}</p>
                    <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-2.5 py-1 text-xs text-slate-200">
                      {{ source.orderLabel }}
                    </span>
                  </div>
                  <p class="mt-2 break-all font-mono text-xs text-slate-400">{{ source.targetValue }}</p>
                </div>
                <span class="inline-flex rounded-full border px-3 py-1 text-xs font-medium" :class="source.fetchStatusTone">
                  {{ source.fetchStatusLabel }}
                </span>
              </div>
              <div class="mt-4 flex flex-wrap gap-2">
                <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                  {{ source.enabled ? '已启用' : '已停用' }}
                </span>
                <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                  {{ source.sourceType }}
                </span>
                <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                  limit {{ source.ipLimit || 0 }}
                </span>
                <span v-if="source.sourceKind" class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                  {{ source.sourceKind }}
                </span>
              </div>
              <div class="mt-4 grid gap-2 text-xs text-slate-400 sm:grid-cols-2">
                <p>Last Fetch At：{{ formatDateTime(source.lastFetchAt) }}</p>
                <p>Last Fetch Count：{{ source.lastFetchCount }}</p>
              </div>
            </div>
          </div>
          <p v-else class="mt-5 text-sm leading-6 text-slate-300">
            当前还没有 sourceList。前端已经打通读取链路，但后端尚未返回可读抓取源配置。
          </p>
        </article>

        <article v-if="sourceEditor.visible" class="stat-tile">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div class="flex items-center gap-3">
                <Link2 class="h-5 w-5 text-ocean-300" />
                <h3 class="text-sm font-medium text-white">抓取源编辑器</h3>
              </div>
              <p class="mt-3 text-sm leading-6 text-slate-300">
                这里继续沿用旧版 source 语义，支持自定义 URL / 域名源，也支持挂接 Worker 已返回的 built-in / preset 选项。
              </p>
            </div>

            <div class="flex flex-wrap gap-3">
              <button type="button" class="secondary-btn" :disabled="loadingSaveSources" @click="handleAddSourceDraft('custom')">
                <Plus class="h-4 w-4" />
                自定义源
              </button>
              <button
                type="button"
                class="secondary-btn"
                :disabled="loadingSaveSources || !builtInSourceOptions.length"
                @click="handleAddSourceDraft('builtin')"
              >
                <Plus class="h-4 w-4" />
                内置源
              </button>
              <button
                type="button"
                class="secondary-btn"
                :disabled="loadingSaveSources || !presetList.length"
                @click="handleAddSourceDraft('preset')"
              >
                <Plus class="h-4 w-4" />
                预设源
              </button>
              <button
                type="button"
                class="secondary-btn"
                :disabled="loadingSaveSources || !hasSourceDraftChanges"
                @click="handleResetSourceEditor"
              >
                重置
              </button>
              <button
                type="button"
                class="secondary-btn"
                :disabled="authRequired || loadingSaveSources || !hasSourceDraftChanges"
                @click="handleSaveSourceEditor"
              >
                <Save class="h-4 w-4" />
                {{ loadingSaveSources ? '保存中' : '保存抓取源' }}
              </button>
            </div>
          </div>

          <div v-if="sourceEditor.drafts.length" class="mt-5 space-y-4">
            <article
              v-for="(draft, index) in sourceEditor.drafts"
              :key="draft.uid"
              class="rounded-3xl border border-white/8 bg-slate-950/40 p-4"
            >
              <div class="flex flex-wrap items-center justify-between gap-3">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                    #{{ index + 1 }}
                  </span>
                  <span class="inline-flex rounded-full border px-3 py-1 text-xs font-medium" :class="resolveSourceKindTone(draft.sourceKind)">
                    {{ resolveSourceKindLabel(draft.sourceKind) }}
                  </span>
                  <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                    {{ draft.enabled ? '已启用' : '已停用' }}
                  </span>
                </div>

                <div class="flex flex-wrap gap-2">
                  <button type="button" class="secondary-btn" :disabled="index === 0" @click="handleMoveSourceDraft(index, -1)">
                    <ArrowUp class="h-4 w-4" />
                    上移
                  </button>
                  <button
                    type="button"
                    class="secondary-btn"
                    :disabled="index >= sourceEditor.drafts.length - 1"
                    @click="handleMoveSourceDraft(index, 1)"
                  >
                    <ArrowDown class="h-4 w-4" />
                    下移
                  </button>
                  <button type="button" class="secondary-btn" @click="handleRemoveSourceDraft(draft.uid)">
                    <Trash2 class="h-4 w-4" />
                    删除
                  </button>
                </div>
              </div>

              <div class="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <label class="field-shell">
                  <span class="field-label">显示名称</span>
                  <input v-model="draft.name" type="text" class="field-input" placeholder="抓取源名称" />
                </label>

                <label class="field-shell">
                  <span class="field-label">来源类型</span>
                  <select v-model="draft.sourceKind" class="field-input">
                    <option value="custom">custom</option>
                    <option value="builtin">builtin</option>
                    <option value="preset">preset</option>
                  </select>
                </label>

                <label v-if="draft.sourceKind === 'custom'" class="field-shell">
                  <span class="field-label">目标格式</span>
                  <select v-model="draft.sourceType" class="field-input">
                    <option value="url">url</option>
                    <option value="domain">domain</option>
                  </select>
                </label>

                <label v-else-if="draft.sourceKind === 'builtin'" class="field-shell md:col-span-2">
                  <span class="field-label">Built-in Source</span>
                  <select v-model="draft.builtinId" class="field-input">
                    <option value="">请选择</option>
                    <option v-for="item in builtInSourceOptions" :key="item.id" :value="item.id">
                      {{ item.label }}
                    </option>
                  </select>
                </label>

                <label v-else class="field-shell md:col-span-2">
                  <span class="field-label">Preset</span>
                  <select v-model="draft.presetId" class="field-input">
                    <option value="">请选择</option>
                    <option v-for="item in presetList" :key="item.id" :value="item.id">
                      {{ item.label }}
                    </option>
                  </select>
                </label>

                <label class="field-shell">
                  <span class="field-label">IP 数量</span>
                  <input v-model="draft.ipLimit" type="number" min="1" max="1000" class="field-input" />
                </label>

                <label class="field-shell">
                  <span class="field-label">启用状态</span>
                  <span class="mt-3 inline-flex items-center gap-3 text-sm text-slate-200">
                    <input v-model="draft.enabled" type="checkbox" class="h-4 w-4 rounded" />
                    启用该抓取源
                  </span>
                </label>

                <label
                  v-if="draft.sourceKind === 'custom' && draft.sourceType === 'url'"
                  class="field-shell md:col-span-2 xl:col-span-2"
                >
                  <span class="field-label">URL</span>
                  <input v-model="draft.url" type="text" class="field-input" placeholder="https://example.com/ip-list.txt" />
                </label>

                <label
                  v-if="draft.sourceKind === 'custom' && draft.sourceType === 'domain'"
                  class="field-shell md:col-span-2 xl:col-span-2"
                >
                  <span class="field-label">域名</span>
                  <input v-model="draft.domain" type="text" class="field-input" placeholder="example.com" />
                </label>

                <div class="field-shell md:col-span-2 xl:col-span-4">
                  <span class="field-label">解析后的目标</span>
                  <div class="mt-3 rounded-2xl border border-white/8 bg-slate-950/60 px-4 py-3">
                    <p class="text-sm font-medium text-white">
                      {{ resolveSourceOptionLabel(draft.sourceKind === 'builtin' ? builtInSourceOptions : presetList, draft.sourceKind === 'builtin' ? draft.builtinId : draft.presetId) || draft.name || '未命名抓取源' }}
                    </p>
                    <p class="mt-2 break-all font-mono text-xs text-slate-300">
                      {{ resolveSourceDraftTarget(draft) || '当前还没有可提交的目标值' }}
                    </p>
                  </div>
                </div>
              </div>
            </article>
          </div>

          <p v-else class="mt-5 text-sm leading-6 text-slate-300">
            当前还没有抓取源草稿。可以从自定义 URL / 域名开始，也可以直接追加 built-in / preset。
          </p>
        </article>

        <article class="stat-tile">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="flex items-center gap-3">
              <Network class="h-5 w-5 text-mint-300" />
              <h3 class="text-sm font-medium text-white">抓取刷新结果</h3>
            </div>
            <div class="flex flex-wrap gap-2">
              <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
                导入 {{ refreshState.importedCount || 0 }} 条
              </span>
              <span
                class="inline-flex rounded-full border px-3 py-1 text-xs font-medium"
                :class="resolveRefreshCacheStatusTone(refreshState.cacheStatus)"
              >
                {{ resolveRefreshCacheStatusLabel(refreshState.cacheStatus) }}
              </span>
            </div>
          </div>

          <div class="mt-5 grid gap-4 xl:grid-cols-[0.95fr_1.05fr]">
            <div class="space-y-3">
              <div class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
                <p class="text-xs uppercase tracking-[0.16em] text-slate-400">Cached At</p>
                <p class="mt-3 text-sm font-medium text-slate-100">{{ formatDateTime(refreshState.cachedAt) }}</p>
              </div>
              <div class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
                <p class="text-xs uppercase tracking-[0.16em] text-slate-400">Expires At</p>
                <p class="mt-3 text-sm font-medium text-slate-100">{{ formatDateTime(refreshState.expiresAt) }}</p>
              </div>
              <div class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
                <p class="text-xs uppercase tracking-[0.16em] text-slate-400">Background Refresh</p>
                <p class="mt-3 text-sm font-medium text-slate-100">
                  {{ refreshState.backgroundRefreshQueued ? '后台刷新已排队' : '本次没有后台队列' }}
                </p>
              </div>
            </div>

            <div class="space-y-3">
              <div
                v-for="result in sourceResults"
                :key="result.id"
                class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3"
              >
                <div class="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p class="text-sm font-medium text-white">{{ result.name }}</p>
                    <p class="mt-2 text-xs uppercase tracking-[0.16em] text-slate-400">{{ result.sourceType }}</p>
                  </div>
                  <span class="inline-flex rounded-full border px-3 py-1 text-xs font-medium" :class="resolveFetchStatusTone(result.status)">
                    {{ resolveFetchStatusLabel(result.status) }}
                  </span>
                </div>
                <p class="mt-3 text-sm text-slate-300">
                  抓取 {{ result.count }} 条 · {{ formatDateTime(result.lastFetchAt) }}
                </p>
                <p v-if="result.error" class="mt-2 text-sm leading-6 text-rose-200">
                  {{ result.error }}
                </p>
              </div>
              <p v-if="!sourceResults.length" class="text-sm leading-6 text-slate-300">
                还没有手动刷新结果。点击顶部“刷新抓取结果”后，这里会展示每个 source 的抓取状态。
              </p>
            </div>
          </div>

          <div v-if="refreshPreviewItems.length" class="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            <div
              v-for="item in refreshPreviewItems"
              :key="item.id"
              class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3"
            >
              <p class="font-mono text-sm text-slate-100">{{ item.ip }}</p>
              <p class="mt-2 text-xs text-slate-400">
                {{ item.ipType }} · {{ item.countryCode || 'UNKNOWN' }} / {{ item.countryName || '未知' }}
              </p>
              <p class="mt-2 text-xs text-slate-400">
                {{ item.coloCode || '未返回 Colo' }} · {{ resolveProbeStatusLabel(item.probeStatus) }}
              </p>
            </div>
          </div>
        </article>

        <div class="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
          <article class="stat-tile">
            <div class="flex items-center gap-3">
              <Link2 class="h-5 w-5 text-mint-300" />
              <h3 class="text-sm font-medium text-white">Preferred Links</h3>
            </div>
            <div class="mt-5 space-y-4">
              <div>
                <p class="text-xs uppercase tracking-[0.16em] text-slate-400">Preferred Domain Links</p>
                <div v-if="preferredDomainLinks.length" class="mt-3 flex flex-wrap gap-3">
                  <a
                    v-for="link in preferredDomainLinks"
                    :key="`${link.label}-${link.href}`"
                    :href="link.href"
                    target="_blank"
                    rel="noreferrer"
                    class="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/6 px-4 py-2 text-sm text-slate-100 transition hover:border-white/20 hover:bg-white/10"
                  >
                    {{ link.label }}
                    <ArrowUpRight class="h-4 w-4" />
                  </a>
                </div>
                <p v-else class="mt-3 text-sm leading-6 text-slate-300">当前没有推荐的域名侧入口链接。</p>
              </div>

              <div>
                <p class="text-xs uppercase tracking-[0.16em] text-slate-400">Preferred IP Links</p>
                <div v-if="preferredIpLinks.length" class="mt-3 flex flex-wrap gap-3">
                  <a
                    v-for="link in preferredIpLinks"
                    :key="`${link.label}-${link.href}`"
                    :href="link.href"
                    target="_blank"
                    rel="noreferrer"
                    class="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/6 px-4 py-2 text-sm text-slate-100 transition hover:border-white/20 hover:bg-white/10"
                  >
                    {{ link.label }}
                    <ArrowUpRight class="h-4 w-4" />
                  </a>
                </div>
                <p v-else class="mt-3 text-sm leading-6 text-slate-300">当前没有推荐的 IP 侧入口链接。</p>
              </div>
            </div>
          </article>

          <div class="grid gap-4">
            <article class="stat-tile">
              <div class="flex items-center gap-3">
                <Database class="h-5 w-5 text-brand-300" />
                <h3 class="text-sm font-medium text-white">Built-in Source Options</h3>
              </div>
              <div v-if="optionCards.length" class="mt-5 grid gap-3 md:grid-cols-2">
                <div
                  v-for="item in optionCards"
                  :key="item.id"
                  class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3"
                >
                  <p class="text-sm font-medium text-white">{{ item.label }}</p>
                  <p class="mt-2 text-xs uppercase tracking-[0.16em] text-slate-400">{{ item.sourceType }}</p>
                  <p class="mt-3 break-all font-mono text-xs text-slate-300">{{ item.targetValue }}</p>
                </div>
              </div>
              <p v-else class="mt-5 text-sm leading-6 text-slate-300">
                后端当前没有返回 built-in source option 列表。
              </p>
            </article>

            <article class="stat-tile">
              <div class="flex items-center gap-3">
                <Database class="h-5 w-5 text-ocean-300" />
                <h3 class="text-sm font-medium text-white">Preset List</h3>
              </div>
              <div v-if="presetCards.length" class="mt-5 grid gap-3 md:grid-cols-2">
                <div
                  v-for="item in presetCards"
                  :key="item.id"
                  class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3"
                >
                  <p class="text-sm font-medium text-white">{{ item.label }}</p>
                  <p class="mt-2 text-xs uppercase tracking-[0.16em] text-slate-400">{{ item.sourceType }}</p>
                  <p class="mt-3 break-all font-mono text-xs text-slate-300">{{ item.targetValue }}</p>
                </div>
              </div>
              <p v-else class="mt-5 text-sm leading-6 text-slate-300">
                当前没有 preset list，可继续等待 Worker 返回或后续再补充更多只读展示。
              </p>
            </article>
          </div>
        </div>
      </template>
    </div>
  </SectionCard>
</template>
