<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue';
import {
  Activity,
  ArrowDown,
  ArrowUp,
  Copy,
  FileJson,
  GripVertical,
  Pencil,
  Plus,
  RefreshCw,
  Save,
  Search,
  Server,
  ShieldAlert,
  Trash2,
  Upload,
  X
} from 'lucide-vue-next';

import SectionCard from '@/components/SectionCard.vue';

const props = defineProps({
  adminConsole: {
    type: Object,
    default: null
  }
});

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

const ENTRY_MODE_OPTIONS = [
  { value: 'kv_route', label: 'KV Route' },
  { value: 'host_prefix', label: 'Host Prefix' }
];

const TAG_COLOR_OPTIONS = [
  { value: '', label: '默认' },
  { value: 'amber', label: 'Amber' },
  { value: 'emerald', label: 'Emerald' },
  { value: 'sky', label: 'Sky' },
  { value: 'violet', label: 'Violet' },
  { value: 'rose', label: 'Rose' }
];

const PLAYBACK_INFO_MODE_OPTIONS = [
  { value: 'inherit', label: 'inherit' },
  { value: 'passthrough', label: 'passthrough' },
  { value: 'rewrite', label: 'rewrite' }
];

const MEDIA_AUTH_MODE_OPTIONS = [
  { value: 'auto', label: 'auto' },
  { value: 'inherit', label: 'inherit' },
  { value: 'emby', label: 'emby' },
  { value: 'jellyfin', label: 'jellyfin' },
  { value: 'passthrough', label: 'passthrough' }
];

const REAL_CLIENT_IP_MODE_OPTIONS = [
  { value: 'forward', label: 'forward' },
  { value: 'inherit', label: 'inherit' },
  { value: 'strip', label: 'strip' },
  { value: 'disable', label: 'disable' }
];

const ROUTING_DECISION_MODE_OPTIONS = [
  { value: 'inherit', label: 'inherit' },
  { value: 'legacy', label: 'legacy' },
  { value: 'simplified', label: 'simplified' }
];

const MAIN_VIDEO_STREAM_MODE_OPTIONS = [
  { value: 'inherit', label: 'inherit' },
  { value: 'proxy', label: 'proxy' },
  { value: 'direct', label: 'direct' }
];

let editorRequestId = 0;
let lineDraftSequence = 0;

const query = ref('');
const feedback = reactive({
  tone: '',
  text: ''
});
const importer = reactive({
  visible: false,
  payload: ''
});
const copyPanel = reactive({
  visible: false,
  nodeName: '',
  nodeDisplayName: '',
  entries: [],
  copiedKey: ''
});
const form = reactive(createEmptyNodeForm());
const lineDragState = reactive({
  dragDraftId: '',
  dropDraftId: '',
  placement: ''
});
const editor = reactive({
  visible: false,
  mode: 'create',
  originalName: '',
  baseline: '',
  loadingPrefill: false
});
const editorRuntime = reactive({
  detailNode: null,
  actionTone: '',
  actionText: '',
  refreshingDetail: false
});

const nodes = computed(() => (Array.isArray(props.adminConsole?.nodes) ? props.adminConsole.nodes : []));
const authRequired = computed(() => props.adminConsole?.state?.authRequired === true);
const loadingNodes = computed(() => Boolean(props.adminConsole?.state?.loading?.nodes));
const loadingNodeDetail = computed(() => Boolean(props.adminConsole?.state?.loading?.nodeDetail));
const savingNode = computed(() => Boolean(props.adminConsole?.state?.loading?.saveNode));
const importingNodes = computed(() => Boolean(props.adminConsole?.state?.loading?.importNodes));
const nodesHydrated = computed(() => props.adminConsole?.state?.nodesHydrated === true);
const nodesError = computed(() => String(props.adminConsole?.state?.errors?.nodes || '').trim());
const pingError = computed(() => String(props.adminConsole?.state?.errors?.pingNode || '').trim());
const deleteError = computed(() => String(props.adminConsole?.state?.errors?.deleteNode || '').trim());
const nodeDetailError = computed(() => String(props.adminConsole?.state?.errors?.nodeDetail || '').trim());
const saveNodeError = computed(() => String(props.adminConsole?.state?.errors?.saveNode || '').trim());
const importNodesError = computed(() => String(props.adminConsole?.state?.errors?.importNodes || '').trim());
const revision = computed(() => String(props.adminConsole?.nodesRevision || '').trim());
const hostDomain = computed(() => String(props.adminConsole?.hostDomain || '').trim());
const legacyHost = computed(() => String(props.adminConsole?.legacyHost || '').trim());
const multiLinkCopyPanelEnabled = computed(() => {
  const settingsConfig = props.adminConsole?.settingsBootstrap?.config;
  const bootstrapConfig = props.adminConsole?.adminBootstrap?.config;
  return settingsConfig?.multiLinkCopyPanelEnabled === true || bootstrapConfig?.multiLinkCopyPanelEnabled === true;
});

const filteredNodes = computed(() => {
  const keyword = String(query.value || '').trim().toLowerCase();
  if (!keyword) return nodes.value;

  return nodes.value.filter((node) => {
    const activeLine = resolveActiveLine(node);
    const haystack = [
      node?.name,
      node?.displayName,
      node?.tag,
      node?.remark,
      node?.entryMode,
      activeLine?.name,
      activeLine?.target,
      ...(Array.isArray(node?.lines) ? node.lines.flatMap((line) => [line?.name, line?.target]) : [])
    ]
      .map((entry) => String(entry || '').toLowerCase())
      .filter(Boolean)
      .join('\n');

    return haystack.includes(keyword);
  });
});

const summaryTiles = computed(() => {
  const totalNodes = nodes.value.length;
  const totalLines = nodes.value.reduce((count, node) => count + resolveLines(node).length, 0);
  const probedNodes = nodes.value.filter((node) => Number.isFinite(Number(resolveActiveLine(node)?.latencyMs))).length;
  const taggedNodes = nodes.value.filter((node) => String(node?.tag || '').trim()).length;

  return [
    {
      title: '节点总数',
      value: String(totalNodes),
      note: `${filteredNodes.value.length} 个命中当前筛选`
    },
    {
      title: '线路总数',
      value: String(totalLines),
      note: '按节点 summary 中的线路数累计'
    },
    {
      title: '已探测节点',
      value: String(probedNodes),
      note: '当前线路带 latency 的节点数'
    },
    {
      title: '标签节点',
      value: String(taggedNodes),
      note: compactRevision(revision.value)
    }
  ];
});

const editorTitle = computed(() => (editor.mode === 'edit' ? '编辑节点' : '新增节点'));
const editorDescription = computed(() => (
  editor.mode === 'edit'
    ? '这一版已经对齐基础字段、自定义 headers、线路编辑和路由策略，保存仍然走 Worker 的原生 `save` 动作。'
    : '这一版支持直接在独立前端创建节点，并复用 Worker 的既有校验与保存语义。'
));
const hasEditorChanges = computed(() => serializeNodeForm(form) !== editor.baseline);
const hasImportPayload = computed(() => String(importer.payload || '').trim().length > 0);
const hostPrefixHint = computed(() => {
  if (form.entryMode !== 'host_prefix') return '';
  if (!hostDomain.value) return '当前 Worker 还没有返回 hostDomain，host prefix 节点保存后仍由后端做最终校验。';
  return `host prefix 节点会按 ${hostDomain.value} 下的子域同步，secret 会被后端自动忽略。`;
});
const importPreview = computed(() => previewImportPayload(importer.payload));
const normalizedHeaderCount = computed(() => Object.keys(normalizeHeaderDrafts(form.headers)).length);
const editorNodeName = computed(() => normalizeNodeRouteName(editor.originalName || form.name));
const editorCanOperateSavedNode = computed(() => editor.mode === 'edit' && !!editorNodeName.value);
const editorSavedNode = computed(() => (isPlainObject(editorRuntime.detailNode) ? editorRuntime.detailNode : null));
const editorSavedActiveLine = computed(() => resolveActiveLine(editorSavedNode.value));
const editorCompatibilityTips = computed(() => resolveNodeCompatibilityTips(editorSavedNode.value || form));
const editorSyncMeta = computed(() => resolveNodeSyncMeta(editorSavedNode.value));
const editorHealthMeta = computed(() => resolveNodeHealthMeta(editorSavedNode.value));

watch([nodesError, pingError, deleteError, nodeDetailError, saveNodeError, importNodesError], (errors) => {
  const nextError = errors.find((item) => item);
  if (nextError) {
    feedback.tone = 'error';
    feedback.text = nextError;
    if (editor.visible) {
      editorRuntime.actionTone = 'error';
      editorRuntime.actionText = nextError;
    }
    return;
  }

  if (feedback.tone === 'error') {
    feedback.tone = '';
    feedback.text = '';
  }

  if (editorRuntime.actionTone === 'error') {
    editorRuntime.actionTone = '';
    editorRuntime.actionText = '';
  }
});

watch(() => form.entryMode, (nextValue) => {
  if (String(nextValue || '').trim() === 'host_prefix') {
    form.secret = '';
  }
});

onMounted(() => {
  if (!props.adminConsole) return;
  if (loadingNodes.value) return;
  if (!nodesHydrated.value) {
    void props.adminConsole.hydrateNodes();
  }
});

async function handleRefresh() {
  feedback.tone = '';
  feedback.text = '';
  await props.adminConsole?.hydrateNodes();
}

function handleOpenImport() {
  feedback.tone = '';
  feedback.text = '';
  importer.visible = true;
}

function handleCloseImport() {
  importer.visible = false;
}

function handleCloseCopyPanel() {
  copyPanel.visible = false;
  copyPanel.nodeName = '';
  copyPanel.nodeDisplayName = '';
  copyPanel.entries = [];
  copyPanel.copiedKey = '';
}

function handleResetImport() {
  importer.payload = '';
}

function handleOpenCreate() {
  feedback.tone = '';
  feedback.text = '';
  clearLineDragState();
  hydrateNodeForm(createEmptyNodeForm());
  editorRuntime.detailNode = null;
  editorRuntime.actionTone = '';
  editorRuntime.actionText = '';
  editorRuntime.refreshingDetail = false;
  editor.visible = true;
  editor.mode = 'create';
  editor.originalName = '';
  editor.loadingPrefill = false;
  editor.baseline = serializeNodeForm(form);
}

async function handleOpenEdit(node) {
  const nodeName = String(node?.name || '').trim();
  if (!nodeName) return;

  feedback.tone = '';
  feedback.text = '';

  const requestId = Date.now();
  editorRequestId = requestId;
  editor.visible = true;
  editor.mode = 'edit';
  editor.originalName = nodeName;
  editor.loadingPrefill = true;
  editorRuntime.detailNode = cloneNodeRuntimeState(node);
  editorRuntime.actionTone = '';
  editorRuntime.actionText = '';
  editorRuntime.refreshingDetail = false;
  hydrateNodeForm(buildNodeFormFromNode(node));
  editor.baseline = serializeNodeForm(form);

  const result = await props.adminConsole?.getNode(nodeName);
  if (editorRequestId !== requestId) return;

  if (result?.node) {
    editorRuntime.detailNode = cloneNodeRuntimeState(result.node);
    hydrateNodeForm(buildNodeFormFromNode(result.node));
    editor.originalName = String(result.node.name || nodeName).trim();
    editor.baseline = serializeNodeForm(form);
  }

  editor.loadingPrefill = false;
}

function handleCloseEditor() {
  editorRequestId = 0;
  clearLineDragState();
  editorRuntime.detailNode = null;
  editorRuntime.actionTone = '';
  editorRuntime.actionText = '';
  editorRuntime.refreshingDetail = false;
  editor.visible = false;
  editor.mode = 'create';
  editor.originalName = '';
  editor.baseline = '';
  editor.loadingPrefill = false;
  hydrateNodeForm(createEmptyNodeForm());
}

function setEditorAction(tone = '', text = '') {
  editorRuntime.actionTone = String(tone || '').trim();
  editorRuntime.actionText = String(text || '').trim();
}

async function handleRefreshEditorDetail() {
  if (!props.adminConsole || !editorCanOperateSavedNode.value || editor.loadingPrefill || editorRuntime.refreshingDetail) return;

  editorRuntime.refreshingDetail = true;
  setEditorAction('', '');

  const result = await props.adminConsole.getNode(editorNodeName.value);
  editorRuntime.refreshingDetail = false;
  if (!result?.node) return;

  editorRuntime.detailNode = cloneNodeRuntimeState(result.node);
  if (!hasEditorChanges.value) {
    hydrateNodeForm(buildNodeFormFromNode(result.node));
    editor.baseline = serializeNodeForm(form);
    setEditorAction('success', `已重新读取 Worker 中 ${resolveDisplayName(result.node)} 的最新详情。`);
    return;
  }

  mergeLineDiagnosticsIntoDrafts(result.node);
  setEditorAction('success', `已刷新 Worker 中 ${resolveDisplayName(result.node)} 的诊断信息，当前草稿修改已保留。`);
}

async function handlePingEditorSavedNode(line = null, options = {}) {
  if (!editorCanOperateSavedNode.value) return;
  const lineId = String(options.lineId || resolveSavedLineId(line)).trim();
  const probeLine = lineId ? resolveLineById(editorSavedNode.value, lineId) : line;
  const result = await handlePing({
    name: editorNodeName.value,
    displayName: editorSavedNode.value?.displayName || form.displayName || editorNodeName.value
  }, probeLine, {
    lineId,
    successMessageTarget: 'editor'
  });

  if (!result?.node) return;

  editorRuntime.detailNode = mergeNodeRuntimeState(editorSavedNode.value, result.node);
  mergeLineDiagnosticsIntoDrafts(result.node);
}

function handleAddHeader() {
  form.headers.push(createEmptyHeaderDraft());
}

function handleRemoveHeader(index) {
  form.headers.splice(index, 1);
}

function handleAddLine() {
  clearLineDragState();
  form.lines.push(createEmptyLineDraft(form.lines.length));
  ensureActiveLineId();
}

function handleRemoveLine(index) {
  clearLineDragState();
  if (form.lines.length <= 1) {
    form.lines.splice(0, 1, createEmptyLineDraft(0));
    ensureActiveLineId();
    return;
  }

  form.lines.splice(index, 1);
  ensureActiveLineId();
}

function handleMoveLine(index, direction = 0) {
  clearLineDragState();
  const currentIndex = Number(index);
  const offset = Number(direction);
  const targetIndex = currentIndex + offset;
  if (!Number.isInteger(currentIndex) || !Number.isInteger(offset)) return;
  if (currentIndex < 0 || currentIndex >= form.lines.length) return;
  if (targetIndex < 0 || targetIndex >= form.lines.length) return;

  const [movedLine] = form.lines.splice(currentIndex, 1);
  form.lines.splice(targetIndex, 0, movedLine);
  ensureActiveLineId();
}

function clearLineDragState() {
  lineDragState.dragDraftId = '';
  lineDragState.dropDraftId = '';
  lineDragState.placement = '';
}

function handleLineDragStart(draftId = '', event = null) {
  if (savingNode.value || importingNodes.value || form.lines.length <= 1) {
    event?.preventDefault?.();
    return;
  }

  const normalizedDraftId = String(draftId || '').trim();
  if (!normalizedDraftId) {
    event?.preventDefault?.();
    return;
  }

  lineDragState.dragDraftId = normalizedDraftId;
  lineDragState.dropDraftId = '';
  lineDragState.placement = '';

  if (event?.dataTransfer) {
    event.dataTransfer.effectAllowed = 'move';
    event.dataTransfer.dropEffect = 'move';
    try {
      event.dataTransfer.setData('text/plain', normalizedDraftId);
    } catch {
      // 浏览器可能禁止自定义 payload，这里只保留拖拽语义。
    }
  }
}

function handleLineDragOver(draftId = '', event = null) {
  const normalizedDraftId = String(draftId || '').trim();
  if (!lineDragState.dragDraftId || !normalizedDraftId || lineDragState.dragDraftId === normalizedDraftId) return;

  event?.preventDefault?.();
  if (event?.dataTransfer) {
    event.dataTransfer.dropEffect = 'move';
  }

  const placement = resolveLineDropPlacement(event?.currentTarget, event?.clientY);
  lineDragState.dropDraftId = normalizedDraftId;
  lineDragState.placement = placement;
}

function handleLineDrop(draftId = '', event = null) {
  const normalizedDraftId = String(draftId || '').trim();
  if (!lineDragState.dragDraftId || !normalizedDraftId) {
    clearLineDragState();
    return;
  }

  event?.preventDefault?.();
  if (lineDragState.dragDraftId === normalizedDraftId) {
    clearLineDragState();
    return;
  }

  const placement = lineDragState.dropDraftId === normalizedDraftId
    ? lineDragState.placement
    : resolveLineDropPlacement(event?.currentTarget, event?.clientY);

  moveLineDraftTo(lineDragState.dragDraftId, normalizedDraftId, placement);
  clearLineDragState();
}

function handleLineDragEnd() {
  clearLineDragState();
}

function moveLineDraftTo(dragDraftId = '', targetDraftId = '', placement = 'before') {
  const sourceIndex = form.lines.findIndex((line, index) => resolveLineDraftKey(line, index) === dragDraftId);
  const targetIndex = form.lines.findIndex((line, index) => resolveLineDraftKey(line, index) === targetDraftId);
  if (sourceIndex < 0 || targetIndex < 0 || sourceIndex === targetIndex) return;

  const [movedLine] = form.lines.splice(sourceIndex, 1);
  const normalizedPlacement = placement === 'after' ? 'after' : 'before';
  const adjustedTargetIndex = sourceIndex < targetIndex ? targetIndex - 1 : targetIndex;
  const insertIndex = normalizedPlacement === 'after' ? adjustedTargetIndex + 1 : adjustedTargetIndex;

  form.lines.splice(insertIndex, 0, movedLine);
  ensureActiveLineId();
}

function resolveLineDropPlacement(targetElement = null, clientY = 0) {
  if (!targetElement || !Number.isFinite(Number(clientY)) || typeof targetElement.getBoundingClientRect !== 'function') {
    return 'before';
  }

  const rect = targetElement.getBoundingClientRect();
  return Number(clientY) >= rect.top + rect.height / 2 ? 'after' : 'before';
}

function handleSetActiveLine(lineId = '') {
  form.activeLineId = String(lineId || '').trim();
  ensureActiveLineId();
}

function canMoveLineUp(index) {
  return Number(index) > 0;
}

function canMoveLineDown(index) {
  return Number(index) < form.lines.length - 1;
}

async function handleSaveNode() {
  if (!props.adminConsole || savingNode.value || importingNodes.value) return;

  const payload = buildNodePayload(form, editor);
  if (!payload.ok) {
    feedback.tone = 'error';
    feedback.text = payload.message;
    return;
  }

  feedback.tone = '';
  feedback.text = '';

  const result = await props.adminConsole.saveNode(payload.data, {
    source: 'frontend-vue'
  });
  if (!result) return;

  const savedNode = result.node || null;
  feedback.tone = 'success';
  feedback.text = savedNode
    ? `节点 ${resolveDisplayName(savedNode)} 已保存，时间 ${formatDateTime(result.savedAt)}。`
    : `节点配置已保存，时间 ${formatDateTime(result.savedAt)}。`;

  handleCloseEditor();
}

async function handleImportNodes() {
  if (!props.adminConsole || importingNodes.value || savingNode.value) return;

  const parsed = parseImportPayload(importer.payload);
  if (!parsed.ok) {
    feedback.tone = 'error';
    feedback.text = parsed.message;
    return;
  }

  feedback.tone = '';
  feedback.text = '';

  const result = await props.adminConsole.importNodes(parsed.nodes);
  if (!result) return;

  const importedNodes = Array.isArray(result.importedNodes) && result.importedNodes.length
    ? result.importedNodes
    : parsed.nodes;
  const importedNames = importedNodes
    .slice(0, 3)
    .map((node) => resolveDisplayName(node))
    .filter(Boolean)
    .join('、');

  feedback.tone = 'success';
  feedback.text = importedNames
    ? `已导入 ${importedNodes.length} 个节点：${importedNames}${importedNodes.length > 3 ? ' 等' : ''}。`
    : `已导入 ${importedNodes.length} 个节点。`;

  handleResetImport();
  handleCloseImport();
}

async function handlePing(node, line = null, options = {}) {
  const nodeName = String(node?.name || '').trim();
  if (!nodeName) return;
  const lineId = String(options.lineId || line?.id || '').trim();
  const targetLine = lineId ? (line || resolveLineById(node, lineId)) : null;

  feedback.tone = '';
  feedback.text = '';

  const result = await props.adminConsole?.pingNode({
    name: nodeName,
    ...(lineId ? { lineId } : {})
  });
  if (!result) return;

  const activeLine = resolveActiveLine(result.node);
  const matchedLine = lineId
    ? resolveLineById(result.node, lineId) || targetLine || result.line
    : activeLine;
  const displayName = resolveDisplayName(result.node || node);
  const successText = matchedLine
    ? `节点 ${displayName} 的线路 ${resolveLineLabel(matchedLine)} 探测完成，延迟 ${formatLatency(matchedLine.latencyMs)}。`
    : activeLine
      ? `节点 ${displayName} 探测完成，当前线路 ${resolveLineLabel(activeLine)}，延迟 ${formatLatency(activeLine.latencyMs)}。`
      : `节点 ${displayName} 探测完成。`;

  feedback.tone = 'success';
  feedback.text = successText;

  if (
    editor.visible
    && editorCanOperateSavedNode.value
    && normalizeNodeRouteName(editorNodeName.value) === normalizeNodeRouteName(nodeName)
  ) {
    editorRuntime.detailNode = mergeNodeRuntimeState(editorSavedNode.value, result.node);
    mergeLineDiagnosticsIntoDrafts(result.node);
    if (options.successMessageTarget === 'editor') {
      setEditorAction('success', successText);
    }
  }

  return result;
}

async function handleDelete(node) {
  const nodeName = String(node?.name || '').trim();
  if (!nodeName) return;

  const confirmed = window.confirm(`确认删除节点 ${resolveDisplayName(node)}（${nodeName}）吗？`);
  if (!confirmed) return;

  feedback.tone = '';
  feedback.text = '';

  const result = await props.adminConsole?.deleteNode(nodeName);
  if (!result) return;

  feedback.tone = 'success';
  feedback.text = `节点 ${resolveDisplayName(node)} 已从 Worker 配置中删除。`;

  if (copyPanel.visible && normalizeNodeRouteName(copyPanel.nodeName) === normalizeNodeRouteName(nodeName)) {
    handleCloseCopyPanel();
  }

  if (editor.visible && editor.mode === 'edit' && normalizeNodeRouteName(editor.originalName) === normalizeNodeRouteName(nodeName)) {
    handleCloseEditor();
  }
}

async function handleCopy(node) {
  if (multiLinkCopyPanelEnabled.value) {
    const entries = buildNodeCopyEntries(node);
    if (!entries.length) {
      feedback.tone = 'error';
      feedback.text = `节点 ${resolveDisplayName(node)} 当前没有可复制的链接。`;
      return;
    }

    copyPanel.visible = true;
    copyPanel.nodeName = String(node?.name || '').trim();
    copyPanel.nodeDisplayName = resolveDisplayName(node);
    copyPanel.entries = entries;
    copyPanel.copiedKey = '';
    feedback.tone = '';
    feedback.text = '';
    return;
  }

  const activeLine = resolveActiveLine(node);
  const target = String(activeLine?.target || '').trim();
  if (!target) {
    feedback.tone = 'error';
    feedback.text = `节点 ${resolveDisplayName(node)} 当前没有可复制的目标地址。`;
    return;
  }

  try {
    await copyText(target);
    feedback.tone = 'success';
    feedback.text = `已复制 ${resolveDisplayName(node)} 的当前线路地址。`;
  } catch (error) {
    feedback.tone = 'error';
    feedback.text = String(error?.message || '复制失败，请检查浏览器剪贴板权限。').trim();
  }
}

async function handleCopyPanelEntry(entry) {
  try {
    await copyText(entry?.href || '');
    copyPanel.copiedKey = String(entry?.id || '').trim();
    feedback.tone = 'success';
    feedback.text = `已复制 ${copyPanel.nodeDisplayName || '当前节点'} 的 ${entry?.label || '链接'}。`;
  } catch (error) {
    feedback.tone = 'error';
    feedback.text = String(error?.message || '复制失败，请检查浏览器剪贴板权限。').trim();
  }
}

async function handleCopyAllPanelLinks() {
  const content = copyPanel.entries
    .map((entry) => String(entry?.href || '').trim())
    .filter(Boolean)
    .join('\n');

  try {
    await copyText(content);
    copyPanel.copiedKey = '__all__';
    feedback.tone = 'success';
    feedback.text = `已复制 ${copyPanel.nodeDisplayName || '当前节点'} 的全部链接。`;
  } catch (error) {
    feedback.tone = 'error';
    feedback.text = String(error?.message || '复制失败，请检查浏览器剪贴板权限。').trim();
  }
}

function hydrateNodeForm(nextState) {
  clearLineDragState();
  form.name = String(nextState?.name || '').trim();
  form.displayName = String(nextState?.displayName || '').trim();
  form.entryMode = normalizeEntryMode(nextState?.entryMode);
  form.secret = String(nextState?.secret || '').trim();
  form.tag = String(nextState?.tag || '').trim();
  form.tagColor = normalizeTagColor(nextState?.tagColor);
  form.remark = String(nextState?.remark || '').trim();
  form.playbackInfoMode = normalizePlaybackInfoMode(nextState?.playbackInfoMode);
  form.mediaAuthMode = normalizeMediaAuthMode(nextState?.mediaAuthMode);
  form.realClientIpMode = normalizeRealClientIpMode(nextState?.realClientIpMode);
  form.routingDecisionMode = normalizeRoutingDecisionMode(nextState?.routingDecisionMode);
  form.mainVideoStreamMode = normalizeMainVideoStreamMode(nextState?.mainVideoStreamMode);
  form.hedgeProbePath = String(nextState?.hedgeProbePath || '').trim();
  const nextHeaders = buildHeaderDrafts(nextState?.headers);
  form.headers.splice(0, form.headers.length, ...nextHeaders);

  const nextLines = Array.isArray(nextState?.lines) && nextState.lines.length
    ? nextState.lines.map((line, index) => createEmptyLineDraft(index, line))
    : [createEmptyLineDraft(0)];
  form.lines.splice(0, form.lines.length, ...nextLines);
  form.activeLineId = String(nextState?.activeLineId || '').trim();
  ensureActiveLineId();
}

function ensureActiveLineId() {
  const normalizedLines = form.lines
    .map((line, index) => ({
      ...line,
      id: normalizeLineIdValue(line?.id, index)
    }))
    .filter((line) => String(line?.target || '').trim() || String(line?.id || '').trim());

  const currentActiveLineId = String(form.activeLineId || '').trim();
  if (currentActiveLineId && normalizedLines.some((line) => String(line.id || '').trim() === currentActiveLineId)) {
    return;
  }

  const fallbackLine = normalizedLines[0];
  form.activeLineId = fallbackLine ? String(fallbackLine.id || '').trim() : '';
}

function createEmptyNodeForm() {
  return {
    name: '',
    displayName: '',
    entryMode: 'kv_route',
    secret: '',
    tag: '',
    tagColor: '',
    remark: '',
    playbackInfoMode: 'inherit',
    mediaAuthMode: 'auto',
    realClientIpMode: 'forward',
    routingDecisionMode: 'inherit',
    mainVideoStreamMode: 'inherit',
    hedgeProbePath: '',
    headers: [],
    lines: [createEmptyLineDraft(0)],
    activeLineId: 'line-1'
  };
}

function createLineDraftUid() {
  lineDraftSequence += 1;
  return `line-draft-${lineDraftSequence}`;
}

function createEmptyHeaderDraft(source = {}) {
  return {
    key: String(source?.key || '').trim(),
    value: String(source?.value ?? '')
  };
}

function buildHeaderDrafts(headersLike = {}) {
  if (!isPlainObject(headersLike)) return [];
  return Object.entries(headersLike).map(([key, value]) => createEmptyHeaderDraft({ key, value }));
}

function normalizeHeaderDrafts(headers = []) {
  const normalized = {};
  (Array.isArray(headers) ? headers : []).forEach((header) => {
    const key = String(header?.key || '').trim();
    if (!key) return;
    normalized[key] = String(header?.value ?? '');
  });
  return normalized;
}

function createEmptyLineDraft(index = 0, source = {}) {
  return {
    draftId: String(source?.draftId || createLineDraftUid()).trim() || createLineDraftUid(),
    id: String(source?.id || `line-${Number(index) + 1}`).trim() || `line-${Number(index) + 1}`,
    savedId: String(source?.savedId || source?.id || '').trim(),
    name: String(source?.name || `线路${Number(index) + 1}`).trim() || `线路${Number(index) + 1}`,
    target: String(source?.target || '').trim(),
    latencyMs: normalizeLatencyNumber(source?.latencyMs),
    latencyUpdatedAt: String(source?.latencyUpdatedAt || '').trim(),
    probeStatus: String(source?.probeStatus || source?.status || source?.healthStatus || source?.healthState || '').trim(),
    remark: String(source?.remark || '').trim()
  };
}

function resolveLineDraftKey(line = {}, index = 0) {
  return String(line?.draftId || normalizeLineIdValue(line?.id, index)).trim() || `line-draft-fallback-${Number(index) + 1}`;
}

function isDraggingLine(line = {}, index = 0) {
  return resolveLineDraftKey(line, index) === String(lineDragState.dragDraftId || '').trim();
}

function resolveLineDropHint(line = {}, index = 0) {
  const draftId = resolveLineDraftKey(line, index);
  if (!draftId || draftId !== String(lineDragState.dropDraftId || '').trim()) return null;
  if (!lineDragState.dragDraftId || lineDragState.dragDraftId === draftId) return null;
  return {
    placement: lineDragState.placement === 'after' ? 'after' : 'before',
    text: lineDragState.placement === 'after' ? '释放后放到这条线路后面' : '释放后插入到这条线路前面'
  };
}

function buildNodeFormFromNode(node = {}) {
  return {
    name: String(node?.name || '').trim(),
    displayName: String(node?.displayName || '').trim(),
    entryMode: normalizeEntryMode(node?.entryMode),
    secret: String(node?.secret || '').trim(),
    tag: String(node?.tag || '').trim(),
    tagColor: normalizeTagColor(node?.tagColor),
    remark: String(node?.remark || '').trim(),
    playbackInfoMode: normalizePlaybackInfoMode(node?.playbackInfoMode),
    mediaAuthMode: normalizeMediaAuthMode(node?.mediaAuthMode),
    realClientIpMode: normalizeRealClientIpMode(node?.realClientIpMode),
    routingDecisionMode: normalizeRoutingDecisionMode(node?.routingDecisionMode),
    mainVideoStreamMode: normalizeMainVideoStreamMode(node?.mainVideoStreamMode),
    hedgeProbePath: String(node?.hedgeProbePath || '').trim(),
    headers: buildHeaderDrafts(node?.headers),
    lines: resolveLines(node).length
      ? resolveLines(node).map((line, index) => createEmptyLineDraft(index, line))
      : [createEmptyLineDraft(0)],
    activeLineId: String(node?.activeLineId || '').trim()
  };
}

function cloneNodeRuntimeState(node = {}) {
  if (!isPlainObject(node)) return null;
  return {
    ...node,
    lines: resolveLines(node).map((line) => ({ ...line }))
  };
}

function mergeNodeRuntimeState(baseNode = {}, patchNode = {}) {
  const base = isPlainObject(baseNode) ? baseNode : {};
  const patch = isPlainObject(patchNode) ? patchNode : {};
  const mergedLines = mergeLineCollections(resolveLines(base), resolveLines(patch));
  return {
    ...base,
    ...patch,
    lines: mergedLines.length ? mergedLines : resolveLines(patch)
  };
}

function mergeLineCollections(baseLines = [], patchLines = []) {
  const base = Array.isArray(baseLines) ? baseLines : [];
  const patch = Array.isArray(patchLines) ? patchLines : [];
  if (!base.length) return patch.map((line) => ({ ...line }));

  const patchById = new Map();
  patch.forEach((line, index) => {
    const lineId = String(line?.id || '').trim() || `line-patch-${index + 1}`;
    patchById.set(lineId, line);
  });

  const merged = base.map((line, index) => {
    const lineId = String(line?.id || '').trim() || `line-base-${index + 1}`;
    const patchLine = patchById.get(lineId);
    if (!patchLine) return { ...line };
    patchById.delete(lineId);
    return {
      ...line,
      ...patchLine
    };
  });

  patchById.forEach((line) => {
    merged.push({ ...line });
  });

  return merged;
}

function mergeLineDiagnosticsIntoDrafts(node = {}) {
  const runtimeById = new Map();
  resolveLines(node).forEach((line) => {
    const lineId = String(line?.id || '').trim();
    if (!lineId) return;
    runtimeById.set(lineId, line);
  });

  form.lines.splice(0, form.lines.length, ...form.lines.map((line, index) => {
    const savedId = resolveSavedLineId(line, index);
    const runtimeLine = savedId ? runtimeById.get(savedId) : null;
    if (!runtimeLine) return line;

    return {
      ...line,
      savedId,
      latencyMs: normalizeLatencyNumber(runtimeLine?.latencyMs),
      latencyUpdatedAt: String(runtimeLine?.latencyUpdatedAt || '').trim(),
      probeStatus: String(runtimeLine?.probeStatus || runtimeLine?.status || runtimeLine?.healthStatus || runtimeLine?.healthState || '').trim(),
      remark: String(runtimeLine?.remark || line?.remark || '').trim()
    };
  }));
}

function buildNodePayload(currentForm, currentEditor) {
  const name = normalizeNodeRouteName(currentForm?.name);
  if (!name) {
    return {
      ok: false,
      message: '节点路径不能为空。'
    };
  }

  const normalizedLines = normalizeLineDrafts(currentForm?.lines);
  if (!normalizedLines.length) {
    return {
      ok: false,
      message: '至少需要一条有效线路，目标地址必须是 http/https URL。'
    };
  }

  const activeLineId = normalizedLines.some((line) => line.id === String(currentForm?.activeLineId || '').trim())
    ? String(currentForm?.activeLineId || '').trim()
    : normalizedLines[0].id;

  return {
    ok: true,
    data: {
      ...(currentEditor.mode === 'edit' && currentEditor.originalName
        ? { originalName: normalizeNodeRouteName(currentEditor.originalName) }
        : {}),
      name,
      displayName: String(currentForm?.displayName || '').trim(),
      entryMode: normalizeEntryMode(currentForm?.entryMode),
      secret: normalizeEntryMode(currentForm?.entryMode) === 'host_prefix'
        ? ''
        : String(currentForm?.secret || '').trim(),
      tag: String(currentForm?.tag || '').trim(),
      tagColor: normalizeTagColor(currentForm?.tagColor),
      remark: String(currentForm?.remark || '').trim(),
      playbackInfoMode: normalizePlaybackInfoMode(currentForm?.playbackInfoMode),
      mediaAuthMode: normalizeMediaAuthMode(currentForm?.mediaAuthMode),
      realClientIpMode: normalizeRealClientIpMode(currentForm?.realClientIpMode),
      routingDecisionMode: normalizeRoutingDecisionMode(currentForm?.routingDecisionMode),
      mainVideoStreamMode: normalizeMainVideoStreamMode(currentForm?.mainVideoStreamMode),
      hedgeProbePath: String(currentForm?.hedgeProbePath || '').trim(),
      headers: normalizeHeaderDrafts(currentForm?.headers),
      lines: normalizedLines,
      activeLineId
    }
  };
}

function normalizeLineDrafts(lines = []) {
  const usedIds = new Set();
  const normalizedLines = [];

  (Array.isArray(lines) ? lines : []).forEach((line, index) => {
    const target = String(line?.target || '').trim();
    if (!target) return;

    const baseId = normalizeLineIdValue(line?.id, index);
    let nextId = baseId;
    let suffix = 2;
    while (usedIds.has(nextId)) {
      nextId = `${baseId}-${suffix}`;
      suffix += 1;
    }
    usedIds.add(nextId);

    normalizedLines.push({
      id: nextId,
      name: String(line?.name || '').trim() || `线路${Number(index) + 1}`,
      target
    });
  });

  return normalizedLines;
}

function serializeNodeForm(value = {}) {
  return JSON.stringify({
    name: normalizeNodeRouteName(value?.name),
    displayName: String(value?.displayName || '').trim(),
    entryMode: normalizeEntryMode(value?.entryMode),
    secret: normalizeEntryMode(value?.entryMode) === 'host_prefix' ? '' : String(value?.secret || '').trim(),
    tag: String(value?.tag || '').trim(),
    tagColor: normalizeTagColor(value?.tagColor),
    remark: String(value?.remark || '').trim(),
    playbackInfoMode: normalizePlaybackInfoMode(value?.playbackInfoMode),
    mediaAuthMode: normalizeMediaAuthMode(value?.mediaAuthMode),
    realClientIpMode: normalizeRealClientIpMode(value?.realClientIpMode),
    routingDecisionMode: normalizeRoutingDecisionMode(value?.routingDecisionMode),
    mainVideoStreamMode: normalizeMainVideoStreamMode(value?.mainVideoStreamMode),
    hedgeProbePath: String(value?.hedgeProbePath || '').trim(),
    headers: normalizeHeaderDrafts(value?.headers),
    activeLineId: String(value?.activeLineId || '').trim(),
    lines: normalizeLineDrafts(value?.lines)
  });
}

function parseImportPayload(rawText = '') {
  const text = String(rawText || '').trim();
  if (!text) {
    return {
      ok: false,
      message: '请先粘贴节点 JSON。'
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    return {
      ok: false,
      message: `导入内容不是合法 JSON：${String(error?.message || '解析失败').trim()}`
    };
  }

  let nodes = [];
  if (Array.isArray(parsed)) {
    nodes = parsed;
  } else if (isPlainObject(parsed) && Array.isArray(parsed.nodes)) {
    nodes = parsed.nodes;
  } else if (
    isPlainObject(parsed)
    && (
      parsed.name !== undefined
      || parsed.displayName !== undefined
      || parsed.lines !== undefined
      || parsed.target !== undefined
      || parsed.entryMode !== undefined
    )
  ) {
    nodes = [parsed];
  } else {
    return {
      ok: false,
      message: '请提供节点数组，或形如 `{ "nodes": [...] }` 的 JSON。'
    };
  }

  const normalizedNodes = nodes.filter((node) => isPlainObject(node));
  if (!normalizedNodes.length) {
    return {
      ok: false,
      message: '没有识别到可导入的节点对象。'
    };
  }

  return {
    ok: true,
    nodes: normalizedNodes
  };
}

function previewImportPayload(rawText = '') {
  const text = String(rawText || '').trim();
  if (!text) {
    return {
      tone: 'idle',
      title: '等待粘贴节点 JSON',
      description: '支持节点数组，或 `{ "nodes": [...] }` 结构；完整节点对象会继续交给 Worker 做 normalize / merge。'
    };
  }

  const parsed = parseImportPayload(rawText);
  if (!parsed.ok) {
    return {
      tone: 'error',
      title: '导入预检失败',
      description: parsed.message
    };
  }

  const sampleNames = parsed.nodes
    .slice(0, 3)
    .map((node) => resolveDisplayName(node))
    .filter(Boolean);

  return {
    tone: 'success',
    title: `已识别 ${parsed.nodes.length} 个节点`,
    description: sampleNames.length
      ? `示例节点：${sampleNames.join('、')}${parsed.nodes.length > sampleNames.length ? ' 等' : ''}`
      : '已识别到可导入的节点对象。'
  };
}

function normalizeNodeRouteName(value = '') {
  return String(value || '').trim().toLowerCase();
}

function normalizeLineIdValue(value = '', index = 0) {
  const normalized = String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return normalized || `line-${Number(index) + 1}`;
}

function normalizeEntryMode(value = '') {
  return String(value || '').trim().toLowerCase() === 'host_prefix' ? 'host_prefix' : 'kv_route';
}

function normalizeTagColor(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  return TAG_COLOR_OPTIONS.some((option) => option.value === normalized) ? normalized : '';
}

function normalizePlaybackInfoMode(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'rewrite') return 'rewrite';
  if (normalized === 'passthrough') return 'passthrough';
  return 'inherit';
}

function normalizeMediaAuthMode(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'inherit') return 'inherit';
  if (normalized === 'emby') return 'emby';
  if (normalized === 'jellyfin') return 'jellyfin';
  if (normalized === 'passthrough') return 'passthrough';
  return 'auto';
}

function normalizeRealClientIpMode(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'inherit') return 'inherit';
  if (normalized === 'strip') return 'strip';
  if (normalized === 'disable' || normalized === 'none') return 'disable';
  return 'forward';
}

function normalizeRoutingDecisionMode(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'legacy' || normalized === 'simplified') return normalized;
  return 'inherit';
}

function normalizeMainVideoStreamMode(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'direct') return 'direct';
  if (normalized === 'proxy') return 'proxy';
  return 'inherit';
}

function resolveStatusTone() {
  if (authRequired.value) return 'border-amber-400/30 bg-amber-500/12 text-amber-200';
  if (saveNodeError.value || nodeDetailError.value || nodesError.value || pingError.value || deleteError.value || importNodesError.value) {
    return 'border-rose-400/30 bg-rose-500/12 text-rose-200';
  }
  if (importingNodes.value) return 'border-ocean-500/30 bg-ocean-500/12 text-ocean-300';
  if (savingNode.value) return 'border-brand-400/30 bg-brand-500/12 text-brand-200';
  if (loadingNodes.value || loadingNodeDetail.value) return 'border-ocean-500/30 bg-ocean-500/12 text-ocean-300';
  return 'border-mint-400/30 bg-mint-400/12 text-mint-300';
}

function resolveStatusLabel() {
  if (authRequired.value) return '需要登录';
  if (saveNodeError.value || nodeDetailError.value || nodesError.value || pingError.value || deleteError.value || importNodesError.value) return '节点异常';
  if (importingNodes.value) return '正在导入';
  if (savingNode.value) return '正在保存';
  if (loadingNodes.value || loadingNodeDetail.value) return '正在同步';
  return '节点已接通';
}

function resolveLines(node) {
  return Array.isArray(node?.lines) ? node.lines : [];
}

function resolveActiveLine(node) {
  const lines = resolveLines(node);
  if (!lines.length) return null;
  const activeLineId = String(node?.activeLineId || '').trim();
  return lines.find((line) => String(line?.id || '').trim() === activeLineId) || lines[0];
}

function resolveLineById(node, lineId = '') {
  const normalizedLineId = String(lineId || '').trim();
  if (!normalizedLineId) return null;
  return resolveLines(node).find((line) => String(line?.id || '').trim() === normalizedLineId) || null;
}

function resolveSavedLineId(line = {}, index = 0) {
  void index;
  return String(line?.savedId || '').trim();
}

function resolveLineLabel(line = {}, fallback = '默认线路') {
  return String(line?.name || line?.id || fallback).trim() || fallback;
}

function resolveDisplayName(node) {
  return String(node?.displayName || node?.name || '未命名节点').trim() || '未命名节点';
}

function normalizeDiagnosticKey(value = '') {
  return String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
}

function normalizeLatencyNumber(value = null) {
  const ms = Number(value);
  return Number.isFinite(ms) ? Math.max(0, Math.round(ms)) : null;
}

function readFiniteDiagnosticNumber(...candidates) {
  for (const candidate of candidates) {
    const value = Number(candidate);
    if (Number.isFinite(value)) return Math.max(0, Math.round(value));
  }
  return null;
}

function resolveNodeSyncMeta(node = {}) {
  const syncKey = normalizeDiagnosticKey(
    node?._syncState
    || node?.syncState
    || node?.sync_status
  );
  if (!syncKey) return null;

  const labelMap = {
    syncing: '同步中',
    pending: '待同步',
    queued: '待同步',
    failed: '同步失败',
    error: '同步失败',
    success: '已同步',
    ok: '已同步',
    ready: '已同步'
  };
  const toneMap = {
    syncing: 'border-ocean-500/30 bg-ocean-500/12 text-ocean-200',
    pending: 'border-amber-400/30 bg-amber-500/12 text-amber-200',
    queued: 'border-amber-400/30 bg-amber-500/12 text-amber-200',
    failed: 'border-rose-400/30 bg-rose-500/12 text-rose-100',
    error: 'border-rose-400/30 bg-rose-500/12 text-rose-100',
    success: 'border-mint-400/30 bg-mint-400/12 text-mint-200',
    ok: 'border-mint-400/30 bg-mint-400/12 text-mint-200',
    ready: 'border-mint-400/30 bg-mint-400/12 text-mint-200'
  };

  return {
    key: syncKey,
    label: labelMap[syncKey] || syncKey,
    message: String(node?._syncError || node?.syncError || node?.sync_error || '').trim(),
    tone: toneMap[syncKey] || 'border-white/10 bg-white/6 text-slate-200'
  };
}

function resolveNodeHealthMeta(node = {}) {
  const healthKey = normalizeDiagnosticKey(
    node?.healthStatus
    || node?.healthState
    || node?.health?.status
    || node?.health?.state
  );
  const count = readFiniteDiagnosticNumber(
    node?.healthCount,
    node?.health?.count,
    node?.healthyLineCount,
    node?.health?.healthyLineCount
  );
  const message = String(
    node?.healthMessage
    || node?.healthReason
    || node?.health?.message
    || node?.health?.reason
    || ''
  ).trim();

  if (!healthKey && count === null && !message) return null;

  const labelMap = {
    healthy: '健康',
    ok: '健康',
    degraded: '降级',
    warning: '降级',
    pending: '待探测',
    checking: '检查中',
    unhealthy: '异常',
    failed: '异常',
    error: '异常'
  };
  const toneMap = {
    healthy: 'border-mint-400/30 bg-mint-400/12 text-mint-200',
    ok: 'border-mint-400/30 bg-mint-400/12 text-mint-200',
    degraded: 'border-amber-400/30 bg-amber-500/12 text-amber-200',
    warning: 'border-amber-400/30 bg-amber-500/12 text-amber-200',
    pending: 'border-white/10 bg-white/6 text-slate-200',
    checking: 'border-ocean-500/30 bg-ocean-500/12 text-ocean-200',
    unhealthy: 'border-rose-400/30 bg-rose-500/12 text-rose-100',
    failed: 'border-rose-400/30 bg-rose-500/12 text-rose-100',
    error: 'border-rose-400/30 bg-rose-500/12 text-rose-100'
  };

  return {
    key: healthKey,
    label: healthKey ? (labelMap[healthKey] || healthKey) : '健康',
    count,
    message,
    tone: toneMap[healthKey] || 'border-white/10 bg-white/6 text-slate-200'
  };
}

function resolveLineProbeMeta(line = {}) {
  const probeKey = normalizeDiagnosticKey(
    line?.probeStatus
    || line?.status
    || line?.healthStatus
    || line?.healthState
    || line?.state
  );
  if (!probeKey) return null;

  const labelMap = {
    ok: '探测正常',
    success: '探测正常',
    pending: '待探测',
    checking: '探测中',
    timeout: '探测超时',
    failed: '探测失败',
    error: '探测失败',
    network_error: '网络异常',
    unhealthy: '线路异常',
    degraded: '线路降级'
  };
  const toneMap = {
    ok: 'border-mint-400/30 bg-mint-400/12 text-mint-200',
    success: 'border-mint-400/30 bg-mint-400/12 text-mint-200',
    pending: 'border-white/10 bg-white/6 text-slate-200',
    checking: 'border-ocean-500/30 bg-ocean-500/12 text-ocean-200',
    timeout: 'border-amber-400/30 bg-amber-500/12 text-amber-200',
    failed: 'border-rose-400/30 bg-rose-500/12 text-rose-100',
    error: 'border-rose-400/30 bg-rose-500/12 text-rose-100',
    network_error: 'border-rose-400/30 bg-rose-500/12 text-rose-100',
    unhealthy: 'border-rose-400/30 bg-rose-500/12 text-rose-100',
    degraded: 'border-amber-400/30 bg-amber-500/12 text-amber-200'
  };

  return {
    key: probeKey,
    label: labelMap[probeKey] || probeKey,
    tone: toneMap[probeKey] || 'border-white/10 bg-white/6 text-slate-200'
  };
}

function countNodeHeaderEntries(node = {}) {
  if (Array.isArray(node?.headers)) return Object.keys(normalizeHeaderDrafts(node.headers)).length;
  if (isPlainObject(node?.headers)) return Object.keys(node.headers).length;
  return 0;
}

function resolveNodeCompatibilityTips(node = {}) {
  if (!isPlainObject(node)) return [];

  const tips = [];
  const entryMode = normalizeEntryMode(node?.entryMode);
  const headersCount = countNodeHeaderEntries(node);

  if (entryMode === 'host_prefix') {
    tips.push(hostDomain.value
      ? `Host Prefix 节点会挂到 ${hostDomain.value} 子域，secret 会被 Worker 忽略。`
      : 'Host Prefix 节点保存后由 Worker 继续校验 hostDomain 与子域绑定。');
  } else if (String(node?.secret || '').trim()) {
    tips.push('当前节点保留了 secret，适合继续兼容旧的 kv route 入口。');
  }

  if (headersCount > 0) {
    tips.push(`当前节点会携带 ${headersCount} 个自定义 Header，适合兼容旧上游鉴权或特殊网关。`);
  }

  if (normalizePlaybackInfoMode(node?.playbackInfoMode) !== 'inherit') {
    tips.push(`PlaybackInfo 走 ${normalizePlaybackInfoMode(node?.playbackInfoMode)}，旧客户端行为会更可控。`);
  }

  if (normalizeMediaAuthMode(node?.mediaAuthMode) !== 'auto') {
    tips.push(`媒体鉴权策略已固定为 ${normalizeMediaAuthMode(node?.mediaAuthMode)}，可减少不同后端的鉴权漂移。`);
  }

  if (normalizeRoutingDecisionMode(node?.routingDecisionMode) === 'legacy') {
    tips.push('路由决策仍保持 legacy 模式，适合旧版流量先平滑迁移。');
  }

  if (normalizeMainVideoStreamMode(node?.mainVideoStreamMode) !== 'inherit') {
    tips.push(`主视频流模式固定为 ${normalizeMainVideoStreamMode(node?.mainVideoStreamMode)}，可以快速锁定直连或代理语义。`);
  }

  if (String(node?.hedgeProbePath || '').trim()) {
    tips.push(`已配置自定义探测路径 ${String(node.hedgeProbePath).trim()}，更适合按真实上游健康接口治理。`);
  }

  return [...new Set(tips)].slice(0, 4);
}

function resolveDraftSavedLineHint(line = {}, index = 0) {
  if (editor.mode !== 'edit') return '新建节点需要先保存到 Worker，才能做真实线路探测。';

  const savedId = resolveSavedLineId(line, index);
  if (!savedId) return '这条线路还没有保存到 Worker，需先保存节点后再探测。';

  const currentId = normalizeLineIdValue(line?.id, index);
  if (savedId !== currentId) {
    return `当前草稿把线路 ID 改成了 ${currentId}，快速探测仍会命中 Worker 已保存的线路 ${savedId}。`;
  }

  return `快速探测会直接命中 Worker 中的线路 ${savedId}。`;
}

function buildNodeCopyEntries(node = {}) {
  const nodeName = normalizeNodeRouteName(node?.name);
  if (!nodeName) return [];

  const entries = [];
  const seen = new Set();
  const entryMode = normalizeEntryMode(node?.entryMode);
  const currentActiveLineId = String(node?.activeLineId || '').trim();

  const pushEntry = (id, label, href, kind = 'upstream', note = '') => {
    const normalizedHref = String(href || '').trim();
    if (!normalizedHref || seen.has(normalizedHref)) return;
    seen.add(normalizedHref);
    entries.push({
      id,
      label,
      href: normalizedHref,
      kind,
      note: String(note || '').trim()
    });
  };

  const primaryRouteHref = buildNodeRouteHref(nodeName, entryMode, hostDomain.value);
  if (primaryRouteHref) {
    pushEntry(
      `route-${nodeName}`,
      entryMode === 'host_prefix' ? 'Host Prefix 入口' : '主域入口',
      primaryRouteHref,
      'route',
      hostDomain.value
    );
  }

  if (legacyHost.value && entryMode !== 'host_prefix') {
    pushEntry(
      `legacy-${nodeName}`,
      'Legacy Host 入口',
      `https://${legacyHost.value.replace(/^https?:\/\//i, '').replace(/\/+$/, '')}/${nodeName}`,
      'legacy',
      legacyHost.value
    );
  }

  const activeLine = resolveActiveLine(node);
  if (String(activeLine?.target || '').trim()) {
    pushEntry(
      `active-${nodeName}`,
      '当前线路直连',
      activeLine.target,
      'active',
      activeLine?.name || activeLine?.id || '默认线路'
    );
  }

  resolveLines(node).forEach((line, index) => {
    const target = String(line?.target || '').trim();
    if (!target) return;

    const lineLabel = String(line?.name || line?.id || `线路 ${index + 1}`).trim();
    const isActive = String(line?.id || '').trim() && String(line?.id || '').trim() === currentActiveLineId;

    pushEntry(
      `line-${nodeName}-${index}`,
      `线路 ${lineLabel}`,
      target,
      isActive ? 'active' : 'upstream',
      isActive ? '当前 active line' : '线路目标地址'
    );
  });

  return entries;
}

function buildNodeRouteHref(nodeName = '', entryMode = 'kv_route', routeHost = '') {
  const host = String(routeHost || '').trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  if (!host || !nodeName) return '';
  if (normalizeEntryMode(entryMode) === 'host_prefix') return `https://${nodeName}.${host}`;
  return `https://${host}/${nodeName}`;
}

function canCopyNode(node = {}) {
  return buildNodeCopyEntries(node).length > 0;
}

function resolveCopyEntryTone(kind = '') {
  const normalized = String(kind || '').trim().toLowerCase();
  if (normalized === 'route') return 'border-brand-400/25 bg-brand-500/12 text-brand-100';
  if (normalized === 'legacy') return 'border-ocean-500/30 bg-ocean-500/12 text-ocean-200';
  if (normalized === 'active') return 'border-mint-400/30 bg-mint-400/12 text-mint-200';
  return 'border-white/10 bg-white/6 text-slate-200';
}

function resolveTagTone(tagColor = '') {
  const normalizedColor = String(tagColor || '').trim().toLowerCase();
  const toneMap = {
    amber: 'border-amber-300/30 bg-amber-500/12 text-amber-100',
    emerald: 'border-emerald-300/30 bg-emerald-500/12 text-emerald-100',
    sky: 'border-sky-300/30 bg-sky-500/12 text-sky-100',
    violet: 'border-violet-300/30 bg-violet-500/12 text-violet-100',
    rose: 'border-rose-300/30 bg-rose-500/12 text-rose-100'
  };
  return toneMap[normalizedColor] || 'border-white/12 bg-white/8 text-slate-100';
}

function resolveLatencyTone(latencyMs) {
  const ms = Number(latencyMs);
  if (!Number.isFinite(ms)) return 'border-white/12 bg-white/6 text-slate-200';
  if (ms <= 300) return 'border-mint-400/30 bg-mint-400/12 text-mint-200';
  if (ms <= 800) return 'border-amber-400/30 bg-amber-500/12 text-amber-200';
  return 'border-rose-400/30 bg-rose-500/12 text-rose-200';
}

function compactRevision(rawValue = '') {
  const value = String(rawValue || '').trim();
  if (!value) return 'Revision 未生成';
  return value.length > 14 ? `${value.slice(0, 14)}...` : value;
}

function formatLatency(latencyMs) {
  const ms = Number(latencyMs);
  return Number.isFinite(ms) ? `${Math.round(ms)} ms` : '未探测';
}

function formatDateTime(rawValue = '') {
  const value = String(rawValue || '').trim();
  if (!value) return '尚未探测';

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

async function copyText(text = '') {
  const content = String(text || '').trim();
  if (!content) throw new Error('没有可复制的内容。');

  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(content);
    return;
  }

  if (typeof document === 'undefined') {
    throw new Error('当前环境不支持剪贴板复制。');
  }

  const textarea = document.createElement('textarea');
  textarea.value = content;
  textarea.setAttribute('readonly', 'readonly');
  textarea.style.position = 'fixed';
  textarea.style.top = '-9999px';
  document.body.appendChild(textarea);
  textarea.select();

  try {
    const copied = document.execCommand('copy');
    if (!copied) throw new Error('浏览器拒绝写入剪贴板。');
  } finally {
    document.body.removeChild(textarea);
  }
}
</script>

<template>
  <SectionCard
    eyebrow="Nodes Bridge"
    title="节点治理页已经继续往独立前端迁移"
    description="这一版在真实节点列表之外，继续接管 Worker 的 `getNode`、`save` 和 `import`，把节点新增 / 编辑 / 批量导入闭环继续搬过来。"
  >
    <template #meta>
      <div class="flex flex-wrap items-center justify-end gap-3">
        <div class="inline-flex rounded-full border px-3 py-1 text-xs font-semibold" :class="resolveStatusTone()">
          {{ resolveStatusLabel() }}
        </div>
        <button
          type="button"
          class="secondary-btn"
          :disabled="loadingNodes || loadingNodeDetail || savingNode || importingNodes"
          @click="handleRefresh"
        >
          <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loadingNodes }" />
          刷新节点
        </button>
        <button
          type="button"
          class="secondary-btn"
          :disabled="authRequired || savingNode || importingNodes"
          @click="importer.visible ? handleCloseImport() : handleOpenImport()"
        >
          <Upload class="h-4 w-4" />
          {{ importer.visible ? '收起导入' : '批量导入' }}
        </button>
        <button
          type="button"
          class="primary-btn"
          :disabled="authRequired || savingNode || importingNodes"
          @click="handleOpenCreate"
        >
          <Plus class="h-4 w-4" />
          新建节点
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
          <p class="text-sm font-semibold">当前会话尚未授权，节点治理页无法读取或修改真实节点</p>
          <p class="mt-2 text-sm leading-6 text-amber-50/85">
            先在 Worker 管理台完成登录，再回来刷新这一页。这里继续复用原有 `POST /admin/login` 与 `POST /admin`。
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
          <Server class="h-5 w-5 text-brand-300" />
          <p class="text-sm font-medium text-white">{{ tile.title }}</p>
        </div>
        <p class="mt-4 text-2xl font-semibold text-brand-300">{{ tile.value }}</p>
        <p class="mt-3 text-sm leading-6 text-slate-300">{{ tile.note }}</p>
      </article>
    </div>

    <div class="mt-6 rounded-3xl border border-white/10 bg-slate-950/35 p-4">
      <label class="field-shell">
        <span class="field-label">搜索节点</span>
        <div class="relative">
          <Search class="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            v-model="query"
            type="search"
            class="field-input pl-11"
            placeholder="按节点名、显示名、线路地址、标签或备注过滤"
          />
        </div>
      </label>
    </div>

    <article v-if="importer.visible" class="mt-6 form-card">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="max-w-3xl">
          <p class="pill">批量导入</p>
          <h3 class="mt-4 text-2xl font-semibold text-white">从旧节点配置继续搬迁</h3>
          <p class="mt-3 text-sm leading-6 text-slate-300">
            这里直接复用 Worker 的原生 `import` 动作。适合把旧版导出的节点 JSON、配置片段，或手工整理后的节点数组一次性贴进来。
          </p>
        </div>

        <button
          type="button"
          class="secondary-btn"
          :disabled="importingNodes"
          @click="handleCloseImport"
        >
          <X class="h-4 w-4" />
          关闭导入器
        </button>
      </div>

      <div class="mt-6 grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
        <label class="field-shell">
          <span class="field-label">节点 JSON</span>
          <textarea
            v-model="importer.payload"
            rows="16"
            class="field-input field-textarea font-mono text-xs leading-6"
            placeholder='[
  {
    "name": "hk-media",
    "displayName": "香港主入口",
    "headers": {
      "X-From": "legacy-ui"
    },
    "lines": [
      { "id": "line-1", "name": "线路1", "target": "https://upstream.example.com" }
    ]
  }
]'
            :disabled="importingNodes"
          />
          <span class="field-hint">
            支持直接粘贴数组，或粘贴 `{ "nodes": [...] }`。未填写字段仍然由 Worker 继续 merge 和 normalize。
          </span>
        </label>

        <article class="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
          <div class="flex items-center gap-3">
            <FileJson class="h-5 w-5 text-ocean-300" />
            <h4 class="text-sm font-medium text-white">导入说明</h4>
          </div>

          <div class="mt-5 space-y-3 text-sm leading-6 text-slate-300">
            <p>推荐直接从旧版管理台导出的节点结构继续贴过来，现有后端会负责字段归一化与版本兼容。</p>
            <p>如果你只想补几个节点，也可以只提供最核心的 `name + lines`，其余字段让 Worker 走默认值或保留旧值。</p>
            <p>导入成功后，节点列表会立刻刷新到最新 revision，不需要再手动 reload 页面。</p>
          </div>

          <div
            class="mt-5 rounded-2xl border px-4 py-4"
            :class="importPreview.tone === 'error'
              ? 'border-rose-400/25 bg-rose-500/10 text-rose-100'
              : importPreview.tone === 'success'
                ? 'border-mint-400/25 bg-mint-400/10 text-mint-100'
                : 'border-white/10 bg-white/5 text-slate-200'"
          >
            <p class="field-label">{{ importPreview.title }}</p>
            <p class="mt-3 text-sm leading-6">{{ importPreview.description }}</p>
          </div>
        </article>
      </div>

      <div class="mt-6 flex flex-wrap items-center justify-between gap-3">
        <p class="text-sm leading-6 text-slate-400">
          当前 revision：{{ compactRevision(revision) }}。导入期间仍走现有 `POST /admin` + `action=import` 协议。
        </p>

        <div class="flex flex-wrap items-center gap-3">
          <button
            type="button"
            class="secondary-btn"
            :disabled="importingNodes || !hasImportPayload"
            @click="handleResetImport"
          >
            清空内容
          </button>
          <button
            type="button"
            class="primary-btn"
            :disabled="authRequired || importingNodes || savingNode || !hasImportPayload"
            @click="handleImportNodes"
          >
            <Upload class="h-4 w-4" />
            {{ importingNodes ? '导入中' : '导入节点' }}
          </button>
        </div>
      </div>
    </article>

    <article v-if="copyPanel.visible" class="mt-6 form-card">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p class="field-label">多链接复制面板</p>
          <p class="mt-2 text-sm leading-6 text-slate-300">
            当前配置已启用 `multiLinkCopyPanelEnabled`。这里会按节点入口模式、主域 / legacy host 以及各条线路目标地址，汇总出当前节点可直接复制的链接集合。
          </p>
        </div>

        <div class="flex flex-wrap gap-3">
          <button
            type="button"
            class="secondary-btn"
            :disabled="!copyPanel.entries.length"
            @click="handleCopyAllPanelLinks"
          >
            <Copy class="h-4 w-4" />
            {{ copyPanel.copiedKey === '__all__' ? '已复制全部' : '复制全部链接' }}
          </button>
          <button type="button" class="secondary-btn" @click="handleCloseCopyPanel">
            <X class="h-4 w-4" />
            收起
          </button>
        </div>
      </div>

      <div class="mt-5 rounded-3xl border border-white/8 bg-slate-950/40 p-5">
        <div class="flex flex-wrap items-center gap-3">
          <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
            {{ copyPanel.nodeDisplayName || copyPanel.nodeName }}
          </span>
          <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
            {{ copyPanel.entries.length }} 条可复制链接
          </span>
        </div>

        <div v-if="copyPanel.entries.length" class="mt-5 grid gap-3 xl:grid-cols-2">
          <article
            v-for="entry in copyPanel.entries"
            :key="entry.id"
            class="rounded-2xl border border-white/8 bg-slate-950/60 p-4"
          >
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div class="min-w-0">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="inline-flex rounded-full border px-3 py-1 text-xs font-medium" :class="resolveCopyEntryTone(entry.kind)">
                    {{ entry.label }}
                  </span>
                  <span v-if="entry.note" class="text-xs text-slate-400">
                    {{ entry.note }}
                  </span>
                </div>
                <p class="mt-3 break-all font-mono text-xs leading-6 text-slate-300">{{ entry.href }}</p>
              </div>

              <button type="button" class="secondary-btn" @click="handleCopyPanelEntry(entry)">
                <Copy class="h-4 w-4" />
                {{ copyPanel.copiedKey === entry.id ? '已复制' : '复制' }}
              </button>
            </div>
          </article>
        </div>
        <p v-else class="mt-5 text-sm leading-6 text-slate-300">
          当前节点没有可复制的链接。
        </p>
      </div>
    </article>

    <article v-if="editor.visible" class="mt-6 form-card">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="max-w-3xl">
          <p class="pill">{{ editorTitle }}</p>
          <h3 class="mt-4 text-2xl font-semibold text-white">{{ editorTitle }}</h3>
          <p class="mt-3 text-sm leading-6 text-slate-300">{{ editorDescription }}</p>
        </div>

        <div class="flex flex-wrap items-center gap-3">
          <div
            v-if="editor.loadingPrefill || loadingNodeDetail"
            class="inline-flex rounded-full border border-ocean-500/30 bg-ocean-500/12 px-3 py-1 text-xs font-semibold text-ocean-300"
          >
            正在读取节点详情
          </div>
          <button
            type="button"
            class="secondary-btn"
            :disabled="savingNode || importingNodes"
            @click="handleCloseEditor"
          >
            <X class="h-4 w-4" />
            关闭编辑器
          </button>
        </div>
      </div>

      <article
        v-if="editor.mode === 'edit'"
        class="mt-6 rounded-3xl border border-white/10 bg-slate-950/45 p-5"
      >
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div class="max-w-3xl">
            <p class="field-label">已保存节点诊断</p>
            <p class="mt-2 text-sm leading-6 text-slate-300">
              这里的刷新与探测动作直接命中 Worker 当前已保存的节点，不会用本地草稿做 mock 结果。
            </p>
          </div>

          <div class="flex flex-wrap gap-3">
            <button
              type="button"
              class="secondary-btn"
              :disabled="savingNode || importingNodes || editor.loadingPrefill || editorRuntime.refreshingDetail"
              @click="handleRefreshEditorDetail"
            >
              <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': editorRuntime.refreshingDetail }" />
              {{ editorRuntime.refreshingDetail ? '刷新中' : '刷新详情' }}
            </button>
            <button
              type="button"
              class="secondary-btn"
              :disabled="!editorCanOperateSavedNode || props.adminConsole?.isNodePingPending(editorNodeName) || savingNode || importingNodes || !editorSavedActiveLine"
              @click="handlePingEditorSavedNode(editorSavedActiveLine, { lineId: String(editorSavedActiveLine?.id || '').trim(), successMessageTarget: 'editor' })"
            >
              <Activity class="h-4 w-4" :class="{ 'animate-pulse': props.adminConsole?.isNodePingPending(editorNodeName) }" />
              {{ props.adminConsole?.isNodePingPending(editorNodeName) ? '探测中' : '探测 active line' }}
            </button>
            <button
              type="button"
              class="secondary-btn"
              :disabled="!editorCanOperateSavedNode || props.adminConsole?.isNodePingPending(editorNodeName) || savingNode || importingNodes"
              @click="handlePingEditorSavedNode(null, { successMessageTarget: 'editor' })"
            >
              <Activity class="h-4 w-4" :class="{ 'animate-pulse': props.adminConsole?.isNodePingPending(editorNodeName) }" />
              {{ props.adminConsole?.isNodePingPending(editorNodeName) ? '探测中' : '探测全部线路' }}
            </button>
          </div>
        </div>

        <div class="mt-5 flex flex-wrap gap-2">
          <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
            路径 /{{ editorNodeName || '未命名节点' }}
          </span>
          <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
            已保存线路 {{ resolveLines(editorSavedNode).length }}
          </span>
          <span class="inline-flex rounded-full border border-brand-400/25 bg-brand-500/12 px-3 py-1 text-xs text-brand-100">
            saved active {{ resolveLineLabel(editorSavedActiveLine) }}
          </span>
          <span
            v-if="editorSyncMeta"
            class="inline-flex rounded-full border px-3 py-1 text-xs font-medium"
            :class="editorSyncMeta.tone"
          >
            {{ editorSyncMeta.label }}
          </span>
          <span
            v-if="editorHealthMeta"
            class="inline-flex rounded-full border px-3 py-1 text-xs font-medium"
            :class="editorHealthMeta.tone"
          >
            {{ editorHealthMeta.label }}<template v-if="editorHealthMeta.count !== null"> · {{ editorHealthMeta.count }}</template>
          </span>
          <span
            v-if="countNodeHeaderEntries(editorSavedNode)"
            class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200"
          >
            Headers {{ countNodeHeaderEntries(editorSavedNode) }}
          </span>
          <span
            v-if="editorSavedNode?.hedgeProbePath"
            class="inline-flex rounded-full border border-ocean-500/30 bg-ocean-500/12 px-3 py-1 text-xs text-ocean-200"
          >
            Probe {{ editorSavedNode.hedgeProbePath }}
          </span>
        </div>

        <article
          v-if="editorRuntime.actionText"
          class="mt-5 rounded-2xl border px-4 py-4"
          :class="editorRuntime.actionTone === 'success'
            ? 'border-mint-400/25 bg-mint-400/10 text-mint-100'
            : 'border-rose-400/25 bg-rose-500/10 text-rose-100'"
        >
          <p class="text-sm leading-6">{{ editorRuntime.actionText }}</p>
        </article>

        <p
          v-if="hasEditorChanges"
          class="mt-4 rounded-2xl border border-amber-300/20 bg-amber-500/10 px-4 py-3 text-sm leading-6 text-amber-50"
        >
          当前存在未保存草稿。快速治理动作仍然只会作用于 Worker 已保存节点，但会把最新线路探测结果合并回当前草稿，方便你边看边改。
        </p>

        <div class="mt-5 grid gap-4 xl:grid-cols-[0.95fr_1.05fr]">
          <article class="rounded-2xl border border-white/10 bg-slate-950/55 p-4">
            <p class="field-label">同步 / 健康</p>
            <div class="mt-3 space-y-3 text-sm leading-6 text-slate-200">
              <p>
                同步状态：{{ editorSyncMeta?.label || 'Worker 未返回 sync 状态' }}
              </p>
              <p v-if="editorSyncMeta?.message" class="text-rose-100">
                {{ editorSyncMeta.message }}
              </p>
              <p>
                健康状态：
                <span>
                  {{ editorHealthMeta?.label || 'Worker 未返回 health 状态' }}
                  <template v-if="editorHealthMeta?.count !== null"> · {{ editorHealthMeta.count }}</template>
                </span>
              </p>
              <p v-if="editorHealthMeta?.message" class="text-slate-300">
                {{ editorHealthMeta.message }}
              </p>
              <p>
                保存态备注：{{ editorSavedNode?.remark || '未填写' }}
              </p>
            </div>
          </article>

          <article class="rounded-2xl border border-white/10 bg-slate-950/55 p-4">
            <p class="field-label">兼容 / 治理提示</p>
            <div v-if="editorCompatibilityTips.length" class="mt-3 space-y-2 text-sm leading-6 text-slate-200">
              <p v-for="tip in editorCompatibilityTips" :key="tip">
                {{ tip }}
              </p>
            </div>
            <p v-else class="mt-3 text-sm leading-6 text-slate-300">
              当前节点没有额外兼容提示，继续按基础线路配置与默认策略运行。
            </p>
          </article>
        </div>
      </article>

      <div class="mt-6 grid gap-6 xl:grid-cols-[1fr_1fr]">
        <article class="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
          <div class="flex items-center gap-3">
            <Pencil class="h-5 w-5 text-brand-300" />
            <h4 class="text-sm font-medium text-white">基础字段</h4>
          </div>

          <div class="mt-5 grid gap-4 md:grid-cols-2">
            <label class="field-shell">
              <span class="field-label">节点路径</span>
              <input
                v-model="form.name"
                type="text"
                class="field-input"
                placeholder="例如 hk-media"
                :disabled="savingNode || importingNodes"
              />
              <span class="field-hint">会作为 Worker 路由节点名保存，后端最终会统一转成小写。</span>
            </label>

            <label class="field-shell">
              <span class="field-label">显示名称</span>
              <input
                v-model="form.displayName"
                type="text"
                class="field-input"
                placeholder="例如 香港主入口"
                :disabled="savingNode || importingNodes"
              />
            </label>

            <label class="field-shell">
              <span class="field-label">入口模式</span>
              <select v-model="form.entryMode" class="field-input" :disabled="savingNode || importingNodes">
                <option v-for="option in ENTRY_MODE_OPTIONS" :key="option.value" :value="option.value">
                  {{ option.label }}
                </option>
              </select>
            </label>

            <label class="field-shell">
              <span class="field-label">Secret</span>
              <input
                v-model="form.secret"
                type="text"
                class="field-input"
                placeholder="kv_route 时可选"
                :disabled="savingNode || importingNodes || form.entryMode === 'host_prefix'"
              />
              <span class="field-hint">
                {{ form.entryMode === 'host_prefix' ? (hostPrefixHint || 'host prefix 节点不会保存 secret。') : '未填写时沿用无 secret 的普通路径。' }}
              </span>
            </label>

            <label class="field-shell">
              <span class="field-label">标签</span>
              <input
                v-model="form.tag"
                type="text"
                class="field-input"
                placeholder="例如 Premium"
                :disabled="savingNode || importingNodes"
              />
            </label>

            <label class="field-shell">
              <span class="field-label">标签颜色</span>
              <select v-model="form.tagColor" class="field-input" :disabled="savingNode || importingNodes">
                <option v-for="option in TAG_COLOR_OPTIONS" :key="option.value || 'default'" :value="option.value">
                  {{ option.label }}
                </option>
              </select>
            </label>

            <label class="field-shell md:col-span-2">
              <span class="field-label">备注</span>
              <textarea
                v-model="form.remark"
                rows="4"
                class="field-input field-textarea"
                placeholder="记录节点用途、地域或特殊策略"
                :disabled="savingNode || importingNodes"
              />
            </label>
          </div>
        </article>

        <article class="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
          <div class="flex items-center gap-3">
            <Activity class="h-5 w-5 text-ocean-300" />
            <h4 class="text-sm font-medium text-white">代理与播放策略</h4>
          </div>

          <div class="mt-5 grid gap-4 md:grid-cols-2">
            <label class="field-shell">
              <span class="field-label">PlaybackInfo 模式</span>
              <select v-model="form.playbackInfoMode" class="field-input" :disabled="savingNode || importingNodes">
                <option v-for="option in PLAYBACK_INFO_MODE_OPTIONS" :key="option.value" :value="option.value">
                  {{ option.label }}
                </option>
              </select>
            </label>

            <label class="field-shell">
              <span class="field-label">媒体鉴权策略</span>
              <select v-model="form.mediaAuthMode" class="field-input" :disabled="savingNode || importingNodes">
                <option v-for="option in MEDIA_AUTH_MODE_OPTIONS" :key="option.value" :value="option.value">
                  {{ option.label }}
                </option>
              </select>
            </label>

            <label class="field-shell">
              <span class="field-label">真实客户端 IP</span>
              <select v-model="form.realClientIpMode" class="field-input" :disabled="savingNode || importingNodes">
                <option v-for="option in REAL_CLIENT_IP_MODE_OPTIONS" :key="option.value" :value="option.value">
                  {{ option.label }}
                </option>
              </select>
            </label>

            <label class="field-shell">
              <span class="field-label">路由决策模式</span>
              <select v-model="form.routingDecisionMode" class="field-input" :disabled="savingNode || importingNodes">
                <option v-for="option in ROUTING_DECISION_MODE_OPTIONS" :key="option.value" :value="option.value">
                  {{ option.label }}
                </option>
              </select>
            </label>

            <label class="field-shell">
              <span class="field-label">主视频流模式</span>
              <select v-model="form.mainVideoStreamMode" class="field-input" :disabled="savingNode || importingNodes">
                <option v-for="option in MAIN_VIDEO_STREAM_MODE_OPTIONS" :key="option.value" :value="option.value">
                  {{ option.label }}
                </option>
              </select>
            </label>

            <label class="field-shell">
              <span class="field-label">Hedge Probe Path</span>
              <input
                v-model="form.hedgeProbePath"
                type="text"
                class="field-input"
                placeholder="/emby/system/ping"
                :disabled="savingNode || importingNodes"
              />
              <span class="field-hint">可留空，继续继承 Worker 默认探测路径。</span>
            </label>
          </div>
        </article>

        <article class="rounded-3xl border border-white/10 bg-slate-950/40 p-5 xl:col-span-2">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="flex items-center gap-3">
              <FileJson class="h-5 w-5 text-brand-300" />
              <div>
                <h4 class="text-sm font-medium text-white">自定义 Headers</h4>
                <p class="mt-2 text-sm leading-6 text-slate-300">
                  这一版先暴露节点 `headers`，用于上游鉴权或兼容旧配置。Worker 保存时仍会按既有规则过滤危险请求头。
                </p>
              </div>
            </div>

            <button
              type="button"
              class="secondary-btn"
              :disabled="savingNode || importingNodes"
              @click="handleAddHeader"
            >
              <Plus class="h-4 w-4" />
              新增 Header
            </button>
          </div>

          <div v-if="form.headers.length" class="mt-5 space-y-3">
            <article
              v-for="(header, index) in form.headers"
              :key="`${header.key || 'header'}-${index}`"
              class="rounded-3xl border border-white/10 bg-slate-950/55 p-4"
            >
              <div class="grid gap-4 md:grid-cols-[1fr_1fr_auto]">
                <label class="field-shell">
                  <span class="field-label">Header 名称</span>
                  <input
                    v-model="header.key"
                    type="text"
                    class="field-input"
                    placeholder="Authorization"
                    :disabled="savingNode || importingNodes"
                  />
                </label>

                <label class="field-shell">
                  <span class="field-label">Header 值</span>
                  <input
                    v-model="header.value"
                    type="text"
                    class="field-input"
                    placeholder="Bearer xxx"
                    :disabled="savingNode || importingNodes"
                  />
                </label>

                <div class="flex items-end">
                  <button
                    type="button"
                    class="inline-flex items-center gap-2 rounded-full border border-rose-400/30 bg-rose-500/12 px-3 py-2 text-sm font-medium text-rose-100 transition hover:border-rose-300/40 hover:bg-rose-500/18 disabled:pointer-events-none disabled:opacity-60"
                    :disabled="savingNode || importingNodes"
                    @click="handleRemoveHeader(index)"
                  >
                    <Trash2 class="h-4 w-4" />
                    删除
                  </button>
                </div>
              </div>
            </article>
          </div>

          <div
            v-else
            class="mt-5 rounded-2xl border border-dashed border-white/12 bg-white/4 px-4 py-5 text-sm leading-6 text-slate-300"
          >
            当前节点没有自定义 headers。需要兼容旧上游鉴权时，再按 key / value 补进去即可。
          </div>

          <p class="mt-4 text-sm leading-6 text-slate-400">
            当前会提交 {{ normalizedHeaderCount }} 个有效 Header。
          </p>
        </article>
      </div>

      <article class="mt-6 rounded-3xl border border-white/10 bg-slate-950/40 p-5">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p class="field-label">线路编辑</p>
            <p class="mt-2 text-sm leading-6 text-slate-300">
              这一版已经支持真正的拖拽排序。按住拖拽手柄即可调整线路顺序，保存时会继续沿用当前数组顺序提交给 Worker。
            </p>
          </div>

          <button
            type="button"
            class="secondary-btn"
            :disabled="savingNode || importingNodes"
            @click="handleAddLine"
          >
            <Plus class="h-4 w-4" />
            新增线路
          </button>
        </div>

        <div class="mt-5 space-y-4">
          <article
            v-for="(line, index) in form.lines"
            :key="resolveLineDraftKey(line, index)"
            class="relative rounded-3xl border border-white/10 bg-slate-950/55 p-4 transition"
            :class="[
              isDraggingLine(line, index) ? 'opacity-70' : '',
              resolveLineDropHint(line, index) ? 'border-brand-400/60 bg-brand-500/10' : ''
            ]"
            @dragover="handleLineDragOver(resolveLineDraftKey(line, index), $event)"
            @drop="handleLineDrop(resolveLineDraftKey(line, index), $event)"
          >
            <div
              v-if="resolveLineDropHint(line, index)"
              class="absolute left-4 right-4 h-0.5 rounded-full bg-brand-300 shadow-[0_0_18px_rgba(249,115,22,0.45)]"
              :class="resolveLineDropHint(line, index)?.placement === 'after'
                ? 'bottom-0 translate-y-1/2'
                : 'top-0 -translate-y-1/2'"
            />

            <div class="flex flex-wrap items-start justify-between gap-3">
              <div class="inline-flex items-center gap-3">
                <button
                  type="button"
                  class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-3 py-1.5 text-xs font-medium text-slate-100 transition hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
                  :disabled="savingNode || importingNodes || form.lines.length <= 1"
                  :draggable="!(savingNode || importingNodes || form.lines.length <= 1)"
                  title="拖拽调整线路顺序"
                  @dragstart="handleLineDragStart(resolveLineDraftKey(line, index), $event)"
                  @dragend="handleLineDragEnd"
                >
                  <GripVertical class="h-3.5 w-3.5" />
                  拖拽排序
                </button>
                <div class="inline-flex rounded-full border border-white/10 bg-white/6 px-2.5 py-1 text-xs font-medium text-slate-300">
                  #{{ index + 1 }}
                </div>
                <label class="inline-flex items-center gap-2 text-sm text-slate-200">
                  <input
                    :checked="String(form.activeLineId || '').trim() === normalizeLineIdValue(line.id, index)"
                    type="radio"
                    name="node-active-line"
                    class="h-4 w-4"
                    :disabled="savingNode || importingNodes"
                    @change="handleSetActiveLine(normalizeLineIdValue(line.id, index))"
                  />
                  设为 active line
                </label>
              </div>

              <div class="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-3 py-1.5 text-xs font-medium text-slate-100 transition hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
                  :disabled="savingNode || importingNodes || !canMoveLineUp(index)"
                  @click="handleMoveLine(index, -1)"
                >
                  <ArrowUp class="h-3.5 w-3.5" />
                  上移
                </button>
                <button
                  type="button"
                  class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-3 py-1.5 text-xs font-medium text-slate-100 transition hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
                  :disabled="savingNode || importingNodes || !canMoveLineDown(index)"
                  @click="handleMoveLine(index, 1)"
                >
                  <ArrowDown class="h-3.5 w-3.5" />
                  下移
                </button>
                <button
                  type="button"
                  class="inline-flex items-center gap-2 rounded-full border border-rose-400/30 bg-rose-500/12 px-3 py-1.5 text-xs font-medium text-rose-100 transition hover:border-rose-300/40 hover:bg-rose-500/18 disabled:pointer-events-none disabled:opacity-60"
                  :disabled="savingNode || importingNodes"
                  @click="handleRemoveLine(index)"
                >
                  <Trash2 class="h-3.5 w-3.5" />
                  删除线路
                </button>
              </div>
            </div>

            <p
              v-if="resolveLineDropHint(line, index)"
              class="mt-3 text-xs font-medium tracking-[0.08em] text-brand-200"
            >
              {{ resolveLineDropHint(line, index)?.text }}
            </p>

            <div class="mt-4 grid gap-4 md:grid-cols-3">
              <label class="field-shell">
                <span class="field-label">线路 ID</span>
                <input
                  v-model="line.id"
                  type="text"
                  class="field-input"
                  placeholder="line-1"
                  :disabled="savingNode || importingNodes"
                />
              </label>

              <label class="field-shell">
                <span class="field-label">线路名称</span>
                <input
                  v-model="line.name"
                  type="text"
                  class="field-input"
                  placeholder="线路1"
                  :disabled="savingNode || importingNodes"
                />
              </label>

              <label class="field-shell md:col-span-1">
                <span class="field-label">目标地址</span>
                <input
                  v-model="line.target"
                  type="text"
                  class="field-input"
                  placeholder="https://upstream.example.com"
                  :disabled="savingNode || importingNodes"
                />
              </label>
            </div>

            <div class="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-white/8 bg-white/5 px-4 py-3">
              <div class="flex flex-wrap items-center gap-2">
                <span
                  class="inline-flex rounded-full border px-2.5 py-1 text-[11px] font-medium"
                  :class="resolveSavedLineId(line, index)
                    ? 'border-white/10 bg-white/6 text-slate-200'
                    : 'border-amber-400/30 bg-amber-500/12 text-amber-200'"
                >
                  {{ resolveSavedLineId(line, index) ? `已保存 ${resolveSavedLineId(line, index)}` : '未保存线路' }}
                </span>
                <span
                  class="inline-flex rounded-full border px-2.5 py-1 text-[11px] font-medium"
                  :class="resolveLatencyTone(line.latencyMs)"
                >
                  {{ formatLatency(line.latencyMs) }}
                </span>
                <span
                  v-if="resolveLineProbeMeta(line)"
                  class="inline-flex rounded-full border px-2.5 py-1 text-[11px] font-medium"
                  :class="resolveLineProbeMeta(line)?.tone"
                >
                  {{ resolveLineProbeMeta(line)?.label }}
                </span>
                <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-2.5 py-1 text-[11px] text-slate-300">
                  最近探测 {{ formatDateTime(line.latencyUpdatedAt) }}
                </span>
              </div>

              <button
                type="button"
                class="secondary-btn"
                :disabled="!editorCanOperateSavedNode || !resolveSavedLineId(line, index) || props.adminConsole?.isNodePingPending(editorNodeName) || savingNode || importingNodes"
                @click="handlePingEditorSavedNode(line, { lineId: resolveSavedLineId(line, index), successMessageTarget: 'editor' })"
              >
                <Activity class="h-4 w-4" :class="{ 'animate-pulse': props.adminConsole?.isNodePingPending(editorNodeName) }" />
                {{ props.adminConsole?.isNodePingPending(editorNodeName)
                  ? '探测中'
                  : (!editorCanOperateSavedNode || !resolveSavedLineId(line, index) ? '保存后可探测' : '探测已保存线路') }}
              </button>
            </div>

            <p class="mt-3 text-xs leading-6 text-slate-400">
              {{ resolveDraftSavedLineHint(line, index) }}
            </p>
          </article>
        </div>

        <div class="mt-6 flex flex-wrap items-center justify-between gap-3">
          <p class="text-sm leading-6 text-slate-400">
            当前会提交 {{ normalizeLineDrafts(form.lines).length }} 条有效线路。
          </p>

          <div class="flex flex-wrap items-center gap-3">
            <button
              type="button"
              class="secondary-btn"
              :disabled="savingNode || importingNodes"
              @click="handleCloseEditor"
            >
              取消
            </button>
            <button
              type="button"
              class="primary-btn"
              :disabled="authRequired || savingNode || importingNodes || editor.loadingPrefill || !hasEditorChanges"
              @click="handleSaveNode"
            >
              <Save class="h-4 w-4" />
              {{ savingNode ? '保存中' : '保存节点' }}
            </button>
          </div>
        </div>
      </article>
    </article>

    <div v-if="filteredNodes.length" class="mt-6 grid gap-4 xl:grid-cols-2">
      <article
        v-for="node in filteredNodes"
        :key="node.name"
        class="form-card flex h-full flex-col gap-5"
      >
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="flex flex-wrap items-center gap-2">
              <h3 class="text-lg font-semibold text-white">{{ resolveDisplayName(node) }}</h3>
              <span
                v-if="node.tag"
                class="inline-flex rounded-full border px-2.5 py-1 text-xs font-medium"
                :class="resolveTagTone(node.tagColor)"
              >
                {{ node.tag }}
              </span>
            </div>
            <p class="mt-2 break-all text-sm text-slate-400">/{{ node.name }}</p>
          </div>

          <div
            class="inline-flex rounded-full border px-3 py-1 text-xs font-semibold"
            :class="resolveLatencyTone(resolveActiveLine(node)?.latencyMs)"
          >
            {{ formatLatency(resolveActiveLine(node)?.latencyMs) }}
          </div>
        </div>

        <div class="flex flex-wrap gap-2">
          <div class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200">
            线路 {{ resolveLines(node).length }}
          </div>
          <div class="inline-flex rounded-full border border-brand-400/25 bg-brand-500/12 px-3 py-1 text-xs text-brand-100">
            当前 {{ resolveActiveLine(node)?.name || resolveActiveLine(node)?.id || '默认线路' }}
          </div>
          <div class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-300">
            {{ node.entryMode || 'kv_route' }}
          </div>
          <div
            v-if="resolveNodeSyncMeta(node)"
            class="inline-flex rounded-full border px-3 py-1 text-xs font-medium"
            :class="resolveNodeSyncMeta(node)?.tone"
          >
            {{ resolveNodeSyncMeta(node)?.label }}
          </div>
          <div
            v-if="resolveNodeHealthMeta(node)"
            class="inline-flex rounded-full border px-3 py-1 text-xs font-medium"
            :class="resolveNodeHealthMeta(node)?.tone"
          >
            {{ resolveNodeHealthMeta(node)?.label }}<template v-if="resolveNodeHealthMeta(node)?.count !== null"> · {{ resolveNodeHealthMeta(node)?.count }}</template>
          </div>
        </div>

        <div class="grid gap-3">
          <article class="rounded-2xl border border-white/10 bg-slate-950/55 p-4">
            <p class="field-label">当前线路目标</p>
            <p class="mt-3 break-all text-sm leading-6 text-slate-100">
              {{ resolveActiveLine(node)?.target || '未配置目标地址' }}
            </p>
            <p class="mt-3 text-xs text-slate-400">
              最近探测：{{ formatDateTime(resolveActiveLine(node)?.latencyUpdatedAt) }}
            </p>
            <p
              v-if="resolveNodeSyncMeta(node)?.message || resolveNodeHealthMeta(node)?.message"
              class="mt-3 text-xs leading-5 text-slate-400"
            >
              {{ resolveNodeSyncMeta(node)?.message || resolveNodeHealthMeta(node)?.message }}
            </p>
          </article>

          <article v-if="node.remark" class="rounded-2xl border border-white/10 bg-slate-950/45 p-4">
            <p class="field-label">备注</p>
            <p class="mt-3 text-sm leading-6 text-slate-200">{{ node.remark }}</p>
          </article>

          <article v-if="resolveNodeCompatibilityTips(node).length" class="rounded-2xl border border-white/10 bg-slate-950/45 p-4">
            <p class="field-label">兼容提示</p>
            <div class="mt-3 space-y-2 text-sm leading-6 text-slate-200">
              <p v-for="tip in resolveNodeCompatibilityTips(node)" :key="tip">
                {{ tip }}
              </p>
            </div>
          </article>

          <article class="rounded-2xl border border-white/10 bg-slate-950/45 p-4">
            <div class="flex items-center justify-between gap-3">
              <p class="field-label">线路列表</p>
              <p class="text-xs text-slate-400">{{ resolveLines(node).length }} 条</p>
            </div>

            <div class="mt-3 space-y-2">
              <div
                v-for="line in resolveLines(node)"
                :key="line.id || line.target"
                class="flex flex-wrap items-start justify-between gap-3 rounded-2xl border border-white/8 bg-white/5 px-4 py-3"
              >
                <div class="min-w-0 flex-1">
                  <div class="flex flex-wrap items-center gap-2">
                    <p class="text-sm font-medium text-white">{{ line.name || line.id || '未命名线路' }}</p>
                    <div
                      class="inline-flex rounded-full border px-2.5 py-1 text-[11px] font-semibold"
                      :class="String(line.id || '').trim() === String(node.activeLineId || '').trim()
                        ? 'border-brand-400/25 bg-brand-500/12 text-brand-100'
                        : 'border-white/10 bg-white/6 text-slate-300'"
                    >
                      {{ String(line.id || '').trim() === String(node.activeLineId || '').trim() ? 'active' : 'standby' }}
                    </div>
                    <div
                      class="inline-flex rounded-full border px-2.5 py-1 text-[11px] font-semibold"
                      :class="resolveLatencyTone(line.latencyMs)"
                    >
                      {{ formatLatency(line.latencyMs) }}
                    </div>
                    <div
                      v-if="resolveLineProbeMeta(line)"
                      class="inline-flex rounded-full border px-2.5 py-1 text-[11px] font-semibold"
                      :class="resolveLineProbeMeta(line)?.tone"
                    >
                      {{ resolveLineProbeMeta(line)?.label }}
                    </div>
                  </div>
                  <p class="mt-2 break-all text-xs leading-5 text-slate-400">{{ line.target || '未配置目标地址' }}</p>
                  <p class="mt-2 text-[11px] leading-5 text-slate-500">
                    最近探测 {{ formatDateTime(line.latencyUpdatedAt) }}<template v-if="line.remark"> · {{ line.remark }}</template>
                  </p>
                </div>
                <button
                  type="button"
                  class="secondary-btn"
                  :disabled="props.adminConsole?.isNodePingPending(node.name) || props.adminConsole?.isNodeDeleting(node.name) || savingNode || importingNodes"
                  @click="handlePing(node, line)"
                >
                  <Activity class="h-4 w-4" :class="{ 'animate-pulse': props.adminConsole?.isNodePingPending(node.name) }" />
                  {{ props.adminConsole?.isNodePingPending(node.name) ? '探测中' : '探测此线路' }}
                </button>
              </div>
            </div>
          </article>
        </div>

        <div class="mt-auto flex flex-wrap gap-3">
          <button
            type="button"
            class="secondary-btn"
            :disabled="savingNode || importingNodes || props.adminConsole?.isNodeDeleting(node.name)"
            @click="handleOpenEdit(node)"
          >
            <Pencil class="h-4 w-4" />
            编辑节点
          </button>

          <button
            type="button"
            class="secondary-btn"
            :disabled="props.adminConsole?.isNodePingPending(node.name) || props.adminConsole?.isNodeDeleting(node.name) || savingNode || importingNodes"
            @click="handlePing(node)"
          >
            <Activity class="h-4 w-4" :class="{ 'animate-pulse': props.adminConsole?.isNodePingPending(node.name) }" />
            {{ props.adminConsole?.isNodePingPending(node.name) ? '探测中' : '探测全部线路' }}
          </button>

          <button
            type="button"
            class="secondary-btn"
            :disabled="!canCopyNode(node) || props.adminConsole?.isNodeDeleting(node.name) || importingNodes"
            @click="handleCopy(node)"
          >
            <Copy class="h-4 w-4" />
            {{ multiLinkCopyPanelEnabled ? '复制多链接' : '复制当前线路' }}
          </button>

          <button
            type="button"
            class="inline-flex items-center gap-2 rounded-full border border-rose-400/30 bg-rose-500/12 px-4 py-2 text-sm font-medium text-rose-100 transition hover:border-rose-300/40 hover:bg-rose-500/18 disabled:pointer-events-none disabled:opacity-60"
            :disabled="props.adminConsole?.isNodeDeleting(node.name) || savingNode || importingNodes"
            @click="handleDelete(node)"
          >
            <Trash2 class="h-4 w-4" />
            {{ props.adminConsole?.isNodeDeleting(node.name) ? '删除中' : '删除节点' }}
          </button>
        </div>
      </article>
    </div>

    <article
      v-else
      class="mt-6 rounded-3xl border border-dashed border-white/12 bg-white/4 px-5 py-10 text-center"
    >
      <p class="text-base font-medium text-white">
        {{ query ? '没有匹配当前筛选的节点' : '当前还没有可展示的节点' }}
      </p>
      <p class="mt-3 text-sm leading-6 text-slate-400">
        {{ query
          ? '换一个关键词，或先点击“刷新节点”重新读取 Worker 的节点 summary。'
          : '先新建一个节点，或完成登录后重新同步。' }}
      </p>
      <button
        v-if="!query"
        type="button"
        class="primary-btn mt-5"
        :disabled="authRequired || importingNodes"
        @click="handleOpenCreate"
      >
        <Plus class="h-4 w-4" />
        新建第一个节点
      </button>
    </article>
  </SectionCard>
</template>
