<script setup>
import { computed, ref } from 'vue';
import { Eye, RotateCcw, SlidersHorizontal } from 'lucide-vue-next';

import { useUiPreferences } from '@/composables/useUiPreferences';

const props = defineProps({
  items: {
    type: Array,
    default: () => []
  },
  activeLogKey: {
    type: String,
    default: ''
  },
  anyBusy: {
    type: Boolean,
    default: false
  },
  emptyText: {
    type: String,
    default: '当前没有可展示的日志结果。'
  }
});

const emit = defineEmits(['open-detail']);

const UA_COLUMN_WIDTH_MIN = 50;
const UA_COLUMN_WIDTH_MAX = 520;
const UA_COLUMN_WIDTH_STEP = 10;
const UA_COLUMN_WIDTH_DEFAULT = 220;

const uiPreferences = useUiPreferences();

const normalizedItems = computed(() => (Array.isArray(props.items) ? props.items : []));
const uaColumnWidth = ref(resolveInitialUaColumnWidth());

const uaColumnWidthStyle = computed(() => ({
  '--logs-ua-column-width': `${uaColumnWidth.value}px`
}));

const uaColumnWidthLabel = computed(() => `${uaColumnWidth.value} px`);
const hasCustomUaColumnWidth = computed(() => uaColumnWidth.value !== UA_COLUMN_WIDTH_DEFAULT);

function handleUaColumnWidthInput(event) {
  applyUaColumnWidth(event?.target?.value ?? UA_COLUMN_WIDTH_DEFAULT);
}

function handleResetUaColumnWidth() {
  uaColumnWidth.value = UA_COLUMN_WIDTH_DEFAULT;
  uiPreferences.persistLogUaColumnWidth('');
}

function handleOpenDetail(item = null) {
  const logKey = String(item?.key || '').trim();
  if (!logKey || props.anyBusy) return;
  emit('open-detail', logKey);
}

function resolveInitialUaColumnWidth() {
  const storedValue = uiPreferences.readLogUaColumnWidth();
  return normalizeUaColumnWidth(storedValue, UA_COLUMN_WIDTH_DEFAULT);
}

function applyUaColumnWidth(value) {
  const normalized = normalizeUaColumnWidth(value, UA_COLUMN_WIDTH_DEFAULT);
  uaColumnWidth.value = normalized;
  uiPreferences.persistLogUaColumnWidth(
    normalized === UA_COLUMN_WIDTH_DEFAULT
      ? ''
      : String(normalized)
  );
}

function normalizeUaColumnWidth(value, fallback = UA_COLUMN_WIDTH_DEFAULT) {
  const numeric = Math.round(Number.parseFloat(String(value ?? '').trim()));
  if (!Number.isFinite(numeric)) return fallback;
  return Math.min(UA_COLUMN_WIDTH_MAX, Math.max(UA_COLUMN_WIDTH_MIN, numeric));
}
</script>

<template>
  <div class="mt-6" :style="uaColumnWidthStyle">
    <article
      v-if="normalizedItems.length"
      class="mb-4 rounded-3xl border border-white/8 bg-white/4 px-5 py-4"
    >
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="max-w-3xl">
          <div class="flex items-center gap-3">
            <SlidersHorizontal class="h-4 w-4 text-brand-300" />
            <p class="text-xs uppercase tracking-[0.16em] text-slate-400">UA 宽度偏好</p>
          </div>
          <p class="mt-3 text-sm leading-6 text-slate-300">
            这里会沿用现有 `logUaColumnWidth` 本地偏好。调整后会立即写回本地存储，后续再次进入日志页仍会沿用。
          </p>
        </div>

        <div class="w-full max-w-xl rounded-2xl border border-white/8 bg-slate-950/45 px-4 py-3">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <p class="text-sm font-medium text-white">User Agent 区域宽度</p>
            <span class="inline-flex rounded-full border border-brand-400/20 bg-brand-500/10 px-3 py-1 text-xs text-brand-100">
              {{ hasCustomUaColumnWidth ? uaColumnWidthLabel : `${uaColumnWidthLabel} · 默认` }}
            </span>
          </div>

          <input
            class="mt-4 w-full accent-brand-400"
            type="range"
            :min="UA_COLUMN_WIDTH_MIN"
            :max="UA_COLUMN_WIDTH_MAX"
            :step="UA_COLUMN_WIDTH_STEP"
            :value="uaColumnWidth"
            @input="handleUaColumnWidthInput"
          />

          <div class="mt-3 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400">
                <span>{{ UA_COLUMN_WIDTH_MIN }} px 到 {{ UA_COLUMN_WIDTH_MAX }} px</span>
            <button
              type="button"
              class="secondary-btn !px-3 !py-2 text-xs"
              :disabled="!hasCustomUaColumnWidth"
              @click="handleResetUaColumnWidth"
            >
              <RotateCcw class="h-3.5 w-3.5" />
              重置
            </button>
          </div>
        </div>
      </div>
    </article>

    <div v-if="normalizedItems.length" class="space-y-4">
      <article
        v-for="item in normalizedItems"
        :key="item.key"
        class="rounded-3xl border bg-slate-950/45 p-5"
        :class="item.key === activeLogKey
          ? 'border-brand-400/40 shadow-[0_16px_42px_rgba(249,115,22,0.12)]'
          : 'border-white/10'"
      >
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div class="min-w-0 flex-1">
            <div class="flex flex-wrap items-center gap-2">
              <span
                class="inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold"
                :class="item.statusTone"
              >
                {{ item.statusCode }}
              </span>
              <span class="inline-flex rounded-full border border-white/10 bg-white/6 px-2.5 py-1 text-xs text-slate-200">
                {{ item.category }}
              </span>
              <span
                v-if="item.requestGroup"
                class="inline-flex rounded-full border border-ocean-400/20 bg-ocean-500/10 px-2.5 py-1 text-xs text-ocean-100"
              >
                {{ item.requestGroup }}
              </span>
              <span
                v-if="item.deliveryMode"
                class="inline-flex rounded-full border border-brand-400/20 bg-brand-500/10 px-2.5 py-1 text-xs text-brand-100"
              >
                {{ item.deliveryMode }}
              </span>
              <span
                v-if="item.protocolFailureReason"
                class="inline-flex rounded-full border border-rose-400/20 bg-rose-500/10 px-2.5 py-1 text-xs text-rose-100"
              >
                {{ item.protocolFailureReason }}
              </span>
            </div>

            <p class="mt-4 break-all font-mono text-sm text-white">
              {{ item.method }} {{ item.path }}
            </p>
            <p class="mt-3 text-sm leading-6 text-slate-300">
              节点 {{ item.nodeName }}，客户端 {{ item.clientText }}，入口 / 出口 {{ item.coloText }}
            </p>
            <div v-if="item.diagnosticBadges.length" class="mt-4 flex flex-wrap gap-2">
              <span
                v-for="badge in item.diagnosticBadges"
                :key="`${item.key}-${badge.key}`"
                class="inline-flex rounded-full border px-2.5 py-1 text-xs"
                :class="badge.tone"
              >
                {{ badge.label }} · {{ badge.value }}
              </span>
            </div>
            <p
              v-if="item.diagnosticSummary"
              class="mt-3 text-xs leading-6 text-slate-400"
            >
              {{ item.diagnosticSummary }}
            </p>
          </div>

          <div class="flex flex-col items-end gap-3 text-right text-sm leading-6 text-slate-300">
            <div>
              <p>{{ item.timestampText }}</p>
              <p class="mt-2 text-xs uppercase tracking-[0.16em] text-slate-500">{{ item.responseTimeText }}</p>
            </div>

            <button
              type="button"
              class="secondary-btn"
              :disabled="anyBusy"
              @click="handleOpenDetail(item)"
            >
              <Eye class="h-4 w-4" />
              {{ item.key === activeLogKey ? '查看中' : '查看详情' }}
            </button>
          </div>
        </div>

        <div class="logs-results-list__detail-grid mt-4 gap-4">
          <div class="rounded-2xl border border-white/8 bg-white/4 px-4 py-3">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">错误详情</p>
            <p class="mt-3 break-all text-sm leading-6 text-slate-200">
              {{ item.errorDetailText }}
            </p>
          </div>

          <div class="rounded-2xl border border-white/8 bg-white/4 px-4 py-3">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">User Agent</p>
            <p class="mt-3 break-all text-sm leading-6 text-slate-200">
              {{ item.userAgentText }}
            </p>
          </div>
        </div>
      </article>
    </div>

    <article
      v-else
      class="rounded-3xl border border-dashed border-white/12 bg-white/4 px-5 py-8 text-sm leading-6 text-slate-300"
    >
      {{ emptyText }}
    </article>
  </div>
</template>

<style scoped>
.logs-results-list__detail-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
}

@media (min-width: 1280px) {
  .logs-results-list__detail-grid {
    grid-template-columns: minmax(0, 1fr) minmax(0, var(--logs-ua-column-width, 220px));
  }
}
</style>
