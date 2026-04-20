<script setup>
import { computed, reactive, watch } from 'vue';
import { BellRing, Globe } from 'lucide-vue-next';

import {
  cloneDnsAutoUploadForm,
  createEmptyDnsAutoUploadForm,
  DEFAULT_DNS_AUTO_UPLOAD_RECORD_TYPE_SUGGESTIONS,
  DEFAULT_DNS_AUTO_UPLOAD_SCHEDULE_MODE_OPTIONS,
  mergeDnsAutoUploadForm,
  parseDnsAutoUploadClockTimes,
  parseDnsAutoUploadCountryCodes,
  parseDnsAutoUploadRecordTypes,
  serializeDnsAutoUploadForm
} from './dnsAutoUploadPanel.shared.js';

const props = defineProps({
  modelValue: {
    type: Object,
    default: null
  },
  form: {
    type: Object,
    default: null
  },
  disabled: {
    type: Boolean,
    default: false
  },
  readonly: {
    type: Boolean,
    default: false
  },
  title: {
    type: String,
    default: 'DNS 自动上传调度'
  },
  description: {
    type: String,
    default: '独立承载 dnsAutoUpload* 一组字段，方便后续嵌入任意设置页或弹层。'
  },
  scheduleModeOptions: {
    type: Array,
    default: () => DEFAULT_DNS_AUTO_UPLOAD_SCHEDULE_MODE_OPTIONS.map((option) => ({ ...option }))
  },
  recordTypeSuggestions: {
    type: Array,
    default: () => DEFAULT_DNS_AUTO_UPLOAD_RECORD_TYPE_SUGGESTIONS.slice()
  },
  showPreview: {
    type: Boolean,
    default: true
  }
});

const emit = defineEmits(['update:modelValue', 'update:form', 'change']);

const draft = reactive(createEmptyDnsAutoUploadForm());

const isLocked = computed(() => props.disabled || props.readonly);
const usesClockTimes = computed(() => draft.dnsAutoUploadScheduleMode === 'clock_times');
const usesIntervalMinutes = computed(() => (
  draft.dnsAutoUploadScheduleMode === 'interval' || draft.dnsAutoUploadScheduleMode === 'window'
));
const usesWindowRange = computed(() => draft.dnsAutoUploadScheduleMode === 'window');
const parsedClockTimes = computed(() => parseDnsAutoUploadClockTimes(draft.dnsAutoUploadClockTimes));
const parsedCountryCodes = computed(() => parseDnsAutoUploadCountryCodes(draft.dnsAutoUploadCountryCodes));
const parsedRecordTypes = computed(() => parseDnsAutoUploadRecordTypes(draft.dnsAutoUploadRecordTypes));

const resolvedScheduleModeOptions = computed(() => {
  const normalized = Array.isArray(props.scheduleModeOptions)
    ? props.scheduleModeOptions
      .filter(isPlainObject)
      .map((option) => ({
        value: String(option.value || '').trim(),
        label: String(option.label || option.value || '').trim(),
        hint: String(option.hint || '').trim()
      }))
      .filter((option) => option.value)
    : [];

  if (normalized.some((option) => option.value === draft.dnsAutoUploadScheduleMode)) {
    return normalized;
  }

  if (!draft.dnsAutoUploadScheduleMode) return normalized;

  return [
    ...normalized,
    {
      value: draft.dnsAutoUploadScheduleMode,
      label: draft.dnsAutoUploadScheduleMode,
      hint: '当前值不是预置选项，组件会继续保留这个模式。'
    }
  ];
});

const activeScheduleMode = computed(() => {
  return resolvedScheduleModeOptions.value.find((option) => option.value === draft.dnsAutoUploadScheduleMode) || null;
});

const activeScheduleLabel = computed(() => activeScheduleMode.value?.label || '未设置');
const activeScheduleHint = computed(() => {
  if (activeScheduleMode.value?.hint) return activeScheduleMode.value.hint;
  if (usesWindowRange.value) return '窗口模式通常会搭配开始/结束时间和 interval 分钟数一起使用。';
  if (usesIntervalMinutes.value) return '固定间隔模式会持续按照分钟数调度。';
  return '按时刻模式支持多个 HH:mm 值，适合固定时间点执行。';
});

watch(
  () => serializeDnsAutoUploadForm(props.form ?? props.modelValue),
  () => {
    const nextDraft = cloneDnsAutoUploadForm(props.form ?? props.modelValue);
    if (serializeDnsAutoUploadForm(draft) === serializeDnsAutoUploadForm(nextDraft)) return;
    Object.assign(draft, nextDraft);
  },
  { immediate: true }
);

function updateField(key, value) {
  if (isLocked.value) return;
  draft[key] = value;
  emitDraftChange();
}

function emitDraftChange() {
  const nextSubset = cloneDnsAutoUploadForm(draft);
  const nextForm = props.form ? mergeDnsAutoUploadForm(props.form, nextSubset) : nextSubset;

  emit('update:modelValue', nextSubset);
  emit('update:form', nextForm);
  emit('change', {
    subset: nextSubset,
    form: nextForm
  });
}

function appendRecordType(recordType = '') {
  if (isLocked.value) return;

  const nextType = String(recordType || '').trim().toUpperCase();
  if (!nextType) return;

  const nextValues = parseDnsAutoUploadRecordTypes(draft.dnsAutoUploadRecordTypes);
  if (!nextValues.includes(nextType)) nextValues.push(nextType);

  draft.dnsAutoUploadRecordTypes = nextValues.join('\n');
  emitDraftChange();
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
</script>

<template>
  <article class="form-card" :class="{ 'opacity-70': isLocked }">
    <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
      <div class="flex items-start gap-3">
        <Globe class="mt-0.5 h-5 w-5 text-brand-300" />
        <div>
          <h3 class="text-sm font-medium text-white">{{ title }}</h3>
          <p v-if="description" class="mt-2 max-w-3xl text-sm leading-6 text-slate-300">
            {{ description }}
          </p>
        </div>
      </div>

      <div class="flex flex-wrap gap-2">
        <span class="pill">{{ draft.dnsAutoUploadEnabled ? '自动上传已启用' : '自动上传未启用' }}</span>
        <span class="pill">{{ activeScheduleLabel }}</span>
        <span class="pill">{{ draft.dnsAutoUploadNotifyEnabled ? '通知已启用' : '通知未启用' }}</span>
      </div>
    </div>

    <p v-if="!draft.dnsAutoUploadEnabled" class="mt-4 text-sm leading-6 text-slate-300">
      当前只是关闭执行，不会自动清空下面的调度、筛选和通知字段，方便先配好再统一启用。
    </p>

    <div class="mt-5 grid gap-4 md:grid-cols-2">
      <label class="toggle-card md:col-span-2">
        <input
          :checked="draft.dnsAutoUploadEnabled"
          type="checkbox"
          class="h-4 w-4 rounded"
          :disabled="isLocked"
          @change="updateField('dnsAutoUploadEnabled', $event.target.checked)"
        />
        <div class="flex flex-col gap-1">
          <span>启用 DNS 自动上传</span>
          <span class="text-xs leading-5 text-slate-400">关闭时仍会保留所有输入值，适合提前预配置。</span>
        </div>
      </label>

      <label class="field-shell">
        <span class="field-label">调度模式</span>
        <select
          :value="draft.dnsAutoUploadScheduleMode"
          class="field-input"
          :disabled="isLocked"
          @change="updateField('dnsAutoUploadScheduleMode', $event.target.value)"
        >
          <option v-for="option in resolvedScheduleModeOptions" :key="option.value" :value="option.value">
            {{ option.label }}
          </option>
        </select>
        <span class="field-hint">{{ activeScheduleHint }}</span>
      </label>

      <label class="field-shell">
        <span class="field-label">Top N</span>
        <input
          :value="draft.dnsAutoUploadTopN"
          type="number"
          min="1"
          max="500"
          class="field-input"
          :disabled="isLocked"
          placeholder="例如 20"
          @input="updateField('dnsAutoUploadTopN', $event.target.value)"
        />
        <span class="field-hint">限制每次自动上传优先挑选的记录数量。</span>
      </label>

      <div v-if="usesClockTimes" class="field-shell md:col-span-2">
        <span class="field-label">执行时刻</span>
        <textarea
          :value="draft.dnsAutoUploadClockTimes"
          rows="4"
          class="field-input field-textarea"
          :disabled="isLocked"
          placeholder="09:00&#10;21:30"
          @input="updateField('dnsAutoUploadClockTimes', $event.target.value)"
        />
        <span class="field-hint">支持换行、逗号或分号分隔，适合表达多个 HH:mm 定时点。</span>
        <div v-if="showPreview && parsedClockTimes.length > 0" class="flex flex-wrap gap-2">
          <span
            v-for="clockTime in parsedClockTimes"
            :key="clockTime"
            class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200"
          >
            {{ clockTime }}
          </span>
        </div>
      </div>

      <label v-if="usesIntervalMinutes" class="field-shell">
        <span class="field-label">间隔分钟数</span>
        <input
          :value="draft.dnsAutoUploadIntervalMinutes"
          type="number"
          min="1"
          max="1440"
          class="field-input"
          :disabled="isLocked"
          placeholder="例如 30"
          @input="updateField('dnsAutoUploadIntervalMinutes', $event.target.value)"
        />
        <span class="field-hint">固定间隔或窗口轮询都会使用这个值。</span>
      </label>

      <label v-if="usesWindowRange" class="field-shell">
        <span class="field-label">窗口开始时间</span>
        <input
          :value="draft.dnsAutoUploadWindowStartTime"
          type="time"
          step="60"
          class="field-input"
          :disabled="isLocked"
          @input="updateField('dnsAutoUploadWindowStartTime', $event.target.value)"
        />
        <span class="field-hint">例如 08:00，表示此后才允许触发自动上传。</span>
      </label>

      <label v-if="usesWindowRange" class="field-shell">
        <span class="field-label">窗口结束时间</span>
        <input
          :value="draft.dnsAutoUploadWindowEndTime"
          type="time"
          step="60"
          class="field-input"
          :disabled="isLocked"
          @input="updateField('dnsAutoUploadWindowEndTime', $event.target.value)"
        />
        <span class="field-hint">例如 23:00，超出窗口后跳过后续轮询。</span>
      </label>

      <div class="field-shell md:col-span-2">
        <span class="field-label">国家 / 地区代码</span>
        <textarea
          :value="draft.dnsAutoUploadCountryCodes"
          rows="3"
          class="field-input field-textarea"
          :disabled="isLocked"
          placeholder="US&#10;JP&#10;SG"
          @input="updateField('dnsAutoUploadCountryCodes', $event.target.value)"
        />
        <span class="field-hint">建议使用 ISO 3166-1 alpha-2，两位大写代码；预览会自动去重并转成大写。</span>
        <div v-if="showPreview && parsedCountryCodes.length > 0" class="flex flex-wrap gap-2">
          <span
            v-for="countryCode in parsedCountryCodes"
            :key="countryCode"
            class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200"
          >
            {{ countryCode }}
          </span>
        </div>
      </div>

      <div class="field-shell md:col-span-2">
        <span class="field-label">记录类型</span>
        <textarea
          :value="draft.dnsAutoUploadRecordTypes"
          rows="3"
          class="field-input field-textarea"
          :disabled="isLocked"
          placeholder="A&#10;AAAA"
          @input="updateField('dnsAutoUploadRecordTypes', $event.target.value)"
        />
        <span class="field-hint">支持换行、逗号或分号分隔；下面的快捷项只会追加未出现过的类型。</span>
        <div class="flex flex-wrap gap-2">
          <button
            v-for="recordType in recordTypeSuggestions"
            :key="recordType"
            type="button"
            class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
            :disabled="isLocked"
            @click="appendRecordType(recordType)"
          >
            {{ recordType }}
          </button>
        </div>
        <div v-if="showPreview && parsedRecordTypes.length > 0" class="flex flex-wrap gap-2">
          <span
            v-for="recordType in parsedRecordTypes"
            :key="recordType"
            class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200"
          >
            {{ recordType }}
          </span>
        </div>
      </div>
    </div>

    <div class="mt-5 rounded-3xl border border-white/10 bg-slate-950/35 p-4">
      <div class="flex items-start gap-3">
        <BellRing class="mt-0.5 h-4 w-4 text-brand-300" />
        <div>
          <h4 class="text-sm font-medium text-white">通知策略</h4>
          <p class="mt-1 text-sm leading-6 text-slate-300">
            通知与调度设置解耦，方便后续接入 Telegram、Webhook 或别的告警入口。
          </p>
        </div>
      </div>

      <div class="mt-4 grid gap-4 md:grid-cols-2">
        <label class="toggle-card md:col-span-2">
          <input
            :checked="draft.dnsAutoUploadNotifyEnabled"
            type="checkbox"
            class="h-4 w-4 rounded"
            :disabled="isLocked"
            @change="updateField('dnsAutoUploadNotifyEnabled', $event.target.checked)"
          />
          <div class="flex flex-col gap-1">
            <span>启用自动上传通知</span>
            <span class="text-xs leading-5 text-slate-400">可以单独开启，和总开关分开保留配置。</span>
          </div>
        </label>

        <label class="field-shell">
          <span class="field-label">通知延迟 (分钟)</span>
          <input
            :value="draft.dnsAutoUploadNotifyDelayMinutes"
            type="number"
            min="0"
            max="1440"
            class="field-input"
            :disabled="isLocked || !draft.dnsAutoUploadNotifyEnabled"
            placeholder="例如 10"
            @input="updateField('dnsAutoUploadNotifyDelayMinutes', $event.target.value)"
          />
          <span class="field-hint">延迟一段时间再发通知，能减少刚开始执行时的噪音。</span>
        </label>
      </div>
    </div>
  </article>
</template>
