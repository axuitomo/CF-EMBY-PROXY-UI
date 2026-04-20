export const DNS_AUTO_UPLOAD_FIELD_KEYS = [
  'dnsAutoUploadEnabled',
  'dnsAutoUploadScheduleMode',
  'dnsAutoUploadClockTimes',
  'dnsAutoUploadIntervalMinutes',
  'dnsAutoUploadWindowStartTime',
  'dnsAutoUploadWindowEndTime',
  'dnsAutoUploadTopN',
  'dnsAutoUploadCountryCodes',
  'dnsAutoUploadRecordTypes',
  'dnsAutoUploadNotifyEnabled',
  'dnsAutoUploadNotifyDelayMinutes'
];

export const DEFAULT_DNS_AUTO_UPLOAD_SCHEDULE_MODE_OPTIONS = [
  {
    value: 'clock_times',
    label: '按时刻执行',
    hint: '使用 dnsAutoUploadClockTimes，支持每行或逗号分隔的 HH:mm。'
  },
  {
    value: 'interval',
    label: '固定间隔',
    hint: '使用 dnsAutoUploadIntervalMinutes，按固定分钟间隔轮询。'
  },
  {
    value: 'window',
    label: '时窗轮询',
    hint: '在开始/结束时间窗口内，按 interval 分钟执行。'
  }
];

export const DEFAULT_DNS_AUTO_UPLOAD_RECORD_TYPE_SUGGESTIONS = ['A', 'AAAA', 'CNAME', 'HTTPS', 'TXT'];

export function createEmptyDnsAutoUploadForm() {
  return {
    dnsAutoUploadEnabled: false,
    dnsAutoUploadScheduleMode: 'clock_times',
    dnsAutoUploadClockTimes: '',
    dnsAutoUploadIntervalMinutes: '',
    dnsAutoUploadWindowStartTime: '',
    dnsAutoUploadWindowEndTime: '',
    dnsAutoUploadTopN: '',
    dnsAutoUploadCountryCodes: '',
    dnsAutoUploadRecordTypes: '',
    dnsAutoUploadNotifyEnabled: false,
    dnsAutoUploadNotifyDelayMinutes: ''
  };
}

export function hydrateDnsAutoUploadForm(source = null) {
  const raw = isPlainObject(source) ? source : {};

  return {
    dnsAutoUploadEnabled: normalizeBoolean(raw.dnsAutoUploadEnabled, false),
    dnsAutoUploadScheduleMode: normalizeScalarText(raw.dnsAutoUploadScheduleMode, 'clock_times'),
    dnsAutoUploadClockTimes: normalizeListText(raw.dnsAutoUploadClockTimes),
    dnsAutoUploadIntervalMinutes: normalizeScalarText(raw.dnsAutoUploadIntervalMinutes),
    dnsAutoUploadWindowStartTime: normalizeScalarText(raw.dnsAutoUploadWindowStartTime),
    dnsAutoUploadWindowEndTime: normalizeScalarText(raw.dnsAutoUploadWindowEndTime),
    dnsAutoUploadTopN: normalizeScalarText(raw.dnsAutoUploadTopN),
    dnsAutoUploadCountryCodes: normalizeListText(raw.dnsAutoUploadCountryCodes),
    dnsAutoUploadRecordTypes: normalizeListText(raw.dnsAutoUploadRecordTypes),
    dnsAutoUploadNotifyEnabled: normalizeBoolean(raw.dnsAutoUploadNotifyEnabled, false),
    dnsAutoUploadNotifyDelayMinutes: normalizeScalarText(raw.dnsAutoUploadNotifyDelayMinutes)
  };
}

export function cloneDnsAutoUploadForm(source = null) {
  return { ...hydrateDnsAutoUploadForm(source) };
}

export function mergeDnsAutoUploadForm(base = null, subset = null) {
  const nextForm = isPlainObject(base) ? { ...base } : {};
  return {
    ...nextForm,
    ...hydrateDnsAutoUploadForm(subset)
  };
}

export function serializeDnsAutoUploadForm(value = null) {
  return JSON.stringify(hydrateDnsAutoUploadForm(value));
}

export function parseDnsAutoUploadClockTimes(value = '') {
  return parseLooseTextList(value);
}

export function parseDnsAutoUploadCountryCodes(value = '') {
  return [...new Set(
    parseLooseTextList(value)
      .map((entry) => String(entry || '').trim().toUpperCase())
      .filter(Boolean)
  )];
}

export function parseDnsAutoUploadRecordTypes(value = '') {
  return [...new Set(
    parseLooseTextList(value)
      .map((entry) => String(entry || '').trim().toUpperCase())
      .filter(Boolean)
  )];
}

function normalizeBoolean(value, fallback = false) {
  if (value === true || value === 'true' || value === 1 || value === '1') return true;
  if (value === false || value === 'false' || value === 0 || value === '0') return false;
  return fallback;
}

function normalizeScalarText(value, fallback = '') {
  if (value === null || value === undefined) return fallback;
  return String(value);
}

function normalizeListText(value, fallback = '') {
  if (value === null || value === undefined || value === '') return fallback;
  if (Array.isArray(value)) return parseLooseTextList(value).join('\n');
  return String(value);
}

function parseLooseTextList(value = '') {
  if (Array.isArray(value)) {
    return [...new Set(
      value
        .map((entry) => String(entry || '').trim())
        .filter(Boolean)
    )];
  }

  return [...new Set(
    String(value || '')
      .split(/[\r\n,，;；|]+/)
      .map((entry) => entry.trim())
      .filter(Boolean)
  )];
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
