const UI_PREFERENCE_STORAGE_KEYS = Object.freeze({
  theme: 'theme',
  settingsExperienceMode: 'settingsExperienceMode',
  desktopSidebarCollapsed: 'desktopSidebarCollapsed',
  logUaColumnWidth: 'logUaColumnWidth',
  dnsIpPoolItems: 'dnsIpPoolItemsV1',
  dnsIpSourcePrefetchCache: 'dnsIpSourcePrefetchCacheV1'
});

function readStorageValue(key) {
  if (typeof window === 'undefined' || !window.localStorage) return '';
  try {
    return String(window.localStorage.getItem(key) || '').trim();
  } catch {
    return '';
  }
}

function writeStorageValue(key, value) {
  if (typeof window === 'undefined' || !window.localStorage) return;
  try {
    if (value === '' || value === null || value === undefined) {
      window.localStorage.removeItem(key);
      return;
    }
    window.localStorage.setItem(key, String(value));
  } catch {
    // Ignore localStorage quota / privacy mode failures.
  }
}

function normalizeSettingsExperienceMode(value = '') {
  return String(value || '').trim().toLowerCase() === 'expert' ? 'expert' : 'novice';
}

export function useUiPreferences() {
  return {
    keys: UI_PREFERENCE_STORAGE_KEYS,
    readTheme() {
      return readStorageValue(UI_PREFERENCE_STORAGE_KEYS.theme);
    },
    persistTheme(value = '') {
      const normalized = String(value || '').trim().toLowerCase();
      writeStorageValue(UI_PREFERENCE_STORAGE_KEYS.theme, normalized === 'dark' ? 'dark' : normalized === 'light' ? 'light' : '');
    },
    readSettingsExperienceMode() {
      return normalizeSettingsExperienceMode(readStorageValue(UI_PREFERENCE_STORAGE_KEYS.settingsExperienceMode));
    },
    persistSettingsExperienceMode(value = '') {
      writeStorageValue(
        UI_PREFERENCE_STORAGE_KEYS.settingsExperienceMode,
        normalizeSettingsExperienceMode(value)
      );
    },
    readDesktopSidebarCollapsed() {
      return readStorageValue(UI_PREFERENCE_STORAGE_KEYS.desktopSidebarCollapsed) === '1';
    },
    persistDesktopSidebarCollapsed(value = false) {
      writeStorageValue(UI_PREFERENCE_STORAGE_KEYS.desktopSidebarCollapsed, value === true ? '1' : '0');
    },
    readLogUaColumnWidth() {
      return readStorageValue(UI_PREFERENCE_STORAGE_KEYS.logUaColumnWidth);
    },
    persistLogUaColumnWidth(value = '') {
      writeStorageValue(UI_PREFERENCE_STORAGE_KEYS.logUaColumnWidth, value);
    },
    readDnsIpPoolItems() {
      const rawValue = readStorageValue(UI_PREFERENCE_STORAGE_KEYS.dnsIpPoolItems);
      if (!rawValue) return [];
      try {
        const parsed = JSON.parse(rawValue);
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    },
    persistDnsIpPoolItems(value = []) {
      writeStorageValue(UI_PREFERENCE_STORAGE_KEYS.dnsIpPoolItems, JSON.stringify(Array.isArray(value) ? value : []));
    },
    readDnsIpSourcePrefetchCache() {
      const rawValue = readStorageValue(UI_PREFERENCE_STORAGE_KEYS.dnsIpSourcePrefetchCache);
      if (!rawValue) return null;
      try {
        return JSON.parse(rawValue);
      } catch {
        return null;
      }
    },
    persistDnsIpSourcePrefetchCache(value = null) {
      writeStorageValue(
        UI_PREFERENCE_STORAGE_KEYS.dnsIpSourcePrefetchCache,
        value && typeof value === 'object' ? JSON.stringify(value) : ''
      );
    }
  };
}
