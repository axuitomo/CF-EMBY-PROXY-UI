import { useUiPreferences } from './useUiPreferences';

const THEME_LIGHT = 'light';
const THEME_DARK = 'dark';
const SYSTEM_THEME_MEDIA_QUERY = '(prefers-color-scheme: dark)';

function normalizeTheme(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized === THEME_LIGHT || normalized === THEME_DARK ? normalized : '';
}

function getSystemThemeMediaQuery() {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return null;
  try {
    return window.matchMedia(SYSTEM_THEME_MEDIA_QUERY);
  } catch {
    return null;
  }
}

function resolveSystemTheme(mediaQuery = getSystemThemeMediaQuery()) {
  if (!mediaQuery) return THEME_DARK;
  return mediaQuery.matches ? THEME_DARK : THEME_LIGHT;
}

function resolveThemeState(preferredTheme = '') {
  const normalized = normalizeTheme(preferredTheme);
  if (normalized) {
    return {
      source: 'stored',
      preference: normalized,
      resolved: normalized
    };
  }

  return {
    source: 'system',
    preference: 'system',
    resolved: resolveSystemTheme()
  };
}

function applyThemeState(themeState) {
  if (typeof document === 'undefined') return themeState;

  const resolvedTheme = themeState?.resolved === THEME_LIGHT ? THEME_LIGHT : THEME_DARK;
  const themePreference = themeState?.preference || 'system';
  const themeSource = themeState?.source || 'system';
  const targets = [document.documentElement, document.body].filter(Boolean);

  for (const target of targets) {
    target.dataset.theme = resolvedTheme;
    target.dataset.themePreference = themePreference;
    target.dataset.themeSource = themeSource;
    target.classList.toggle('theme-light', resolvedTheme === THEME_LIGHT);
    target.classList.toggle('theme-dark', resolvedTheme === THEME_DARK);
  }

  document.documentElement.style.colorScheme = resolvedTheme;
  if (document.body) {
    document.body.style.colorScheme = resolvedTheme;
  }

  return {
    source: themeSource,
    preference: themePreference,
    resolved: resolvedTheme
  };
}

function watchSystemTheme(onChange) {
  const mediaQuery = getSystemThemeMediaQuery();
  if (!mediaQuery || typeof onChange !== 'function') return () => {};

  const handleChange = () => {
    onChange(resolveSystemTheme(mediaQuery));
  };

  if (typeof mediaQuery.addEventListener === 'function') {
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }

  if (typeof mediaQuery.addListener === 'function') {
    mediaQuery.addListener(handleChange);
    return () => mediaQuery.removeListener(handleChange);
  }

  return () => {};
}

export function useTheme() {
  const uiPreferences = useUiPreferences();
  let stopSystemThemeSync = () => {};

  function readThemePreference() {
    return normalizeTheme(uiPreferences.readTheme());
  }

  function restartSystemThemeSync(preferredTheme = '') {
    stopSystemThemeSync();
    stopSystemThemeSync = () => {};

    if (normalizeTheme(preferredTheme)) return;

    stopSystemThemeSync = watchSystemTheme(() => {
      applyThemeState(resolveThemeState(''));
    });
  }

  function applyTheme(preferredTheme = '') {
    const normalizedTheme = normalizeTheme(preferredTheme);
    const themeState = applyThemeState(resolveThemeState(normalizedTheme));
    restartSystemThemeSync(normalizedTheme);
    return themeState;
  }

  function initializeTheme() {
    return applyTheme(readThemePreference());
  }

  function setTheme(value = '') {
    const normalizedTheme = normalizeTheme(value);
    uiPreferences.persistTheme(normalizedTheme);
    return applyTheme(normalizedTheme);
  }

  function cleanup() {
    stopSystemThemeSync();
    stopSystemThemeSync = () => {};
  }

  return {
    THEME_LIGHT,
    THEME_DARK,
    normalizeTheme,
    readThemePreference,
    resolveThemeState,
    applyTheme,
    initializeTheme,
    setTheme,
    cleanup
  };
}
