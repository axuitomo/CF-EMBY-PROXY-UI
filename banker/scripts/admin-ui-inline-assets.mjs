const TAILWIND_CDN_VERSION = "3.4.17";
const VUE_CDN_VERSION = "3.5.32";
const LUCIDE_CDN_VERSION = "1.8.0";
const CHART_CDN_VERSION = "4.4.7";

function buildAdminCdnHeadHtml() {
  return [
    '<script>tailwind.config={darkMode:"class"};</script>',
    `<script src="https://cdn.tailwindcss.com/${TAILWIND_CDN_VERSION}"></script>`,
    `<script src="https://cdn.jsdelivr.net/npm/vue@${VUE_CDN_VERSION}/dist/vue.global.prod.js"></script>`,
    `<script src="https://cdn.jsdelivr.net/npm/lucide@${LUCIDE_CDN_VERSION}/dist/umd/lucide.min.js"></script>`,
    `<script src="https://cdn.jsdelivr.net/npm/chart.js@${CHART_CDN_VERSION}/dist/chart.umd.min.js"></script>`
  ].join("");
}

export async function buildAdminInlineAssetBundle() {
  return {
    headHtml: buildAdminCdnHeadHtml(),
    lucideRegistrySource: ""
  };
}
