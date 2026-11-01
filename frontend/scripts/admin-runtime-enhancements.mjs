const ADMIN_RUNTIME_ENHANCEMENT_STYLE = `<style data-admin-runtime-enhancements="1">
:root{--ui-control-radius-px:var(--ui-radius-px,10px);--admin-toolbar-hover-bg:rgb(var(--ui-c-n-400) / .14);--admin-toolbar-hover-bg-dark:rgb(var(--ui-c-n-700) / .68)}
:root{--ui-c-white:255 255 255;--ui-c-n-50:248 250 252;--ui-c-n-100:241 245 249;--ui-c-n-200:226 232 240;--ui-c-n-300:203 213 225;--ui-c-n-400:148 163 184;--ui-c-n-500:100 116 139;--ui-c-n-600:71 85 105;--ui-c-n-700:51 65 85;--ui-c-n-800:30 41 59;--ui-c-n-900:15 23 42;--ui-c-n-950:2 6 23;--ui-c-a-50:239 246 255;--ui-c-a-100:219 234 254;--ui-c-a-200:191 219 254;--ui-c-a-300:147 197 253;--ui-c-a-400:96 165 250;--ui-c-a-500:59 130 246;--ui-c-a-600:37 99 235;--ui-c-a-700:29 78 216;--ui-c-a-800:30 64 175;--ui-c-a-900:30 58 138;--ui-c-a-950:23 37 84;--ui-surface-panel:255 255 255;--ui-surface-soft:248 250 252;--ui-surface-dark:15 23 42;--ui-border-soft:226 232 240;--ui-border-strong:203 213 225;--ui-border-dark:51 65 85;--ui-text-strong:15 23 42;--ui-text-dark:248 251 255;--ui-shadow-brand:0 10px 22px rgba(37,99,235,0.16);--ui-shadow-brand-hover:0 14px 28px rgba(37,99,235,0.18);--ui-shadow-brand-soft:0 6px 16px rgba(59,130,246,0.08);--ui-shadow-card-hover:0 18px 36px rgba(15,23,42,0.07);--ui-shadow-card-hover-dark:0 16px 32px rgba(2,6,23,0.34);--ui-shadow-surface:0 0 0 1px rgba(226,232,240,0.92),0 10px 22px rgba(15,23,42,0.05);--ui-shadow-surface-dark:0 0 0 1px rgba(51,65,85,0.88),0 10px 22px rgba(2,6,23,0.3);--ui-shadow-surface-hover:0 0 0 1px rgba(203,213,225,0.98),0 14px 28px rgba(15,23,42,0.08);--ui-shadow-surface-hover-dark:0 0 0 1px rgba(71,85,105,0.92),0 16px 30px rgba(2,6,23,0.38);--ui-chart-accent:59,130,246;--ui-chart-line:#3b82f6;--ui-chart-axis:#0f172a;--ui-chart-axis-dark:#e2e8f0;--ui-chart-tick:#64748b;--ui-chart-tick-dark:#94a3b8;--ui-chart-grid:rgba(148,163,184,0.22);--ui-chart-grid-dark:rgba(71,85,105,0.35);--ui-accent-shadow:rgba(59,130,246,0.08)}
html[data-theme="claude"]{--ui-c-white:250 249 245;--ui-c-n-50:245 244 237;--ui-c-n-100:237 236 228;--ui-c-n-200:232 230 220;--ui-c-n-300:209 207 197;--ui-c-n-400:176 174 165;--ui-c-n-500:135 134 127;--ui-c-n-600:94 93 89;--ui-c-n-700:77 76 72;--ui-c-n-800:48 48 46;--ui-c-n-900:20 20 19;--ui-c-n-950:14 14 13;--ui-c-a-50:250 243 239;--ui-c-a-100:246 228 220;--ui-c-a-200:237 199 183;--ui-c-a-300:224 164 140;--ui-c-a-400:217 119 87;--ui-c-a-500:201 100 66;--ui-c-a-600:180 85 58;--ui-c-a-700:150 69 47;--ui-c-a-800:122 56 38;--ui-c-a-900:95 44 30;--ui-c-a-950:61 28 18;--ui-surface-panel:250 249 245;--ui-surface-soft:245 244 237;--ui-surface-dark:20 20 19;--ui-border-soft:232 230 220;--ui-border-strong:209 207 197;--ui-border-dark:48 48 46;--ui-text-strong:20 20 19;--ui-text-dark:250 249 245;--ui-shadow-brand:0 10px 22px rgba(201,100,66,0.18);--ui-shadow-brand-hover:0 14px 28px rgba(201,100,66,0.20);--ui-shadow-brand-soft:0 6px 16px rgba(217,119,87,0.10);--ui-shadow-card-hover:0 18px 36px rgba(20,20,19,0.07);--ui-shadow-card-hover-dark:0 16px 32px rgba(0,0,0,0.34);--ui-shadow-surface:0 0 0 1px rgba(232,230,220,0.92),0 10px 22px rgba(20,20,19,0.05);--ui-shadow-surface-dark:0 0 0 1px rgba(48,48,46,0.88),0 10px 22px rgba(0,0,0,0.3);--ui-shadow-surface-hover:0 0 0 1px rgba(209,207,197,0.98),0 14px 28px rgba(20,20,19,0.08);--ui-shadow-surface-hover-dark:0 0 0 1px rgba(77,76,72,0.92),0 16px 30px rgba(0,0,0,0.38);--ui-chart-accent:201,100,66;--ui-chart-line:#c96442;--ui-chart-axis:#141413;--ui-chart-axis-dark:#e8e6dc;--ui-chart-tick:#4a4944;--ui-chart-tick-dark:#c6c4b9;--ui-chart-grid:rgba(94,93,89,0.34);--ui-chart-grid-dark:rgba(170,167,154,0.32);--ui-accent-shadow:rgba(201,100,66,0.08)}
#app-shell .rounded-control,
#app-shell [role="tab"]{border-radius:max(16px,calc(var(--ui-control-radius-px) + 2px)) !important}
#app-shell [role="tab"]{position:relative;isolation:isolate}
#app-shell [data-admin-toolbar-group="title"]{min-width:0;flex:1 1 auto}
#app-shell [data-admin-page-title="1"]{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#app-shell [data-admin-toolbar-group="actions"]{display:flex;align-items:center;justify-content:flex-end;gap:.25rem;flex-shrink:0;position:relative;z-index:2;white-space:nowrap}
#app-shell [data-admin-toolbar-group="actions"]>*{margin-left:0 !important;margin-right:0 !important}
#app-shell [data-admin-brand-mark="1"]{position:relative;overflow:hidden}
#app-shell [data-admin-brand-mark="1"] svg{display:block;width:1.1rem;height:1.1rem;color:currentColor;filter:drop-shadow(0 1px 2px rgb(var(--ui-c-n-900) / .16))}
#app-shell [data-admin-toolbar-action]{display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;width:2.5rem;height:2.5rem;padding:0;border:0 !important;background:transparent !important;color:rgb(var(--ui-c-n-600));box-shadow:none !important;border-radius:max(14px,var(--ui-control-radius-px));transition:background-color .18s ease,color .18s ease,transform .18s ease,opacity .18s ease}
.dark #app-shell [data-admin-toolbar-action]{color:rgb(var(--ui-c-n-300))}
#app-shell [data-admin-toolbar-action]:hover{transform:translateY(-1px);background:var(--admin-toolbar-hover-bg) !important;color:#ea580c}
.dark #app-shell [data-admin-toolbar-action]:hover{background:var(--admin-toolbar-hover-bg-dark) !important;color:#fb923c}
#app-shell [data-admin-toolbar-action]:focus-visible{outline:none;background:var(--admin-toolbar-hover-bg) !important;box-shadow:0 0 0 2px rgba(249,115,22,.2) !important}
.dark #app-shell [data-admin-toolbar-action]:focus-visible{background:var(--admin-toolbar-hover-bg-dark) !important;box-shadow:0 0 0 2px rgba(251,146,60,.24) !important}
#app-shell [data-admin-toolbar-action] i[data-lucide],
#app-shell [data-admin-toolbar-action] svg{width:1.1rem;height:1.1rem}
#app-shell [data-admin-toolbar-action="theme"][data-theme-state="dark"]{color:#ea580c}
.dark #app-shell [data-admin-toolbar-action="theme"][data-theme-state="dark"]{color:#fb923c}
#app-shell [data-admin-toolbar-action="theme"][data-theme-state="light"]{color:#0369a1}
.dark #app-shell [data-admin-toolbar-action="theme"][data-theme-state="light"]{color:#7dd3fc}
body.bg-slate-50,body.antialiased{background:rgb(var(--ui-c-n-50)) !important;color:rgb(var(--ui-c-n-900)) !important}
.dark body,.dark body.antialiased{background:rgb(var(--ui-c-n-950)) !important;color:rgb(var(--ui-c-n-200)) !important}
#app-shell{min-width:0;background:rgb(var(--ui-c-n-50));color:rgb(var(--ui-c-n-900))}
.dark #app-shell{background:rgb(var(--ui-c-n-950));color:rgb(var(--ui-c-n-200))}
#view-nodes .node-toolbar-primary-btn,
#view-nodes .node-tag-filter-trigger,
#view-nodes .node-toolbar-search,
#view-nodes .node-tag-filter-chip,
#view-nodes .node-action-btn,
#node-modal .node-modal-primary-btn,
#node-modal .node-modal-secondary-btn,
#view-settings .set-tab{position:relative;z-index:1}
#view-nodes .node-toolbar-primary-btn,
#view-nodes .node-tag-filter-trigger,
#view-nodes .node-toolbar-search,
#view-nodes .node-tag-filter-chip,
#view-nodes .node-action-btn,
#view-nodes .rounded-control,
#node-modal .node-modal-primary-btn,
#node-modal .node-modal-secondary-btn,
#view-logs .rounded-control,
#view-dns .rounded-control,
#view-settings .set-tab{border-radius:max(16px,calc(var(--ui-control-radius-px) + 4px)) !important}
#view-nodes .node-toolbar-primary-btn,
#view-nodes .node-tag-filter-trigger,
#view-nodes .node-toolbar-search,
#view-nodes .node-action-btn,
#node-modal .node-modal-primary-btn,
#node-modal .node-modal-secondary-btn{display:inline-flex;align-items:center;justify-content:center;isolation:isolate}
#view-nodes .node-tag-filter-panel-shell{position:relative;z-index:4}
#node-modal [data-admin-node-advanced="1"]{overflow:hidden;border:1px solid rgb(var(--ui-c-n-200));border-radius:max(16px,calc(var(--ui-control-radius-px) + 6px));background:rgb(var(--ui-c-n-50) / .72)}
.dark #node-modal [data-admin-node-advanced="1"]{border-color:rgb(var(--ui-c-n-700));background:rgb(var(--ui-c-n-950) / .34)}
#node-modal [data-admin-node-advanced="1"]>summary{display:flex;align-items:center;justify-content:space-between;gap:.75rem;padding:.75rem 1rem;cursor:pointer;list-style:none;color:rgb(var(--ui-c-n-700));font-size:.875rem;font-weight:600;user-select:none}
.dark #node-modal [data-admin-node-advanced="1"]>summary{color:rgb(var(--ui-c-n-200))}
#node-modal [data-admin-node-advanced="1"]>summary::-webkit-details-marker{display:none}
#node-modal [data-admin-node-advanced="1"]>summary svg{width:1rem;height:1rem;transition:transform .18s ease}
#node-modal [data-admin-node-advanced="1"][open]>summary svg{transform:rotate(180deg)}
#node-modal [data-admin-node-advanced-content="1"]{display:grid;gap:1rem;padding:.75rem 1.25rem 1.25rem;border-top:1px solid rgb(var(--ui-c-n-200))}
.dark #node-modal [data-admin-node-advanced-content="1"]{border-color:rgb(var(--ui-c-n-700))}
#node-modal [data-admin-node-advanced-content="1"],#node-modal [data-admin-node-advanced-fields="1"],#node-modal [data-admin-node-advanced-headers="1"]{min-width:0;max-width:100%}
#node-modal [data-admin-node-advanced-fields="1"]{padding-top:1rem}
#node-modal [data-admin-node-advanced-fields="1"]>*{min-width:0}
#node-modal [data-admin-node-advanced-fields="1"] input,#node-modal [data-admin-node-advanced-fields="1"] select{min-width:0;max-width:100%;width:100%}
#node-modal [data-admin-node-advanced-headers="1"]{margin:0;background:rgb(var(--ui-c-white));min-width:0}
#node-modal [data-admin-node-advanced-headers="1"] #headers-container>div{min-width:0}
.dark #node-modal [data-admin-node-advanced-headers="1"]{background:rgb(var(--ui-c-n-900) / .72)}
#node-modal>div[data-ui-dialog-surface="1"]{padding:1.5rem !important}
#node-modal #node-modal-title{margin-bottom:1.25rem !important;font-size:1.125rem;line-height:1.5rem}
#node-modal form{max-height:calc(86vh - env(safe-area-inset-bottom) - env(safe-area-inset-top)) !important}
#node-modal form>*+*{margin-top:1.25rem !important}
#node-modal form>[class*="grid"]{gap:1rem !important;align-items:start}
#node-modal form label{margin-bottom:.375rem}
#node-modal form p[class*="text-xs"]{margin-top:.375rem;line-height:1.15rem}
#node-modal form input:not([type="checkbox"]):not([type="radio"]),
#node-modal form select{min-height:2.75rem;padding-top:.5rem !important;padding-bottom:.5rem !important}
#node-modal form .rounded-2xl.border{padding:1rem !important}
#node-modal #node-lines-container{gap:.625rem}
#node-modal #node-lines-container>[data-node-line-row="1"]{padding:.5rem .75rem !important}
#node-modal [data-admin-node-lines-panel="1"]>div:first-child>div:first-child{min-width:0;flex:1 1 auto}
#node-modal [data-admin-node-lines-panel="1"]>div:first-child>div:last-child{flex:0 0 auto;white-space:nowrap}
#node-modal [data-admin-node-lines-panel="1"]>div:first-child>div:last-child button{flex-shrink:0;white-space:nowrap}
#node-modal [data-admin-node-lines-panel="1"]>div:first-child>div:first-child>label{display:inline-block;margin-bottom:0}
#node-modal [data-admin-node-line-count="1"]{display:inline-block;margin-left:.5rem;font-size:.6875rem;line-height:1.15rem;color:rgb(var(--ui-c-n-400))}
#node-modal form>div:last-child{margin-top:1.25rem !important;gap:1rem !important;padding:.75rem 0 !important;justify-content:flex-end}
#node-modal form>div:last-child>button{flex:0 0 auto !important;min-width:7.5rem;min-height:3rem;padding-top:0 !important;padding-bottom:0 !important}
#node-modal [data-admin-hint="1"]{display:-webkit-box;-webkit-line-clamp:1;-webkit-box-orient:vertical;overflow:hidden}
#node-modal [data-admin-hint="1"]~[data-admin-hint="1"]{display:none}
#node-modal [data-admin-hint-open="1"]>[data-admin-hint="1"]{display:block;overflow:visible;padding-right:0}
#node-modal [data-admin-hint-field="1"]{position:relative}
#node-modal [data-admin-hint-field="1"]>[data-admin-hint="1"]{padding-right:3rem}
#node-modal [data-admin-hint-toggle="1"]{position:absolute;right:0;bottom:.1rem;padding:0;border:0;background:transparent;font-size:.6875rem;line-height:1.05rem;color:rgb(var(--ui-c-n-400));cursor:pointer}
#node-modal [data-admin-hint-toggle="1"]:hover{color:rgb(var(--ui-c-n-600))}
.dark #node-modal [data-admin-hint-toggle="1"]{color:rgb(var(--ui-c-n-500))}
.dark #node-modal [data-admin-hint-toggle="1"]:hover{color:rgb(var(--ui-c-n-300))}
#view-settings [data-admin-credential-test="1"] button{border:1px solid rgb(var(--ui-c-n-200));padding:.375rem .75rem;font-size:.75rem;line-height:1.15rem;font-weight:500;color:rgb(var(--ui-c-n-600));background:transparent;cursor:pointer}
#view-settings [data-admin-credential-test="1"] button:hover{border-color:rgb(var(--ui-c-a-300));color:rgb(var(--ui-c-a-600))}
#view-settings [data-admin-credential-test="1"] button:disabled{opacity:.55;cursor:progress}
.dark #view-settings [data-admin-credential-test="1"] button{border-color:rgb(var(--ui-c-n-700));color:rgb(var(--ui-c-n-300))}
#view-settings [data-credential-test-result="1"][data-tone="ok"]{color:rgb(var(--ui-c-a-600))}
#view-settings [data-credential-test-result="1"][data-tone="error"]{color:#c0392b}
#node-modal [data-admin-node-basic-grid="1"]{grid-template-columns:repeat(2,minmax(0,1fr)) !important}
#node-modal [data-admin-node-meta-grid="1"]{grid-template-columns:minmax(0,1.35fr) minmax(0,1fr) minmax(15rem,1fr) !important}
#node-modal [data-admin-node-entry-field="1"] p{margin-bottom:0}
#node-modal [data-admin-node-stream-field="1"]{min-width:0}
/* 标签颜色内嵌进标签输入框：颜色选择器贴在输入框右侧，只留一条分隔线。*/
#node-modal [data-admin-node-tag-field="1"]{position:relative;display:block !important;min-width:0}
#node-modal [data-admin-node-tag-field="1"]>#form-tag{width:100%;padding-right:6.25rem}
/* 原生 select 的弹出菜单由系统绘制，选项颜色改不动（Windows 上是系统强调色），
   所以把 select 留作唯一状态源并隐藏，另画一个按钮 + 面板按真实标签色显示。*/
#node-modal [data-admin-node-tag-field="1"]>#form-tag-color{position:absolute;width:1px;height:1px;min-height:0;padding:0;margin:0;border:0;opacity:0;pointer-events:none}
#node-modal [data-admin-node-tag-color-trigger="1"]{position:absolute;top:.3125rem;right:.3125rem;bottom:.3125rem;display:inline-flex;align-items:center;justify-content:space-between;gap:.25rem;width:5.5rem;padding:0 .375rem 0 .5rem;border:0;border-left:1px solid rgb(var(--ui-c-n-200));border-radius:0;background:transparent;font-size:.75rem;line-height:1.25rem;color:rgb(var(--ui-c-n-600));cursor:pointer;text-align:left}
.dark #node-modal [data-admin-node-tag-color-trigger="1"]{border-left-color:rgb(var(--ui-c-n-700));color:rgb(var(--ui-c-n-300))}
#node-modal [data-admin-node-tag-color-trigger="1"]:focus-visible{outline:2px solid rgb(var(--ui-c-a-500) / .45);outline-offset:-2px;border-radius:max(8px,var(--ui-control-radius-px))}
[data-admin-node-tag-color-panel="1"]{position:fixed;z-index:2147483000;min-width:7rem;padding:.25rem;border:1px solid rgb(var(--ui-c-n-200));border-radius:12px;background:rgb(var(--ui-c-white));box-shadow:0 16px 32px rgb(var(--ui-c-n-900) / .16)}
.dark [data-admin-node-tag-color-panel="1"]{border-color:rgb(var(--ui-c-n-700));background:rgb(var(--ui-c-n-900));box-shadow:0 16px 32px rgb(0 0 0 / .42)}
[data-admin-node-tag-color-option="1"]{display:flex;align-items:center;gap:.5rem;width:100%;padding:.375rem .5rem;border:0;border-radius:8px;background:transparent;font-size:.8125rem;text-align:left;cursor:pointer}
[data-admin-node-tag-color-option="1"]:hover{background:rgb(var(--ui-c-n-100))}
.dark [data-admin-node-tag-color-option="1"]:hover{background:rgb(var(--ui-c-n-800))}
[data-admin-node-tag-color-option="1"][aria-selected="true"]{background:rgb(var(--ui-c-n-100));font-weight:600}
.dark [data-admin-node-tag-color-option="1"][aria-selected="true"]{background:rgb(var(--ui-c-n-800))}
[data-admin-node-tag-color-swatch="1"]{display:inline-block;flex:0 0 auto;width:.75rem;height:.75rem;border-radius:4px;border:1px solid currentColor}
@media (max-width:767px){#node-modal [data-admin-node-basic-grid="1"],#node-modal [data-admin-node-meta-grid="1"],#node-modal [data-admin-node-advanced-fields="1"]{grid-template-columns:minmax(0,1fr) !important}#node-modal [data-admin-node-advanced-headers="1"] #headers-container>div{flex-wrap:wrap}#node-modal [data-admin-node-advanced-headers="1"] #headers-container>div>input{flex:1 1 100%;width:100%}#node-modal [data-admin-node-advanced-headers="1"] #headers-container>div>button{margin-left:auto}}
@media (max-width:767px){#node-modal [data-admin-node-lines-panel="1"]>div:first-child{align-items:stretch;flex-direction:column}#node-modal [data-admin-node-lines-panel="1"]>div:first-child>div:first-child,#node-modal [data-admin-node-lines-panel="1"]>div:first-child>div:last-child{width:100%}#node-modal [data-admin-node-lines-panel="1"]>div:first-child>div:last-child button{flex:1 1 0;min-width:0}}
@media (max-width:767px){#node-modal form>div:last-child>button{flex:1 1 0 !important;min-width:0}}
@media (min-width:768px){#node-modal{max-width:72rem}#node-modal [data-admin-node-lines-head="1"],#node-modal [data-admin-node-line-grid="1"]{grid-template-columns:88px minmax(0,1fr) minmax(0,1.8fr) 104px 88px 176px !important}}
#view-nodes [data-admin-node-toolbar="1"]{display:grid;grid-template-columns:minmax(0,1fr);gap:1rem;align-items:start}
#view-nodes [data-admin-node-toolbar-main="1"]{width:100%;max-width:none;min-width:0}
#view-nodes [data-admin-node-toolbar-row="1"]{display:grid;grid-template-columns:max-content max-content minmax(15rem,1fr);align-items:center;gap:.5rem;width:100%}
#view-nodes [data-admin-node-toolbar-actions="1"]{display:grid;grid-template-columns:repeat(4,max-content);align-items:center;justify-content:start;gap:.5rem;width:auto}
#view-nodes [data-admin-node-toolbar-actions="1"]>*{width:auto;min-height:2.5rem;margin:0}
.dark #view-nodes .node-toolbar-primary-btn,
.dark #node-modal .node-modal-primary-btn{background:rgb(var(--ui-c-a-600)) !important;color:rgb(var(--ui-c-white)) !important;box-shadow:0 10px 24px rgb(var(--ui-c-a-600) / .22) !important}
.dark #view-nodes .node-toolbar-primary-btn:hover,
.dark #node-modal .node-modal-primary-btn:hover{background:rgb(var(--ui-c-a-700)) !important}
.dark #view-nodes .node-tag-filter-trigger,
.dark #view-nodes .node-toolbar-search,
.dark #view-nodes .node-tag-filter-chip,
.dark #view-nodes .node-action-btn,
.dark #node-modal .node-modal-secondary-btn{background:rgb(var(--ui-c-n-900) / .88) !important;color:rgb(var(--ui-c-n-200)) !important;border-color:rgb(var(--ui-c-n-600) / .82) !important;box-shadow:none !important}
.dark #view-nodes .node-card-shell,
.dark #view-nodes .node-tag-filter-panel-shell,
.dark #node-modal>div{background:rgb(var(--ui-c-n-900)) !important;border-color:rgb(var(--ui-c-n-800)) !important}
#view-settings{--settings-surface:rgb(var(--ui-c-white));--settings-soft:rgb(var(--ui-c-n-50));--settings-border:#dbe3ee;--settings-border-strong:rgb(var(--ui-c-n-300));overflow-x:hidden}
.dark #view-settings{--settings-surface:rgb(var(--ui-c-n-900));--settings-soft:#111827;--settings-border:rgb(var(--ui-c-n-700));--settings-border-strong:rgb(var(--ui-c-n-600))}
#view-settings,#view-settings .settings-view-layout,#view-settings #settings-forms,#settings-forms>[id^="set-"]{min-width:0;min-height:0}
#view-settings .settings-view-layout{align-items:flex-start;overflow-x:hidden}
#view-settings #settings-forms{flex:1 1 auto;min-width:0}
#settings-forms>[id^="set-"]>.settings-block.h-full{height:auto;min-height:0}
#view-settings .ui-settings-panel,
#view-settings .settings-nav-shell,
#view-settings .settings-block,
#view-settings .settings-list-shell{background:var(--settings-surface) !important;border-color:var(--settings-border) !important;background-image:none !important;box-shadow:none !important}
#view-settings .settings-summary-tile{border:1px solid var(--settings-border) !important;border-radius:max(16px,calc(var(--ui-control-radius-px) + 4px)) !important;background:var(--settings-soft) !important;padding:.875rem 1rem;box-shadow:none !important}
#view-settings .settings-worker-html-update-card [data-admin-worker-html-grid="1"]{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem}
#view-settings .settings-worker-html-update-card [data-admin-worker-html-file="1"]{display:grid;gap:.5rem;min-width:0;padding:1rem;border:1px solid var(--settings-border);border-radius:max(14px,var(--ui-control-radius-px));background:var(--settings-soft)}
#view-settings .settings-worker-html-update-card [data-admin-worker-html-file="1"] input{width:100%;min-width:0}
#view-settings .settings-worker-html-update-card [data-admin-worker-html-file-meta="1"],
#view-settings .settings-worker-html-update-card [data-admin-worker-html-status="1"]{overflow-wrap:anywhere}
#view-settings .settings-worker-html-update-card [data-admin-worker-html-actions="1"]{display:flex;align-items:center;justify-content:flex-end;gap:.5rem;padding-top:.25rem}
#view-settings .settings-worker-html-update-card [data-admin-worker-html-actions="1"] button{min-height:2.5rem}
/* 文件选择框：::file-selector-button 的完整样式原本只写在 claude 皮肤下，
   经典皮肤拿到的是浏览器默认（透明背景 + 黑边），"Choose File" 看着像裸文字。*/
#view-settings .settings-worker-html-update-card [data-admin-worker-file-input="1"],
#view-settings .settings-worker-html-update-card [data-admin-index-file-input="1"]{display:block;width:100%;min-width:0;max-width:100%;padding:.375rem;border:1px solid var(--settings-border);border-radius:max(12px,var(--ui-control-radius-px));background:var(--settings-surface);color:rgb(var(--ui-c-n-700));font-size:.8125rem;line-height:1.25rem;cursor:pointer}
.dark #view-settings .settings-worker-html-update-card [data-admin-worker-file-input="1"],
.dark #view-settings .settings-worker-html-update-card [data-admin-index-file-input="1"]{color:rgb(var(--ui-c-n-200))}
#view-settings .settings-worker-html-update-card [data-admin-worker-file-input="1"]::file-selector-button,
#view-settings .settings-worker-html-update-card [data-admin-index-file-input="1"]::file-selector-button{margin-right:.625rem;padding:.375rem .875rem;border:1px solid var(--settings-border-strong);border-radius:max(10px,calc(var(--ui-control-radius-px) - 2px));background:rgb(var(--ui-c-a-600));color:rgb(var(--ui-c-white));font-size:.8125rem;font-weight:600;line-height:1.25rem;cursor:pointer;transition:background-color .18s ease,border-color .18s ease}
#view-settings .settings-worker-html-update-card [data-admin-worker-file-input="1"]::file-selector-button:hover,
#view-settings .settings-worker-html-update-card [data-admin-index-file-input="1"]::file-selector-button:hover{background:rgb(var(--ui-c-a-700))}
#view-settings .settings-worker-html-update-card [data-admin-worker-file-input="1"]:focus-visible,
#view-settings .settings-worker-html-update-card [data-admin-index-file-input="1"]:focus-visible{outline:2px solid rgb(var(--ui-c-a-500) / .45);outline-offset:2px}
#view-settings .ui-block-head,
#view-settings .settings-nav-shell .border-b,
#view-settings #settings-forms>div>.ui-settings-panel+.ui-settings-panel{border-color:var(--settings-border) !important}
#view-settings .settings-secondary-btn,
#view-settings .settings-secondary-label,
#view-settings button[class*="border-slate-200"],
#view-settings button[class*="border-slate-300"],
#view-settings label[class*="border-slate-200"],
#view-settings label[class*="bg-slate-200"]{display:inline-flex;align-items:center;justify-content:center;border-radius:max(14px,var(--ui-control-radius-px)) !important;background:var(--settings-soft) !important;border:1px solid var(--settings-border) !important;color:rgb(var(--ui-c-n-700)) !important;box-shadow:none !important;background-image:none !important}
.dark #view-settings .settings-secondary-btn,
.dark #view-settings .settings-secondary-label,
.dark #view-settings button[class*="border-slate-200"],
.dark #view-settings button[class*="border-slate-300"],
.dark #view-settings label[class*="border-slate-200"],
.dark #view-settings label[class*="bg-slate-200"]{background:var(--settings-soft) !important;border-color:var(--settings-border) !important;color:rgb(var(--ui-c-n-200)) !important}
#view-settings .settings-secondary-btn:hover,
#view-settings .settings-secondary-label:hover,
#view-settings button[class*="border-slate-200"]:hover,
#view-settings button[class*="border-slate-300"]:hover,
#view-settings label[class*="border-slate-200"]:hover,
#view-settings label[class*="bg-slate-200"]:hover{background:var(--settings-surface) !important;border-color:var(--settings-border-strong) !important;color:rgb(var(--ui-c-n-900)) !important}
.dark #view-settings .settings-secondary-btn:hover,
.dark #view-settings .settings-secondary-label:hover,
.dark #view-settings button[class*="border-slate-200"]:hover,
.dark #view-settings button[class*="border-slate-300"]:hover,
.dark #view-settings label[class*="border-slate-200"]:hover,
.dark #view-settings label[class*="bg-slate-200"]:hover{background:#162033 !important;border-color:var(--settings-border-strong) !important;color:rgb(var(--ui-c-n-50)) !important}
#view-settings .set-tab{background:var(--settings-surface) !important;border-color:var(--settings-border) !important;color:rgb(var(--ui-c-n-600)) !important;box-shadow:none !important}
#view-settings .set-tab:hover{background:var(--settings-surface) !important;border-color:var(--settings-border-strong) !important;color:rgb(var(--ui-c-n-900)) !important}
.dark #view-settings .set-tab{background:var(--settings-surface) !important;color:rgb(var(--ui-c-n-300)) !important}
.dark #view-settings .set-tab:hover{background:#162033 !important;color:rgb(var(--ui-c-white)) !important}
#view-settings .set-tab[aria-selected="true"]{background:var(--settings-surface) !important;border-color:rgb(var(--ui-c-a-200)) !important;color:rgb(var(--ui-c-a-700)) !important;box-shadow:inset 0 0 0 1px rgb(var(--ui-c-a-200) / .75) !important}
.dark #view-settings .set-tab[aria-selected="true"]{background:var(--settings-surface) !important;border-color:rgb(var(--ui-c-a-500)) !important;color:rgb(var(--ui-c-a-200)) !important;box-shadow:inset 0 0 0 1px rgb(var(--ui-c-a-500) / .3) !important}
#view-settings button:disabled,
#view-settings .settings-secondary-btn:disabled,
#view-settings .set-tab:disabled{opacity:.65 !important;pointer-events:none}
@media (max-width:767px){#view-nodes [data-admin-node-toolbar-row="1"],#view-nodes [data-admin-node-toolbar-actions="1"]{grid-template-columns:minmax(0,1fr)}#view-nodes [data-admin-node-toolbar-row="1"]>*{width:100%}#view-settings .settings-view-layout{display:flex;flex-direction:column}#view-settings .settings-worker-html-update-card [data-admin-worker-html-grid="1"]{grid-template-columns:minmax(0,1fr)}#view-settings .settings-worker-html-update-card [data-admin-worker-html-actions="1"]{align-items:stretch;flex-direction:column}#view-settings .settings-worker-html-update-card [data-admin-worker-html-actions="1"] button{width:100%}}
@media (min-width:768px) and (max-width:1535px){#view-nodes [data-admin-node-toolbar-actions="1"]{grid-template-columns:repeat(4,minmax(0,1fr));width:100%}#view-nodes [data-admin-node-toolbar-actions="1"]>*{width:100%}}
@media (min-width:1536px){#view-nodes [data-admin-node-toolbar="1"]{grid-template-columns:minmax(0,1fr) max-content}#view-nodes [data-admin-node-toolbar-actions="1"]{justify-content:end}}
@media (min-width:768px){#app-shell.settings-split-layout #content-area{overflow:hidden}#app-shell.settings-split-layout #view-settings{height:100%;min-height:0;overflow:hidden}#app-shell.settings-split-layout #view-settings .settings-view-layout{height:100%;min-height:0}#app-shell.settings-split-layout #view-settings .settings-nav-shell{position:sticky;top:0;max-height:100%;overflow-y:auto;flex:0 0 auto}#app-shell.settings-split-layout #view-settings #settings-forms{height:100%;min-height:0;overflow-y:auto;padding-right:.25rem;scrollbar-gutter:stable}}
#app-shell.render-lite.settings-split-layout #view-settings .settings-nav-shell{position:static;top:auto;max-height:none;overflow:visible}
#app-shell input:not([type="checkbox"]):not([type="radio"]):not([type="range"]):not([type="color"]),
#app-shell select,
#app-shell textarea,
#app-shell label:has(> input:not([type="checkbox"]):not([type="radio"]):not([type="range"]):not([type="color"])),
#app-shell label:has(> select),
#app-shell label:has(> textarea){border-radius:var(--ui-control-radius-px) !important}
#app-shell i[data-lucide]{display:inline-flex;align-items:center;justify-content:center;vertical-align:middle}
#app-shell svg.lucide{display:block;flex-shrink:0;stroke:currentColor}
#view-dashboard [data-dashboard-traffic-card="1"]{position:relative !important}
#view-dashboard [data-dashboard-traffic-label="1"]{width:calc(100% - 2.75rem);padding-right:0;overflow:visible;text-overflow:clip;white-space:normal !important}
#view-dashboard [data-dashboard-traffic-toggle="1"]{position:absolute;top:1rem;right:1rem;display:inline-flex;align-items:center;justify-content:center;width:2.25rem;height:2.25rem;padding:0;border:1px solid #dbe3ee;background:rgb(var(--ui-c-white) / .9);color:rgb(var(--ui-c-n-600));border-radius:max(12px,var(--ui-control-radius-px));box-shadow:none;transition:background-color .18s ease,border-color .18s ease,color .18s ease,opacity .18s ease}
#view-dashboard [data-dashboard-traffic-toggle="1"]:hover{background:rgb(var(--ui-c-n-50));border-color:rgb(var(--ui-c-n-400));color:#047857}
#view-dashboard [data-dashboard-traffic-toggle="1"]:focus-visible{outline:none;box-shadow:0 0 0 2px rgba(16,185,129,.22)}
#view-dashboard [data-dashboard-traffic-toggle="1"]:disabled{cursor:wait;opacity:.6}
#view-dashboard [data-dashboard-traffic-toggle="1"] i,#view-dashboard [data-dashboard-traffic-toggle="1"] svg{width:1rem;height:1rem}
.dark #view-dashboard [data-dashboard-traffic-toggle="1"]{border-color:rgb(var(--ui-c-n-700));background:rgb(var(--ui-c-n-900) / .92);color:rgb(var(--ui-c-n-300))}
.dark #view-dashboard [data-dashboard-traffic-toggle="1"]:hover{border-color:rgb(var(--ui-c-n-500));background:#111827;color:#34d399}

/* ── Claude palette layer ────────────────────────────────────────────
   Warm parchment neutrals, terracotta accent, warm-toned dark mode.
   Overrides the earlier cool slate/blue theme in one place. */html[data-theme="claude"]{
  --admin-toolbar-hover-bg:rgba(201,100,66,.10);
  --admin-toolbar-hover-bg-dark:rgba(201,100,66,.18);
}:where(html[data-theme="claude"]) body.bg-slate-50,
:where(html[data-theme="claude"]) body.antialiased{background:rgb(var(--ui-c-n-50)) !important;color:rgb(var(--ui-c-n-900)) !important}:where(html[data-theme="claude"]) #app-shell{background:rgb(var(--ui-c-n-50));color:rgb(var(--ui-c-n-900))}html[data-theme="claude"].dark body,
html[data-theme="claude"].dark body.antialiased{background:rgb(var(--ui-c-n-900)) !important;color:rgb(var(--ui-c-white)) !important}:where(html[data-theme="claude"]) .dark #app-shell{background:rgb(var(--ui-c-n-900));color:rgb(var(--ui-c-white))}:where(html[data-theme="claude"]) .glass-card{background:rgb(var(--ui-c-white));border:1px solid rgb(var(--ui-c-n-200));box-shadow:0 4px 24px rgb(var(--ui-c-n-900) / .05)}:where(html[data-theme="claude"]) .dark .glass-card{background:var(--d1-raised-dark);border:1px solid rgb(var(--ui-c-n-800));box-shadow:none}:where(html[data-theme="claude"]) #app-shell.no-backdrop-fx [data-ui-backdrop="1"]{background-color:rgb(var(--ui-c-n-900) / .72) !important}:where(html[data-theme="claude"]) #app-shell.no-backdrop-fx [data-ui-surface-blur="1"]{background-color:rgb(var(--ui-c-white) / .98) !important}:where(html[data-theme="claude"]) .dark #app-shell.no-backdrop-fx [data-ui-surface-blur="1"]{background-color:rgba(36,36,32,.98) !important}:where(html[data-theme="claude"]) .ui-section-title{color:rgb(var(--ui-c-n-900))}:where(html[data-theme="claude"]) .dark .ui-section-title{color:rgb(var(--ui-c-white))}:where(html[data-theme="claude"]) .ui-section-kicker{color:rgb(var(--ui-c-n-500))}:where(html[data-theme="claude"]) .dark .ui-section-kicker{color:rgb(var(--ui-c-n-500))}:where(html[data-theme="claude"]) .ui-chip-muted{border-color:rgb(var(--ui-c-n-200));background:rgb(var(--ui-c-white));color:rgb(var(--ui-c-n-600))}:where(html[data-theme="claude"]) .dark .ui-chip-muted{border-color:rgb(var(--ui-c-n-800));background:var(--d1-raised-dark);color:rgb(var(--ui-c-n-300))}:where(html[data-theme="claude"]) .ui-block-head{border-bottom-color:rgb(var(--ui-c-n-200) / .9)}:where(html[data-theme="claude"]) .dark .ui-block-head{border-color:rgb(var(--ui-c-n-800))}:where(html[data-theme="claude"]) .ui-settings-panel{border-color:rgb(var(--ui-c-n-200));background:rgb(var(--ui-c-white) / .7);box-shadow:0 1px 2px rgb(var(--ui-c-n-900) / .05)}:where(html[data-theme="claude"]) .dark .ui-settings-panel{border-color:rgb(var(--ui-c-n-800));background:rgba(36,36,32,.55)}:where(html[data-theme="claude"]) .ui-field-label{color:var(--d1-ink-2)}:where(html[data-theme="claude"]) .dark .ui-field-label{color:rgb(var(--ui-c-n-200))}:where(html[data-theme="claude"]) #app-shell [data-admin-toolbar-action]{color:rgb(var(--ui-c-n-600))}:where(html[data-theme="claude"]) .dark #app-shell [data-admin-toolbar-action]{color:rgb(var(--ui-c-n-400))}:where(html[data-theme="claude"]) #app-shell [data-admin-toolbar-action]:hover{color:rgb(var(--ui-c-a-500))}:where(html[data-theme="claude"]) .dark #app-shell [data-admin-toolbar-action]:hover{color:rgb(var(--ui-c-a-400))}:where(html[data-theme="claude"]) #app-shell [data-admin-toolbar-action]:focus-visible{box-shadow:0 0 0 2px rgb(var(--ui-c-a-500) / .28) !important}:where(html[data-theme="claude"]) .dark #app-shell [data-admin-toolbar-action]:focus-visible{box-shadow:0 0 0 2px rgb(var(--ui-c-a-400) / .32) !important}:where(html[data-theme="claude"]) #app-shell [data-admin-toolbar-action="theme"][data-theme-state="dark"]{color:rgb(var(--ui-c-a-500))}:where(html[data-theme="claude"]) .dark #app-shell [data-admin-toolbar-action="theme"][data-theme-state="dark"]{color:rgb(var(--ui-c-a-400))}:where(html[data-theme="claude"]) #app-shell [data-admin-toolbar-action="theme"][data-theme-state="light"]{color:rgb(var(--ui-c-a-600))}:where(html[data-theme="claude"]) .dark #app-shell [data-admin-toolbar-action="theme"][data-theme-state="light"]{color:rgb(var(--ui-c-a-400))}:where(html[data-theme="claude"]) #node-modal [data-admin-node-advanced="1"]{border-color:rgb(var(--ui-c-n-200));background:rgb(var(--ui-c-n-50) / .72)}:where(html[data-theme="claude"]) .dark #node-modal [data-admin-node-advanced="1"]{border-color:rgb(var(--ui-c-n-800));background:rgb(var(--ui-c-n-900) / .4)}:where(html[data-theme="claude"]) #node-modal [data-admin-node-advanced="1"]>summary{color:var(--d1-ink-2)}:where(html[data-theme="claude"]) .dark #node-modal [data-admin-node-advanced="1"]>summary{color:rgb(var(--ui-c-n-200))}:where(html[data-theme="claude"]) #node-modal [data-admin-node-advanced-content="1"]{border-top-color:rgb(var(--ui-c-n-200))}:where(html[data-theme="claude"]) .dark #node-modal [data-admin-node-advanced-content="1"]{border-color:rgb(var(--ui-c-n-800))}:where(html[data-theme="claude"]) #node-modal [data-admin-node-advanced-headers="1"]{background:rgb(var(--ui-c-white))}:where(html[data-theme="claude"]) .dark #node-modal [data-admin-node-advanced-headers="1"]{background:rgba(36,36,32,.72)}:where(html[data-theme="claude"]) .dark #node-modal>div{background:var(--d1-raised-dark) !important;border-color:rgb(var(--ui-c-n-800)) !important}:where(html[data-theme="claude"]) .dark #view-nodes .node-card-shell,
:where(html[data-theme="claude"]) .dark #view-nodes .node-tag-filter-panel-shell{background:var(--d1-raised-dark) !important;border-color:rgb(var(--ui-c-n-800)) !important}:where(html[data-theme="claude"]) .dark #view-nodes .node-toolbar-primary-btn,
:where(html[data-theme="claude"]) .dark #node-modal .node-modal-primary-btn{background:rgb(var(--ui-c-a-500)) !important;color:rgb(var(--ui-c-white)) !important;box-shadow:0 10px 24px rgb(var(--ui-c-a-500) / .22) !important}:where(html[data-theme="claude"]) .dark #view-nodes .node-toolbar-primary-btn:hover,
:where(html[data-theme="claude"]) .dark #node-modal .node-modal-primary-btn:hover{background:rgb(var(--ui-c-a-600)) !important}:where(html[data-theme="claude"]) .dark #view-nodes .node-tag-filter-trigger,
:where(html[data-theme="claude"]) .dark #view-nodes .node-toolbar-search,
:where(html[data-theme="claude"]) .dark #view-nodes .node-tag-filter-chip,
:where(html[data-theme="claude"]) .dark #view-nodes .node-action-btn,
:where(html[data-theme="claude"]) .dark #node-modal .node-modal-secondary-btn{background:rgba(36,36,32,.9) !important;color:rgb(var(--ui-c-n-200)) !important;border-color:rgb(var(--ui-c-n-700) / .85) !important}:where(html[data-theme="claude"]) #view-settings{--settings-surface:rgb(var(--ui-c-white));--settings-soft:rgb(var(--ui-c-n-50));--settings-border:rgb(var(--ui-c-n-200));--settings-border-strong:rgb(var(--ui-c-n-300))}:where(html[data-theme="claude"]) .dark #view-settings{--settings-surface:var(--d1-raised-dark);--settings-soft:rgb(var(--ui-c-n-800));--settings-border:rgb(var(--ui-c-n-800));--settings-border-strong:rgb(var(--ui-c-n-700))}:where(html[data-theme="claude"]) #view-settings .settings-secondary-btn,
:where(html[data-theme="claude"]) #view-settings .settings-secondary-label,
:where(html[data-theme="claude"]) #view-settings button[class*="border-slate-200"],
:where(html[data-theme="claude"]) #view-settings button[class*="border-slate-300"],
:where(html[data-theme="claude"]) #view-settings label[class*="border-slate-200"],
:where(html[data-theme="claude"]) #view-settings label[class*="bg-slate-200"]{color:var(--d1-ink-2) !important}:where(html[data-theme="claude"]) .dark #view-settings .settings-secondary-btn,
:where(html[data-theme="claude"]) .dark #view-settings .settings-secondary-label,
:where(html[data-theme="claude"]) .dark #view-settings button[class*="border-slate-200"],
:where(html[data-theme="claude"]) .dark #view-settings button[class*="border-slate-300"],
:where(html[data-theme="claude"]) .dark #view-settings label[class*="border-slate-200"],
:where(html[data-theme="claude"]) .dark #view-settings label[class*="bg-slate-200"]{color:rgb(var(--ui-c-n-200)) !important}:where(html[data-theme="claude"]) .dark #view-settings .settings-secondary-btn:hover,
:where(html[data-theme="claude"]) .dark #view-settings .settings-secondary-label:hover,
:where(html[data-theme="claude"]) .dark #view-settings button[class*="border-slate-200"]:hover,
:where(html[data-theme="claude"]) .dark #view-settings button[class*="border-slate-300"]:hover,
:where(html[data-theme="claude"]) .dark #view-settings label[class*="border-slate-200"]:hover,
:where(html[data-theme="claude"]) .dark #view-settings label[class*="bg-slate-200"]:hover{background:rgb(var(--ui-c-n-800)) !important;color:rgb(var(--ui-c-white)) !important}:where(html[data-theme="claude"]) #view-settings .set-tab{color:rgb(var(--ui-c-n-600)) !important}:where(html[data-theme="claude"]) #view-settings .set-tab:hover{color:rgb(var(--ui-c-n-900)) !important}:where(html[data-theme="claude"]) .dark #view-settings .set-tab{color:rgb(var(--ui-c-n-300)) !important}:where(html[data-theme="claude"]) .dark #view-settings .set-tab:hover{background:rgb(var(--ui-c-n-800)) !important;color:rgb(var(--ui-c-white)) !important}:where(html[data-theme="claude"]) #view-settings .set-tab[aria-selected="true"]{background:rgb(var(--ui-c-n-50)) !important;border-color:rgb(var(--ui-c-a-300)) !important;color:rgb(var(--ui-c-a-600)) !important;box-shadow:inset 0 0 0 1px rgb(var(--ui-c-a-500) / .28) !important}:where(html[data-theme="claude"]) .dark #view-settings .set-tab[aria-selected="true"]{background:rgb(var(--ui-c-n-800)) !important;border-color:rgb(var(--ui-c-a-500)) !important;color:rgb(var(--ui-c-a-300)) !important;box-shadow:inset 0 0 0 1px rgb(var(--ui-c-a-500) / .35) !important}:where(html[data-theme="claude"]) #view-dashboard [data-dashboard-traffic-toggle="1"]{border-color:rgb(var(--ui-c-n-200));background:rgb(var(--ui-c-white) / .9);color:rgb(var(--ui-c-n-600))}:where(html[data-theme="claude"]) #view-dashboard [data-dashboard-traffic-toggle="1"]:hover{background:rgb(var(--ui-c-n-50));border-color:rgb(var(--ui-c-n-400));color:rgb(var(--ui-c-a-500))}:where(html[data-theme="claude"]) #view-dashboard [data-dashboard-traffic-toggle="1"]:focus-visible{box-shadow:0 0 0 2px rgb(var(--ui-c-a-500) / .24)}:where(html[data-theme="claude"]) .dark #view-dashboard [data-dashboard-traffic-toggle="1"]{border-color:rgb(var(--ui-c-n-800));background:rgba(36,36,32,.92);color:rgb(var(--ui-c-n-300))}:where(html[data-theme="claude"]) .dark #view-dashboard [data-dashboard-traffic-toggle="1"]:hover{border-color:rgb(var(--ui-c-n-700));background:rgb(var(--ui-c-n-800));color:rgb(var(--ui-c-a-400))}:where(html[data-theme="claude"]) .d1-heatmap-col-label{color:rgb(var(--ui-c-n-500))}:where(html[data-theme="claude"]) .dark .d1-heatmap-col-label{color:rgb(var(--ui-c-n-500))}:where(html[data-theme="claude"]) .d1-heatmap-row-label{color:rgb(var(--ui-c-n-600))}:where(html[data-theme="claude"]) .dark .d1-heatmap-row-label{color:rgb(var(--ui-c-n-300))}:where(html[data-theme="claude"]) .d1-heat-cell{border-color:rgb(var(--ui-c-a-500) / .18);background:rgba(201,100,66,var(--ui-heat-alpha,.08))}:where(html[data-theme="claude"]) .d1-heat-cell.is-active:hover{border-color:rgb(var(--ui-c-a-500) / .4);box-shadow:0 10px 22px rgb(var(--ui-c-a-500) / .12)}:where(html[data-theme="claude"]) .d1-heat-cell.is-empty{border-color:rgb(var(--ui-c-n-200));background:rgb(var(--ui-c-n-50))}:where(html[data-theme="claude"]) .dark .d1-heat-cell{border-color:rgb(var(--ui-c-a-400) / .18);background:rgba(217,119,87,var(--ui-heat-alpha,.12))}:where(html[data-theme="claude"]) .dark .d1-heat-cell.is-active:hover{border-color:rgb(var(--ui-c-a-300) / .42);box-shadow:0 12px 26px rgb(var(--ui-c-a-500) / .16)}:where(html[data-theme="claude"]) .dark .d1-heat-cell.is-empty{border-color:rgb(var(--ui-c-n-800));background:rgb(var(--ui-c-n-900) / .74)}:where(html[data-theme="claude"]) .dark [class*="text-slate-500"],
:where(html[data-theme="claude"]) .dark [class*="text-slate-400"],
:where(html[data-theme="claude"]) .dark #view-settings label.text-slate-500,
:where(html[data-theme="claude"]) .dark #cfg-source-direct-nodes-summary,
:where(html[data-theme="claude"]) .dark #view-logs p.text-slate-500{color:rgb(var(--ui-c-n-400)) !important}/* ===== Direction A · 暖纸编辑器（排版层）===== */
html[data-theme="claude"]{--font-display:"Noto Serif SC","Source Serif 4",Georgia,"Songti SC","SimSun",serif;--font-body:system-ui,-apple-system,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;--font-mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--d1-paper:#f5f4ed;--d1-raised:#faf9f5;--d1-sunk:#efeee6;--d1-ink:#141413;--d1-ink-2:#3d3d3a;--d1-muted:#87867f;--d1-rule:#e8e6dc;--d1-rule-2:#d8d5c9;--d1-clay:#c96442;--d1-clay-deep:#b4553a;--d1-clay-soft:#e0a48c;--d1-radius:14px;--d1-on-accent:#ffffff;--d1-bean:#964742;--d1-bean-deep:#7f3b37;--d1-action:#8e3a22;--d1-action-hover:#7a301b;--d1-action-strong:#b3502f;--d1-action-strong-hover:#9b4326;--d1-action-active:#83381f;--d1-action-dark:#a3452a;--d1-raised-dark:#242420;--d1-muted-dark:#8f8d84;--d1-rule-2-dark:#4a4a45}/* 支持相对颜色语法时整族由 --d1-action 派生；上面的 literal 是兜底，不能只留 oklch() 一条，那样不支持的浏览器会拿到非法值、整条声明失效。 */@supports (color:oklch(from red calc(l - 0.05) calc(c - 0.01) h)){html[data-theme="claude"]{--d1-action-hover:oklch(from var(--d1-action) calc(l - 0.049) calc(c - 0.0115) calc(h - 0.103));--d1-action-strong:oklch(from var(--d1-action) calc(l + 0.0926) calc(c + 0.0172) calc(h + 1.9883));--d1-action-strong-hover:oklch(from var(--d1-action) calc(l + 0.0348) calc(c + 0.0051) calc(h + 1.7799));--d1-action-active:oklch(from var(--d1-action) calc(l - 0.0213) calc(c - 0.01) calc(h + 1.9515));--d1-action-dark:oklch(from var(--d1-action) calc(l + 0.0509) calc(c + 0.0111) calc(h + 0.0947))}}html[data-theme="claude"],
:where(html[data-theme="claude"]) body,
:where(html[data-theme="claude"]) #app-shell{font-family:var(--font-body);-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}:where(html[data-theme="claude"]) #app-shell{font-variant-numeric:tabular-nums}:where(html[data-theme="claude"]) h1,
:where(html[data-theme="claude"]) h2,
:where(html[data-theme="claude"]) h3,
:where(html[data-theme="claude"]) h4,
:where(html[data-theme="claude"]) .ui-section-title{font-family:var(--font-display);font-weight:600;letter-spacing:-.01em;text-wrap:balance}:where(html[data-theme="claude"]) h1{letter-spacing:-.022em}:where(html[data-theme="claude"]) #app-shell h1,
:where(html[data-theme="claude"]) #app-shell h2,
:where(html[data-theme="claude"]) #app-shell [class*="text-2xl"][class*="font-bold"],
:where(html[data-theme="claude"]) #app-shell [class*="text-3xl"][class*="font-bold"]{font-family:var(--font-display);letter-spacing:-.012em}:where(html[data-theme="claude"]) .ui-section-title{font-size:1.0625rem;line-height:1.5rem;color:var(--d1-ink)}:where(html[data-theme="claude"]) .dark .ui-section-title{color:#f4f2ea}:where(html[data-theme="claude"]) .ui-section-kicker{font-family:var(--font-body);font-size:.6875rem;line-height:1rem;font-weight:600;letter-spacing:.12em;color:var(--d1-muted)}:where(html[data-theme="claude"]) .dark .ui-section-kicker{color:var(--d1-muted-dark)}:where(html[data-theme="claude"]) pre,
:where(html[data-theme="claude"]) code,
:where(html[data-theme="claude"]) kbd,
:where(html[data-theme="claude"]) samp,
:where(html[data-theme="claude"]) .font-mono{font-family:var(--font-mono)}:where(html[data-theme="claude"]) thead th{font-family:var(--font-body);font-size:.6875rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--d1-muted)}:where(html[data-theme="claude"]) .dark thead th{color:var(--d1-muted-dark)}:where(html[data-theme="claude"]) ::selection{background:rgb(var(--ui-c-a-500) / .16);color:var(--d1-ink)}/* 纸张层级：只用 1px 暖灰描边，不用彩色阴影 */
:where(html[data-theme="claude"]) .glass-card{border-radius:var(--d1-radius) !important;border:1px solid var(--d1-rule) !important;background:var(--d1-raised) !important;box-shadow:none !important;transition:border-color .18s ease,background-color .18s ease}:where(html[data-theme="claude"]) .glass-card:hover{border-color:var(--d1-rule-2) !important}:where(html[data-theme="claude"]) .dark .glass-card{background:var(--d1-raised-dark) !important;border-color:rgb(var(--ui-c-n-800)) !important;box-shadow:none !important}:where(html[data-theme="claude"]) .dark .glass-card:hover{border-color:var(--d1-rule-2-dark) !important}:where(html[data-theme="claude"]) .ui-settings-panel,
:where(html[data-theme="claude"]) .ui-chip-muted{border-radius:10px;box-shadow:none}:where(html[data-theme="claude"]) #sidebar{background:var(--d1-raised);border-right:1px solid var(--d1-rule);box-shadow:none}:where(html[data-theme="claude"]) .dark #sidebar{background:#1b1b18;border-color:#2b2b28}@media (max-width:767px){:where(html[data-theme="claude"]) #sidebar{box-shadow:0 24px 60px -28px rgb(var(--ui-c-n-900) / .42)}}:where(html[data-theme="claude"]) #app-shell button,
:where(html[data-theme="claude"]) #app-shell a,
:where(html[data-theme="claude"]) #app-shell [role="tab"]{transition:background-color .16s ease,border-color .16s ease,color .16s ease}:where(html[data-theme="claude"]) #app-shell :focus-visible{outline:2px solid rgb(var(--ui-c-a-500) / .55);outline-offset:2px}:where(html[data-theme="claude"]) .dark #app-shell :focus-visible{outline-color:rgb(var(--ui-c-a-400) / .65)}:where(html[data-theme="claude"]) #app-shell [data-admin-toolbar-action]:focus-visible{box-shadow:none !important}:where(html[data-theme="claude"]) .dark #view-nodes .node-toolbar-primary-btn,
:where(html[data-theme="claude"]) .dark #node-modal .node-modal-primary-btn{box-shadow:none !important;background:var(--d1-clay) !important}:where(html[data-theme="claude"]) #view-nodes .node-toolbar-primary-btn,
:where(html[data-theme="claude"]) #node-modal .node-modal-primary-btn{border-radius:10px}:where(html[data-theme="claude"]) [data-ui-dialog-surface="1"],
:where(html[data-theme="claude"]) [data-ui-toast="1"]{box-shadow:0 24px 60px -28px rgb(var(--ui-c-n-900) / .45) !important}@media (prefers-reduced-motion:reduce){:where(html[data-theme="claude"]) .glass-card{transition:none}}/* ===== Direction A · 排版微调（行高 / 断行 / 数字 / 微标签）===== */
/* 1. 中文行高与断行：正文 1.7，标题逐级收紧；避免末行孤字 */
:where(html[data-theme="claude"]) #app-shell p,
:where(html[data-theme="claude"]) #app-shell li,
:where(html[data-theme="claude"]) #app-shell dd{line-height:1.7;text-wrap:pretty;hanging-punctuation:allow-end}:where(html[data-theme="claude"]) #app-shell h1{line-height:1.24}:where(html[data-theme="claude"]) #app-shell h2{line-height:1.3}:where(html[data-theme="claude"]) #app-shell h3{line-height:1.4}:where(html[data-theme="claude"]) #app-shell h4{line-height:1.45}:where(html[data-theme="claude"]) #app-shell h1,
:where(html[data-theme="claude"]) #app-shell h2,
:where(html[data-theme="claude"]) #app-shell h3{text-wrap:balance}:where(html[data-theme="claude"]) #app-shell small,
:where(html[data-theme="claude"]) #app-shell .text-xs{line-height:1.5}/* 2. 中西文混排：标点压缩、字距正常化，代码块关掉连字 */
:where(html[data-theme="claude"]) #app-shell{text-spacing-trim:trim-start;font-kerning:normal}:where(html[data-theme="claude"]) #app-shell :is(pre,code,kbd,samp,.font-mono){font-variant-ligatures:none;letter-spacing:0}/* 3. 上标小节：字距收窄，与标题合成一个块 */
:where(html[data-theme="claude"]) .ui-section-kicker{letter-spacing:.1em;margin-bottom:4px}:where(html[data-theme="claude"]) .ui-section-title{margin-top:0;line-height:1.45}:where(html[data-theme="claude"]) .ui-block-head .ui-section-title{line-height:1.4}/* 4. 大字号数字：等宽且收紧，行高不撑开卡片 */
:where(html[data-theme="claude"]) #app-shell [class*="text-2xl"][class*="font-bold"],
:where(html[data-theme="claude"]) #app-shell [class*="text-3xl"][class*="font-bold"]{font-variant-numeric:tabular-nums lining-nums;letter-spacing:-.028em;line-height:1.15}/* 5. 表单：正文体、正字距，占位符不低于 AA */
:where(html[data-theme="claude"]) #app-shell label{line-height:1.5;letter-spacing:.005em}:where(html[data-theme="claude"]) #app-shell :is(input,select,textarea){font-family:var(--font-body);letter-spacing:.005em}:where(html[data-theme="claude"]) #app-shell :is(input,select,textarea)::placeholder{color:var(--d1-muted)}:where(html[data-theme="claude"]) .dark #app-shell :is(input,select,textarea)::placeholder{color:var(--d1-muted-dark)}/* 6. 表格：行距略松于默认、表头字距微收 */
:where(html[data-theme="claude"]) #app-shell tbody td{line-height:1.55}:where(html[data-theme="claude"]) #app-shell thead th{letter-spacing:.06em}/* 7. 微标签与链接：可读性优先 */
:where(html[data-theme="claude"]) .ui-chip-muted{font-size:.6875rem;line-height:1.35;letter-spacing:.02em}:where(html[data-theme="claude"]) #app-shell a{text-underline-offset:.2em;text-decoration-thickness:1px}/* ===== Direction A · 组件排版（统计卡 / 分节头 / 表格 / 表单 / 微标签）===== */

/* 1. 统计卡：左侧色条改为顶部 2px 分节规则，标签→数字→注释按 8/10/6 的节奏收紧 */
:where(html[data-theme="claude"]) #app-shell [class*="border-l-4"]{border-left-width:0 !important;border-top-width:2px !important;border-top-color:var(--d1-rule-2) !important}:where(html[data-theme="claude"]) .dark #app-shell [class*="border-l-4"]{border-top-color:var(--d1-rule-2-dark) !important}:where(html[data-theme="claude"]) #app-shell [class*="border-l-4"]>p:first-child{font-size:.75rem;line-height:1.35;font-weight:500;letter-spacing:.08em;color:var(--d1-muted)}:where(html[data-theme="claude"]) .dark #app-shell [class*="border-l-4"]>p:first-child{color:var(--d1-muted-dark)}:where(html[data-theme="claude"]) #app-shell [class*="border-l-4"]>h3{margin-top:.5rem !important;font-size:clamp(1.5rem,1.7vw,1.875rem);line-height:1.12;word-break:break-word;overflow-wrap:anywhere}:where(html[data-theme="claude"]) #app-shell [class*="border-l-4"]>p:last-child{margin-top:.625rem !important;font-size:.75rem;line-height:1.6;letter-spacing:.01em}/* 2. 分节头：标题块左对齐顶部，徽标不再拉高整行高度 */
:where(html[data-theme="claude"]) .ui-block-head{align-items:flex-start !important;margin-bottom:1rem;padding-bottom:.625rem}:where(html[data-theme="claude"]) .ui-block-head>div:first-child{min-width:0}:where(html[data-theme="claude"]) .ui-block-head .ui-chip-muted{margin-top:2px;flex:0 0 auto}/* 3. 表格：等宽数据 + 略松的行距，行分隔线降一级 */
:where(html[data-theme="claude"]) #app-shell table{font-variant-numeric:tabular-nums}:where(html[data-theme="claude"]) #app-shell thead th{padding-top:.625rem;padding-bottom:.625rem}:where(html[data-theme="claude"]) #app-shell tbody td{padding-top:.5625rem;padding-bottom:.5625rem}:where(html[data-theme="claude"]) #app-shell tbody td .break-all{word-break:break-word}/* 4. 表单：字段标签与控件之间的间距按 6px 收紧，面板内边距统一 */
:where(html[data-theme="claude"]) #app-shell .ui-settings-panel{padding:1.375rem}:where(html[data-theme="claude"]) .ui-field-label{margin-bottom:.375rem;font-size:.8125rem;line-height:1.35;letter-spacing:.015em}:where(html[data-theme="claude"]) #app-shell .ui-settings-panel .ui-block-head{margin-bottom:.875rem}:where(html[data-theme="claude"]) #app-shell :is(input,select,textarea){line-height:1.5}/* 5. 微标签：内边距收一档，与相邻标题基线对齐 */
:where(html[data-theme="claude"]) #app-shell .ui-chip-muted{padding:.1875rem .5rem;line-height:1.35}/* 6. 日志与代码块：行距放宽到可长读的水平，时间戳保持等宽 */
:where(html[data-theme="claude"]) #view-logs{font-variant-numeric:tabular-nums}:where(html[data-theme="claude"]) #view-logs :is(.font-mono,pre,code){line-height:1.65}:where(html[data-theme="claude"]) #view-dns :is(table,.font-mono){line-height:1.6}/* 7. 长数字与 URL：只在必要时换行，避免 mid-number 断行造成的错读 */
:where(html[data-theme="claude"]) #app-shell .break-all{word-break:break-word}@media (max-width:767px){:where(html[data-theme="claude"]) #app-shell [class*="border-l-4"]>h3{font-size:1.5rem}:where(html[data-theme="claude"]) #app-shell .ui-settings-panel{padding:1.125rem}}/* ===== Direction A · 表格优化（表头 / 行节奏 / 长文本 / 空态）===== */
/* 表头：一条 1px 暖灰规则收口，底色只降一档；列名提高对比度到 AA */
:where(html[data-theme="claude"]) #view-logs thead tr,
:where(html[data-theme="claude"]) #view-dns thead tr{border-bottom-width:0}:where(html[data-theme="claude"]) #view-logs thead th,
:where(html[data-theme="claude"]) #view-dns thead th{color:#5e5d57;font-weight:600;padding-top:.5rem;padding-bottom:.5rem;border-bottom:1px solid var(--d1-rule-2);background:rgb(var(--ui-c-n-900) / .028)}:where(html[data-theme="claude"]) .dark #view-logs thead th,
:where(html[data-theme="claude"]) .dark #view-dns thead th{color:#a9a79e;border-bottom-color:#3a3a36;background:rgb(var(--ui-c-white) / .04)}/* 行：等距发丝线，悬停只抬背景、不动前景色 */
:where(html[data-theme="claude"]) #view-logs tbody tr,
:where(html[data-theme="claude"]) #view-dns tbody tr{border-bottom:1px solid rgb(var(--ui-c-n-900) / .075);transition:background-color .14s ease}:where(html[data-theme="claude"]) .dark #view-logs tbody tr,
:where(html[data-theme="claude"]) .dark #view-dns tbody tr{border-bottom-color:rgb(var(--ui-c-white) / .085)}:where(html[data-theme="claude"]) #view-logs tbody tr:hover,
:where(html[data-theme="claude"]) #view-dns tbody tr:hover{background:rgb(var(--ui-c-n-900) / .032)}:where(html[data-theme="claude"]) .dark #view-logs tbody tr:hover,
:where(html[data-theme="claude"]) .dark #view-dns tbody tr:hover{background:rgb(var(--ui-c-white) / .05)}:where(html[data-theme="claude"]) #view-logs tbody tr:last-child,
:where(html[data-theme="claude"]) #view-dns tbody tr:last-child{border-bottom-width:0}/* 单元格：日志顶部对齐，DNS 居中；长串只在必要时断 */
:where(html[data-theme="claude"]) #view-logs tbody td{vertical-align:top;padding-top:.5rem;padding-bottom:.5rem;overflow-wrap:anywhere}:where(html[data-theme="claude"]) #view-dns tbody td{vertical-align:middle}:where(html[data-theme="claude"]) #view-dns tbody td :is(input,select){max-width:100%}/* 空态：跨列占位行改为居中说明 */
:where(html[data-theme="claude"]) #app-shell tbody td[colspan]{padding:2rem 1rem;text-align:center;font-family:var(--font-body);font-size:.8125rem;line-height:1.6;letter-spacing:0;color:var(--d1-muted)}:where(html[data-theme="claude"]) .dark #app-shell tbody td[colspan]{color:var(--d1-muted-dark)}@media (prefers-reduced-motion:reduce){:where(html[data-theme="claude"]) #view-logs tbody tr,
:where(html[data-theme="claude"]) #view-dns tbody tr{transition:none}}/* ===== Direction A · 表格圆润化（字形 / 字距 / 行节奏）===== */
html[data-theme="claude"]{
  --font-table:"Nunito","MiSans","HarmonyOS Sans SC","PingFang SC","Hiragino Sans GB","Microsoft YaHei",system-ui,sans-serif;
  --font-table-mono:"DM Mono","JetBrains Mono",ui-monospace,SFMono-Regular,Consolas,monospace;
}/* 字形：表体与表头换成笔画更圆的 Nunito（拉丁/数字），中文回落到圆角优先的国产无衬线 */
:where(html[data-theme="claude"]) #view-logs table,
:where(html[data-theme="claude"]) #view-dns table,
:where(html[data-theme="claude"]) #view-logs tbody td,
:where(html[data-theme="claude"]) #view-dns tbody td,
:where(html[data-theme="claude"]) #view-logs thead th,
:where(html[data-theme="claude"]) #view-dns thead th{font-family:var(--font-table);letter-spacing:.012em;word-spacing:.04em}/* 等宽数据换圆润等宽（DM Mono），仍保持列对齐；不改字号 */
:where(html[data-theme="claude"]) #view-logs table :is(.font-mono,code,pre),
:where(html[data-theme="claude"]) #view-dns table :is(.font-mono,code,pre){font-family:var(--font-table-mono);letter-spacing:0;word-spacing:0}/* 横向：字距与词距各松半档，全大写表头不再拉宽到发硬 */
:where(html[data-theme="claude"]) #view-logs thead th,
:where(html[data-theme="claude"]) #view-dns thead th{font-weight:600;letter-spacing:.05em;word-spacing:.02em}/* 纵向：行高抬到 1.68/1.72，行内边距固定 10px，行与行的呼吸一致 */
:where(html[data-theme="claude"]) #view-logs tbody td,
:where(html[data-theme="claude"]) #view-dns tbody td{padding-top:.625rem;padding-bottom:.625rem;line-height:1.68}:where(html[data-theme="claude"]) #view-logs tbody td{line-height:1.72}/* DNS 表内的输入控件与按钮跟随表体字形，避免混排突兀 */
:where(html[data-theme="claude"]) #view-dns tbody td :is(input,select,button){font-family:var(--font-table);letter-spacing:.01em}/* 空态说明也用表体字形（原规则在上一层的字体声明之后会被这里接住） */
:where(html[data-theme="claude"]) #app-shell tbody td[colspan]{font-family:var(--font-table);letter-spacing:.01em}/* ===== Direction A · 表格圆润化 v2（中文也圆）===== */
/* 上一轮只有数字变圆：Nunito / DM Mono 没有中文字形，中文一直回落到微软雅黑（方体）。
   这里把真正带简体中文的圆润字体 LXGW WenKai Screen 挂在拉丁字体之后，只接管中文，拉丁与数字的圆润度/对齐不变。 */
html[data-theme="claude"]{
  --font-table:"Nunito","LXGW WenKai Screen","MiSans","HarmonyOS Sans SC","PingFang SC","Hiragino Sans GB","Microsoft YaHei",system-ui,sans-serif;
  --font-table-mono:"DM Mono","LXGW WenKai Screen",ui-monospace,SFMono-Regular,Consolas,monospace;
}/* 文楷只有 400：关掉合成粗体避免中文发糊，Nunito 的 500/600 仍走真字形 */
:where(html[data-theme="claude"]) #view-logs tbody td,
:where(html[data-theme="claude"]) #view-dns tbody td,
:where(html[data-theme="claude"]) #view-logs thead th,
:where(html[data-theme="claude"]) #view-dns thead th{font-synthesis-weight:none}/* 表头也走圆润字体：拉丁仍由 Nunito 接管（大写陈列），中文由文楷接管；
   11px 小字下把字距从 .05em 收到 .04em，避免圆体在小字号被拉散 */
:where(html[data-theme="claude"]) #view-logs thead th,
:where(html[data-theme="claude"]) #view-dns thead th{font-family:var(--font-table);letter-spacing:.04em;word-spacing:.02em}:where(html[data-theme="claude"]) #view-dns tbody td :is(input,select,button){font-family:var(--font-body)}/* ===== Direction A · 圆润化 v3（侧栏导航 / 按钮）===== */
/* 复用表格那套「拉丁 Nunito + 中文文楷」的字体栈，命名沿用 --font-table；
   文楷只有 400，按钮里的 font-semibold 中文会走合成假粗，一并关掉。 */
:where(html[data-theme="claude"]) #sidebar,

:where(html[data-theme="claude"]) #app-shell :is(button,[role="button"],a[class*="btn"]){font-family:var(--font-table);font-synthesis-weight:none;letter-spacing:.01em;word-spacing:.02em}/* 侧栏导航行：圆体笔画外扩，短标签给一点点字距才不显挤 */
:where(html[data-theme="claude"]) #sidebar :is(a,button){letter-spacing:.015em}/* 侧栏里的品牌字标与标题仍用衬线，避免整块都变成楷体 */
:where(html[data-theme="claude"]) #sidebar :is(h1,h2,h3,h4){font-family:var(--font-display)}/* 代码、版本号、数值仍走等宽，不被圆体接管 */
:where(html[data-theme="claude"]) #sidebar :is(.font-mono,pre,code,kbd,samp),

:where(html[data-theme="claude"]) #app-shell :is(button,[role="button"]) :is(.font-mono,pre,code,kbd,samp){font-family:var(--font-mono);letter-spacing:0}/* ===== Direction A · 仪表盘可视化（卡面分层 / 图表底板 / 热力可读性）===== */
/* 1. 卡面抬升：纸白提到 #fffdf8，配深半档的 1px 描边 + 一层中性墨影（不用彩色投影），
      卡片才真正从 #f5f4ed 的纸面上浮起来一档，不再和页面底色黏在一起 */
:where(html[data-theme="claude"]) #view-dashboard .glass-card{
  background:#fffdf8 !important;
  border-color:#e3dfd1 !important;
  box-shadow:0 1px 2px rgb(var(--ui-c-n-900) / .05),0 14px 30px -24px rgb(var(--ui-c-n-900) / .42) !important;
}:where(html[data-theme="claude"]) #view-dashboard .glass-card:hover{
  border-color:#d5d0bd !important;
  box-shadow:0 1px 2px rgb(var(--ui-c-n-900) / .06),0 18px 36px -24px rgb(var(--ui-c-n-900) / .46) !important;
}:where(html[data-theme="claude"]) .dark #view-dashboard .glass-card{
  background:#272723 !important;
  border-color:#3d3d38 !important;
  box-shadow:inset 0 1px 0 rgba(255,253,248,.03),0 16px 32px -24px rgba(0,0,0,.7) !important;
}:where(html[data-theme="claude"]) .dark #view-dashboard .glass-card:hover{border-color:var(--d1-rule-2-dark) !important}/* 2. 图表底板：趋势图原来直接画在卡面上，网格与面积填充都贴着同色底，视觉上糊成一片。
      给 canvas 的父级做一张更亮的细边底板，折线与网格立刻有依托 */
:where(html[data-theme="claude"]) #view-dashboard div:has(>#trafficChart){
  background:#fffefb;
  border:1px solid #efece0;
  border-radius:12px;
  padding:14px 12px 6px;
}:where(html[data-theme="claude"]) .dark #view-dashboard div:has(>#trafficChart){background:#1c1c19;border-color:#3a3a36}/* 3. 热力图：低值格原来只有 8% 陶土，在暖纸上几乎看不见。
      把数据映射的透明度整体放大（数据仍按原比例编码，只抬高可见下限），
      圆角从 10px 收到 7px，边界更利落；空格改成斜纹，明确区分「无数据」与「低值」 */
:where(html[data-theme="claude"]) #view-dashboard .d1-heat-cell{
  border-radius:7px;
  border-color:rgb(var(--ui-c-a-600) / .3);
  background:rgba(201,100,66,min(1,calc(var(--ui-heat-alpha,.08) * 1.8)));
  box-shadow:inset 0 1px 0 rgba(255,255,255,.45);
}:where(html[data-theme="claude"]) #view-dashboard .d1-heat-cell.is-active:hover{
  transform:translateY(-1px);
  border-color:rgb(var(--ui-c-a-600) / .62);
  box-shadow:0 8px 18px -8px rgb(var(--ui-c-a-600) / .42);
}:where(html[data-theme="claude"]) #view-dashboard .d1-heat-cell.is-empty{
  border-style:dashed;
  border-color:#e0ddd0;
  background:repeating-linear-gradient(135deg,rgb(var(--ui-c-n-900) / .055) 0 2px,transparent 2px 5px);
  box-shadow:none;
}:where(html[data-theme="claude"]) .dark #view-dashboard .d1-heat-cell{
  border-color:rgb(var(--ui-c-a-400) / .32);
  background:rgba(217,119,87,min(1,calc(var(--ui-heat-alpha,.12) * 1.7)));
  box-shadow:inset 0 1px 0 rgba(255,253,248,.05);
}:where(html[data-theme="claude"]) .dark #view-dashboard .d1-heat-cell.is-active:hover{border-color:rgb(var(--ui-c-a-300) / .66)}:where(html[data-theme="claude"]) .dark #view-dashboard .d1-heat-cell.is-empty{
  border-color:#3a3a36;
  background:repeating-linear-gradient(135deg,rgba(255,253,248,.07) 0 2px,transparent 2px 5px);
}/* 轴标签：11px 下的 #87867f 只有约 3.4:1，扫读时最先糊掉 */
:where(html[data-theme="claude"]) #view-dashboard .d1-heatmap-col-label{color:#6b6a63}:where(html[data-theme="claude"]) #view-dashboard .d1-heatmap-row-label{color:var(--d1-ink-2)}:where(html[data-theme="claude"]) .dark #view-dashboard .d1-heatmap-col-label{color:#a9a79e}:where(html[data-theme="claude"]) .dark #view-dashboard .d1-heatmap-row-label{color:rgb(var(--ui-c-n-300))}/* 图表下方的 12px 说明文字同步提一档对比度 */
:where(html[data-theme="claude"]) #view-dashboard .text-slate-500{color:#5e5d5a !important}:where(html[data-theme="claude"]) .dark #view-dashboard .text-slate-500{color:#a9a79e !important}/* ===== Direction A · 对比度 v2（仪表盘：卡面边界 / 次要文字 / 图表 / 热力图）===== */
/* 1. 卡面：描边再深一档、墨影收紧，卡片边界不再依赖明度差 */
:where(html[data-theme="claude"]) #view-dashboard .glass-card{
  border-color:#d3ccb6 !important;
  box-shadow:0 1px 2px rgb(var(--ui-c-n-900) / .06),0 16px 30px -22px rgb(var(--ui-c-n-900) / .44) !important;
}:where(html[data-theme="claude"]) #view-dashboard .glass-card:hover{
  border-color:#c3bba1 !important;
  box-shadow:0 1px 2px rgb(var(--ui-c-n-900) / .07),0 20px 34px -22px rgb(var(--ui-c-n-900) / .48) !important;
}:where(html[data-theme="claude"]) .dark #view-dashboard .glass-card{
  border-color:#4a4a44 !important;
  box-shadow:inset 0 1px 0 rgba(255,253,248,.04),0 16px 30px -22px rgba(0,0,0,.66) !important;
}:where(html[data-theme="claude"]) .dark #view-dashboard .glass-card:hover{border-color:#5c5c54 !important}/* 2. 图表底板：比卡面更亮 + 更实的描边，图表区自成一块 */
:where(html[data-theme="claude"]) #view-dashboard div:has(>#trafficChart){
  background:var(--d1-on-accent);
  border-color:#ddd6c2;
  box-shadow:inset 0 0 0 1px rgb(var(--ui-c-n-900) / .02);
}:where(html[data-theme="claude"]) .dark #view-dashboard div:has(>#trafficChart){background:#141412;border-color:#4a4a44}/* 3. 次要文字：仪表盘里的 slate-300/400/500/600 逐级提深到 AA 以上 */
:where(html[data-theme="claude"]) #view-dashboard :is(.text-slate-300,.text-slate-400){color:#6b6a62 !important}:where(html[data-theme="claude"]) #view-dashboard .text-slate-500{color:#4f4e48 !important}:where(html[data-theme="claude"]) #view-dashboard .text-slate-600{color:#3d3c37 !important}:where(html[data-theme="claude"]) .dark #view-dashboard :is(.text-slate-300,.text-slate-400){color:#bab8ad !important}:where(html[data-theme="claude"]) .dark #view-dashboard .text-slate-500{color:#c2c0b5 !important}:where(html[data-theme="claude"]) .dark #view-dashboard .text-slate-600{color:#cfcdc2 !important}:where(html[data-theme="claude"]) #view-dashboard .ui-section-kicker{color:#514f49}:where(html[data-theme="claude"]) .dark #view-dashboard .ui-section-kicker{color:#bab8ad}/* 统计卡标签与注释：原 #87867f（约 3.6:1）在纸白上偏淡 */
:where(html[data-theme="claude"]) #view-dashboard [class*="border-l-4"]>p:first-child{color:#54534c !important}:where(html[data-theme="claude"]) #view-dashboard [class*="border-l-4"]>p:last-child{color:#5e5d55 !important}:where(html[data-theme="claude"]) .dark #view-dashboard [class*="border-l-4"]>p:first-child{color:#bcbaaf !important}:where(html[data-theme="claude"]) .dark #view-dashboard [class*="border-l-4"]>p:last-child{color:#aba99f !important}/* 4. 热力图：低值格设 16% 可见下限（数据仍按原比例编码），边界更实 */
:where(html[data-theme="claude"]) #view-dashboard .d1-heat-cell{
  border-color:rgba(176,80,53,.46);
  background:rgba(201,100,66,min(1,max(.16,calc(var(--ui-heat-alpha,.08) * 1.9))));
}:where(html[data-theme="claude"]) #view-dashboard .d1-heat-cell.is-active:hover{
  border-color:rgba(150,64,40,.8);
  box-shadow:0 10px 20px -8px rgba(150,64,40,.5);
}:where(html[data-theme="claude"]) #view-dashboard .d1-heat-cell.is-empty{
  border-color:#c9c2ac;
  background:repeating-linear-gradient(135deg,rgb(var(--ui-c-n-900) / .1) 0 2px,transparent 2px 5px);
}:where(html[data-theme="claude"]) .dark #view-dashboard .d1-heat-cell{
  border-color:rgb(var(--ui-c-a-400) / .5);
  background:rgba(217,119,87,min(1,max(.2,calc(var(--ui-heat-alpha,.12) * 1.8))));
}:where(html[data-theme="claude"]) .dark #view-dashboard .d1-heat-cell.is-active:hover{border-color:rgba(230,175,152,.85)}:where(html[data-theme="claude"]) .dark #view-dashboard .d1-heat-cell.is-empty{
  border-color:#55554e;
  background:repeating-linear-gradient(135deg,rgba(255,253,248,.12) 0 2px,transparent 2px 5px);
}/* 5. 热力图轴标签：11px 下的下限再提一档 */
:where(html[data-theme="claude"]) #view-dashboard .d1-heatmap-col-label{color:#54534c}:where(html[data-theme="claude"]) #view-dashboard .d1-heatmap-row-label{color:#2f2e2a}:where(html[data-theme="claude"]) .dark #view-dashboard .d1-heatmap-col-label{color:#b6b4a9}:where(html[data-theme="claude"]) .dark #view-dashboard .d1-heatmap-row-label{color:#dcdad0}/* ===== 按钮统一：扁平 · 复古工具 UI =====
   一套控件语言：8px 方角、零投影、零渐变，层级只靠 1px 描边 + 底色差；
   实心主按钮用 1px 内描边代替光晕，按下时整体下沉 1px，像按下一枚工具键。 */
html[data-theme="claude"]{--d1-control-radius:8px}:where(html[data-theme="claude"]) #app-shell button,

:where(html[data-theme="claude"]) #app-shell a[class*="btn"],

:where(html[data-theme="claude"]) #app-shell label[class*="btn"],

:where(html[data-theme="claude"]) #app-shell label[class*="border-slate-"],

:where(html[data-theme="claude"]) #app-shell [role="tab"]{
  border-radius:var(--d1-control-radius) !important;
  box-shadow:none !important;
  background-image:none !important;
  text-shadow:none !important;
  -webkit-backdrop-filter:none !important;
  backdrop-filter:none !important;
}/* 与按钮同排的字段/搜索框用同一方角，避免一行里两种圆角打架 */
:where(html[data-theme="claude"]) #app-shell :is(input,select,textarea).rounded-control,

:where(html[data-theme="claude"]) #view-nodes .node-toolbar-search,

:where(html[data-theme="claude"]) #view-logs .rounded-control,

:where(html[data-theme="claude"]) #view-dns .rounded-control{border-radius:var(--d1-control-radius) !important}:where(html[data-theme="claude"]) #app-shell button:hover,

:where(html[data-theme="claude"]) #app-shell a[class*="btn"]:hover,

:where(html[data-theme="claude"]) #app-shell label[class*="btn"]:hover,

:where(html[data-theme="claude"]) #app-shell label[class*="border-slate-"]:hover,

:where(html[data-theme="claude"]) #app-shell [role="tab"]:hover{box-shadow:none !important}/* 实心主按钮：1px 内描边替代投影，边缘依然清晰但不发光 */
:where(html[data-theme="claude"]) #view-nodes .node-toolbar-primary-btn,

:where(html[data-theme="claude"]) #view-nodes .node-toolbar-primary-btn:hover,

:where(html[data-theme="claude"]) #node-modal .node-modal-primary-btn,

:where(html[data-theme="claude"]) #node-modal .node-modal-primary-btn:hover,

:where(html[data-theme="claude"]) #view-settings .set-tab[aria-selected="true"],

:where(html[data-theme="claude"]) [data-ui-dialog-surface="1"] [class*="bg-brand-"],

:where(html[data-theme="claude"]) [data-ui-dialog-surface="1"] [class*="bg-red-600"]{box-shadow:inset 0 0 0 1px rgb(var(--ui-c-n-900) / .18) !important}:where(html[data-theme="claude"]) .dark #view-nodes .node-toolbar-primary-btn,

:where(html[data-theme="claude"]) .dark #view-nodes .node-toolbar-primary-btn:hover,

:where(html[data-theme="claude"]) .dark #node-modal .node-modal-primary-btn,

:where(html[data-theme="claude"]) .dark #node-modal .node-modal-primary-btn:hover,

:where(html[data-theme="claude"]) .dark #view-settings .set-tab[aria-selected="true"],

:where(html[data-theme="claude"]) .dark [data-ui-dialog-surface="1"] [class*="bg-brand-"],

:where(html[data-theme="claude"]) .dark [data-ui-dialog-surface="1"] [class*="bg-red-600"]{box-shadow:inset 0 0 0 1px rgb(var(--ui-c-white) / .16) !important}/* 按下 = 下沉 1px（排除绝对定位按钮，避免位移错位） */
:where(html[data-theme="claude"]) #app-shell button:not([class*="absolute"]):active{transform:translateY(1px)}:where(html[data-theme="claude"]) #app-shell [role="tab"]:active{transform:none}/* ===== 设置页控件：并入同一套扁平工具 UI =====
   设置页自带的控件层把输入框留在 12–16px 圆角与轻投影上，与按钮的 8px 方角打架；
   这里只收敛 #view-settings 内的表单控件与可点标签，不动其他视图与面板圆角。 */
:where(html[data-theme="claude"]) #view-settings :is(input,select,textarea):not([type="checkbox"]):not([type="radio"]):not([type="range"]){
  border-radius:var(--d1-control-radius) !important;
  box-shadow:none !important;
  background-image:none !important;
}/* 投影统一归零后，焦点改用外描边环，避免键盘操作失去可见焦点 */
:where(html[data-theme="claude"]) #view-settings :is(input,select,textarea):focus-visible{outline:2px solid rgb(var(--ui-c-a-500));outline-offset:1px}:where(html[data-theme="claude"]) #view-settings :is(input[type="checkbox"],input[type="radio"]){accent-color:rgb(var(--ui-c-a-500));box-shadow:none !important}:where(html[data-theme="claude"]) #view-settings :is([role="button"],label[class*="rounded-control"],.settings-secondary-label){
  border-radius:var(--d1-control-radius) !important;
  box-shadow:none !important;
  background-image:none !important;
}:where(html[data-theme="claude"]) #view-settings :is([role="button"],label[class*="rounded-control"]):active{transform:translateY(1px)}:where(html[data-theme="claude"]) #view-settings button:disabled{transform:none !important}/* 选项卡 / 分段标签：没带 rounded-control、只靠 border-slate / bg-slate / border-brand
   拼出来的可点卡片，同样并入 8px 方角与零投影，避免和同排按钮两种圆角 */
:where(html[data-theme="claude"]) #view-settings :is(label,a):is([class*="border-slate-200"],[class*="border-slate-300"],[class*="bg-slate-200"],[class*="border-brand-"],[class*="bg-brand-"]){
  border-radius:var(--d1-control-radius) !important;
  box-shadow:none !important;
  background-image:none !important;
}:where(html[data-theme="claude"]) #view-settings :is(label,a):is([class*="border-slate-200"],[class*="border-slate-300"],[class*="bg-slate-200"],[class*="border-brand-"]):focus-visible{outline:2px solid rgb(var(--ui-c-a-500));outline-offset:1px}:where(html[data-theme="claude"]) #view-settings :is(label,a):is([class*="border-slate-200"],[class*="border-slate-300"],[class*="bg-slate-200"]):active{transform:translateY(1px)}/* 缓存区的危险操作键（Purge）：实心砖红的老式工具键——8px 方角、零投影零渐变、
   1px 深色内描边，悬停只加深不发光，按下沉 1px。按 id 定形，不依赖 class 串，
   作用域只到这一个按钮，不会波及其他页面的红描边键。 */
:where(html[data-theme="claude"]) #app-shell #purge-cache-btn{
  border:1px solid #8f2b21 !important;
  border-radius:var(--d1-control-radius) !important;
  background-color:#b23a2c !important;
  background-image:none !important;
  box-shadow:inset 0 0 0 1px rgb(var(--ui-c-n-900) / .16) !important;
  color:#fbf9f4 !important;
  font-weight:600;
  letter-spacing:.01em;
  text-shadow:none !important;
  transition:background-color .12s ease,border-color .12s ease,color .12s ease;
}:where(html[data-theme="claude"]) #app-shell #purge-cache-btn:hover{
  background-color:#9c3125 !important;
  border-color:#7a251d !important;
  color:var(--d1-on-accent) !important;
  box-shadow:inset 0 0 0 1px rgb(var(--ui-c-n-900) / .2) !important;
}:where(html[data-theme="claude"]) #app-shell #purge-cache-btn:active{
  transform:translateY(1px);
  background-color:#8a2b20 !important;
  border-color:#6d211a !important;
}:where(html[data-theme="claude"]) #app-shell #purge-cache-btn:focus-visible{outline:2px solid rgb(var(--ui-c-a-500));outline-offset:2px}:where(html[data-theme="claude"]) .dark #app-shell #purge-cache-btn{
  background-color:#8f2b21 !important;
  border-color:#b5453a !important;
  color:#fdf2ee !important;
}:where(html[data-theme="claude"]) .dark #app-shell #purge-cache-btn:hover{
  background-color:#a3342a !important;
  border-color:#c9554a !important;
  color:var(--d1-on-accent) !important;
}/* 管理页上传控件（index.html / worker.js）：并入同一套扁平复古工具键——8px 方角、
   零投影零渐变，选择键用 1px 描边定形，悬停只加深不发光，按下沉 1px。 */
:where(html[data-theme="claude"]) [data-admin-index-file-input="1"],
:where(html[data-theme="claude"]) [data-admin-worker-file-input="1"]{
  border-radius:var(--d1-control-radius);
  box-shadow:none;
  background-image:none;
  color:#2f2e2a;
  font-size:13px;
  line-height:1.2;
  padding:0;
  max-width:100%;
}:where(html[data-theme="claude"]) [data-admin-index-file-input="1"]::file-selector-button,
:where(html[data-theme="claude"]) [data-admin-worker-file-input="1"]::file-selector-button{
  margin:0 10px 0 0;
  padding:5px 12px;
  border:1px solid rgb(var(--ui-c-n-900) / .24);
  border-radius:var(--d1-control-radius);
  background-color:transparent;
  background-image:none;
  box-shadow:none;
  color:#2f2e2a;
  font:inherit;
  font-weight:600;
  letter-spacing:.01em;
  cursor:pointer;
  transition:background-color .12s ease,border-color .12s ease,color .12s ease;
}:where(html[data-theme="claude"]) [data-admin-index-file-input="1"]::file-selector-button:hover,
:where(html[data-theme="claude"]) [data-admin-worker-file-input="1"]::file-selector-button:hover{
  background-color:rgb(var(--ui-c-n-900) / .06);
  border-color:rgb(var(--ui-c-n-900) / .42);
  color:rgb(var(--ui-c-n-900));
  box-shadow:none;
}:where(html[data-theme="claude"]) [data-admin-index-file-input="1"]::file-selector-button:active,
:where(html[data-theme="claude"]) [data-admin-worker-file-input="1"]::file-selector-button:active{
  transform:translateY(1px);
  background-color:rgb(var(--ui-c-n-900) / .1);
  border-color:rgb(var(--ui-c-n-900) / .5);
}:where(html[data-theme="claude"]) [data-admin-index-file-input="1"]:focus-visible,
:where(html[data-theme="claude"]) [data-admin-worker-file-input="1"]:focus-visible{outline:2px solid rgb(var(--ui-c-a-500));outline-offset:2px}:where(html[data-theme="claude"]) .dark [data-admin-index-file-input="1"],
:where(html[data-theme="claude"]) .dark [data-admin-worker-file-input="1"]{color:#dcdad0}:where(html[data-theme="claude"]) .dark [data-admin-index-file-input="1"]::file-selector-button,
:where(html[data-theme="claude"]) .dark [data-admin-worker-file-input="1"]::file-selector-button{
  border-color:rgb(var(--ui-c-white) / .26);
  color:rgb(var(--ui-c-n-200));
}:where(html[data-theme="claude"]) .dark [data-admin-index-file-input="1"]::file-selector-button:hover,
:where(html[data-theme="claude"]) .dark [data-admin-worker-file-input="1"]::file-selector-button:hover{
  background-color:rgb(var(--ui-c-white) / .1);
  border-color:rgb(var(--ui-c-white) / .46);
  color:rgb(var(--ui-c-white));
}:where(html[data-theme="claude"]) .dark [data-admin-index-file-input="1"]::file-selector-button:active,
:where(html[data-theme="claude"]) .dark [data-admin-worker-file-input="1"]::file-selector-button:active{
  background-color:rgb(var(--ui-c-white) / .16);
}/* 设置页操作行 · 扁平胶囊主操作（保存 + 其右侧的恢复推荐值） */
:where(html[data-theme="claude"]) #view-settings button[class*="bg-brand-600"],

:where(html[data-theme="claude"]) #view-settings button[class*="border-emerald-200"]{
  border:0 !important;
  border-radius:999px !important;
  background-image:none !important;
  box-shadow:none !important;
  color:var(--d1-on-accent) !important;
  font-weight:400 !important;
  padding:9px 22px !important;
  min-height:40px;
  letter-spacing:.01em;
  transition:background-color .12s ease,color .12s ease;
}:where(html[data-theme="claude"]) #view-settings button[class*="bg-brand-600"]{background-color:var(--d1-action-strong) !important}:where(html[data-theme="claude"]) #view-settings button[class*="border-emerald-200"]{background-color:var(--d1-action) !important}:where(html[data-theme="claude"]) #view-settings button[class*="bg-brand-600"]:hover{background-color:var(--d1-action-strong-hover) !important;color:var(--d1-on-accent) !important}:where(html[data-theme="claude"]) #view-settings button[class*="border-emerald-200"]:hover{background-color:var(--d1-action-hover) !important;color:var(--d1-on-accent) !important}:where(html[data-theme="claude"]) #view-settings button[class*="bg-brand-600"]:active,

:where(html[data-theme="claude"]) #view-settings button[class*="border-emerald-200"]:active{background-color:var(--d1-action-active) !important;color:var(--d1-on-accent) !important}:where(html[data-theme="claude"]) #view-settings button[class*="bg-brand-600"]:focus-visible,

:where(html[data-theme="claude"]) #view-settings button[class*="border-emerald-200"]:focus-visible{outline:2px solid #e3a98f;outline-offset:2px}:where(html[data-theme="claude"]) #view-settings button[class*="bg-brand-600"]:disabled,

:where(html[data-theme="claude"]) #view-settings button[class*="border-emerald-200"]:disabled{opacity:.55;color:var(--d1-on-accent) !important}/* 审计修复 · 次要操作（导入备份 / 发送测试通知）→ 扁平实底胶囊 */
:where(html[data-theme="claude"]) #view-settings .settings-secondary-label,

:where(html[data-theme="claude"]) #view-settings button[class*="border-blue-200"][class*="text-blue-600"],

:where(html[data-theme="claude"]) .dark #view-settings button[class*="border-blue-200"][class*="text-blue-600"]{
  border:0 !important;border-radius:999px !important;background-image:none !important;box-shadow:none !important;
  background-color:var(--d1-action) !important;color:var(--d1-on-accent) !important;font-weight:400 !important;
  padding:9px 22px !important;min-height:40px;letter-spacing:.01em;
  transition:background-color .12s ease,color .12s ease}:where(html[data-theme="claude"]) .dark #view-settings .settings-secondary-label{background-color:var(--d1-action-dark) !important;border:0 !important;color:var(--d1-on-accent) !important}:where(html[data-theme="claude"]) #view-settings .settings-secondary-label:hover,

:where(html[data-theme="claude"]) .dark #view-settings .settings-secondary-label:hover,

:where(html[data-theme="claude"]) #view-settings button[class*="border-blue-200"][class*="text-blue-600"]:hover,

:where(html[data-theme="claude"]) .dark #view-settings button[class*="border-blue-200"][class*="text-blue-600"]:hover{background-color:var(--d1-action-hover) !important;color:var(--d1-on-accent) !important;border:0 !important}:where(html[data-theme="claude"]) .dark #view-settings .settings-secondary-label:hover{background-color:var(--d1-action-strong) !important;color:var(--d1-on-accent) !important}:where(html[data-theme="claude"]) #view-settings .settings-secondary-label:active,

:where(html[data-theme="claude"]) #view-settings button[class*="border-blue-200"][class*="text-blue-600"]:active{background-color:var(--d1-action-active) !important;color:var(--d1-on-accent) !important}:where(html[data-theme="claude"]) #view-settings .settings-secondary-label:focus-visible,

:where(html[data-theme="claude"]) #view-settings button[class*="border-blue-200"][class*="text-blue-600"]:focus-visible{outline:2px solid #e3a98f;outline-offset:2px}/* 审计修复 · 文件选择键 → 同一扁平胶囊语言（去掉描边幽灵形态） */
:where(html[data-theme="claude"]) [data-admin-index-file-input="1"]::file-selector-button,

:where(html[data-theme="claude"]) [data-admin-worker-file-input="1"]::file-selector-button{
  border:0 !important;border-radius:999px !important;background-image:none !important;box-shadow:none !important;
  background-color:var(--d1-action) !important;color:var(--d1-on-accent) !important;font-weight:400 !important;
  padding:8px 20px !important;letter-spacing:.01em;cursor:pointer}:where(html[data-theme="claude"]) [data-admin-index-file-input="1"]::file-selector-button:hover,

:where(html[data-theme="claude"]) [data-admin-worker-file-input="1"]::file-selector-button:hover{background-color:var(--d1-action-hover) !important;color:var(--d1-on-accent) !important}:where(html[data-theme="claude"]) [data-admin-index-file-input="1"]::file-selector-button:active,

:where(html[data-theme="claude"]) [data-admin-worker-file-input="1"]::file-selector-button:active{background-color:var(--d1-action-active) !important;transform:none}:where(html[data-theme="claude"]) .dark [data-admin-index-file-input="1"]::file-selector-button,

:where(html[data-theme="claude"]) .dark [data-admin-worker-file-input="1"]::file-selector-button{background-color:var(--d1-action-dark) !important;border:0 !important;color:var(--d1-on-accent) !important}:where(html[data-theme="claude"]) .dark [data-admin-index-file-input="1"]::file-selector-button:hover,

:where(html[data-theme="claude"]) .dark [data-admin-worker-file-input="1"]::file-selector-button:hover{background-color:var(--d1-action-strong) !important;color:var(--d1-on-accent) !important}/* 设置页其余「导入备份」类次要按钮（不同 class 变体）一并并入胶囊语言 */
:where(html[data-theme="claude"]) #view-settings label[class*="settings-secondary"]:not(.settings-secondary-label),

:where(html[data-theme="claude"]) .dark #view-settings label[class*="settings-secondary"]:not(.settings-secondary-label){
  border:0 !important;border-radius:999px !important;background-image:none !important;box-shadow:none !important;
  background-color:var(--d1-action) !important;color:var(--d1-on-accent) !important;font-weight:400 !important;
  padding:9px 22px !important;min-height:40px;letter-spacing:.01em}:where(html[data-theme="claude"]) #view-settings label[class*="settings-secondary"]:not(.settings-secondary-label):hover{background-color:var(--d1-action-hover) !important;color:var(--d1-on-accent) !important}/* ===== 设置页左侧导航 · 与「全局设置」「UI 圆角弧度」同一套标题宋体（图2 / 图4）=====
   直接复用设计令牌 --font-display（Noto Serif SC → 宋体 / SimSun → Georgia），
   不再单独造圆体栈：图2、图4 就是页面里已有的标题字，导航对齐它们即可。 */
:where(html[data-theme="claude"]) #view-settings .settings-nav-shell [role="tab"],

:where(html[data-theme="claude"]) #view-settings .set-tab{
  font-family:var(--font-display) !important;
  font-size:14px !important;
  line-height:1.4 !important;
  font-weight:400 !important;
  letter-spacing:.01em !important;
  padding:9.5px 14px !important;
  min-height:41px;
  text-shadow:none !important;
}:where(html[data-theme="claude"]) #view-settings .settings-nav-shell [role="tab"] .block,

:where(html[data-theme="claude"]) #view-settings .set-tab .block{
  font-family:inherit !important;
  font-size:inherit !important;
  font-weight:400 !important;
  letter-spacing:.01em !important;
  line-height:1.4 !important;
}/* 选中项用更重的衬线字重（图4 的粗宋），未选中保持图2 的常规宋 */
:where(html[data-theme="claude"]) #view-settings .settings-nav-shell [role="tab"][aria-selected="true"] .block,

:where(html[data-theme="claude"]) #view-settings .set-tab[aria-selected="true"] .block{font-weight:700 !important}/* 面板标题「全局设置导航」：与 .ui-section-title（调度时区等面板标题）同字号同字族；SETTINGS 眉标不动 */
:where(html[data-theme="claude"]) #view-settings .settings-nav-shell > div > div.text-\\[13px\\]{
  font-family:var(--font-display) !important;
  font-size:1.0625rem !important;
  line-height:1.5rem !important;
  font-weight:700 !important;
  letter-spacing:.01em !important;
}
:where(html[data-theme="claude"]) #app-shell [data-admin-brand-shell="1"]{min-width:0;padding-inline:1.25rem}
:where(html[data-theme="claude"]) #app-shell [data-admin-brand-mark="1"]{flex:0 0 auto}
:where(html[data-theme="claude"]) #app-shell [data-admin-brand-title="1"]{margin-left:.75rem;min-width:0;font-size:1.0625rem;line-height:1.5rem;letter-spacing:-.01em;white-space:nowrap;overflow:hidden}
:where(html[data-theme="claude"]) #app-shell [data-admin-brand-title="1"]>span{flex:0 0 auto;white-space:nowrap}
#view-settings .settings-theme-skin-card [data-admin-skin-option]{transition:background-color .16s ease,border-color .16s ease,color .16s ease}
#view-settings .settings-theme-skin-card [data-admin-skin-option][aria-pressed="true"]{border-color:rgb(var(--ui-c-a-200));background:rgb(var(--ui-c-a-50));color:rgb(var(--ui-c-a-700))}
.dark #view-settings .settings-theme-skin-card [data-admin-skin-option][aria-pressed="true"]{border-color:rgb(var(--ui-c-a-500));background:rgb(var(--ui-c-a-500) / .14);color:rgb(var(--ui-c-a-200))}
/* 侧栏收起/展开：文字随宽度裁切并淡出，而不是瞬间消失（所有皮肤一致） */
#sidebar [data-admin-brand-title="1"]{min-width:0;white-space:nowrap;overflow:hidden}
#sidebar [data-admin-brand-title="1"]>span{flex:0 0 auto;white-space:nowrap}
#sidebar .nav-item>span{white-space:nowrap}
@media (min-width:768px){
#sidebar [data-admin-brand-title="1"],
#sidebar .nav-item>span{transition:display .24s allow-discrete,opacity .18s ease}
#sidebar[class*="5.5rem"] [data-admin-brand-title="1"],
#sidebar[class*="5.5rem"] .nav-item>span{opacity:0}
}
@media (prefers-reduced-motion:reduce){
#sidebar [data-admin-brand-title="1"],
#sidebar .nav-item>span{transition:none}
}
/* 设置导航尺寸对齐主题B：面板内边距 / 页签高度与字号 / 导航标题字号（所有皮肤） */
#view-settings .settings-nav-shell{padding:1.375rem}
#view-settings .settings-nav-shell [role="tab"],
#view-settings .set-tab{font-size:14px;line-height:1.4;padding:9.5px 14px;min-height:41px}
#view-settings .settings-nav-shell [role="tab"] .block,
#view-settings .set-tab .block{font-size:inherit;line-height:1.4}
#view-settings .settings-nav-shell>div:first-child>div:last-child{font-size:1rem;line-height:1.5rem}
/* 主题B：设置页「整理 KV 数据 / 整理 D1 数据」用红豆实心填充，白字白图标，图标与文字同一行居中 */
:where(html[data-theme="claude"]) #view-settings button.border-amber-300.text-amber-700{display:inline-flex;align-items:center;justify-content:center;gap:.375rem;white-space:nowrap;text-align:center;border-color:var(--d1-bean);background:var(--d1-bean);color:var(--d1-on-accent)}
:where(html[data-theme="claude"]) #view-settings button.border-amber-300.text-amber-700>i{margin-right:0;color:var(--d1-on-accent)}
:where(html[data-theme="claude"]) #view-settings button.border-amber-300.text-amber-700:hover{border-color:var(--d1-bean-deep);background:var(--d1-bean-deep);color:var(--d1-on-accent)}
:where(html[data-theme="claude"]) .dark #view-settings button.border-amber-300.text-amber-700{border-color:var(--d1-bean);background:var(--d1-bean);color:var(--d1-on-accent)}
:where(html[data-theme="claude"]) .dark #view-settings button.border-amber-300.text-amber-700:hover{border-color:var(--d1-bean-deep);background:var(--d1-bean-deep);color:var(--d1-on-accent)}
/* 主题B：迁移与备份的「导入备份 / 导出…」同样红豆实心填充，白字白图标，图标与文字同一行居中 */
:where(html[data-theme="claude"]) #view-settings .settings-secondary-label,
:where(html[data-theme="claude"]) #view-settings .flex.gap-4.flex-wrap>button[class*="bg-brand-600"]{display:inline-flex;align-items:center;justify-content:center;gap:.375rem;white-space:nowrap;text-align:center;flex:0 0 auto;border:0 !important;background:var(--d1-bean) !important;color:var(--d1-on-accent) !important}
:where(html[data-theme="claude"]) #view-settings .settings-secondary-label>i,
:where(html[data-theme="claude"]) #view-settings .flex.gap-4.flex-wrap>button[class*="bg-brand-600"]>i{margin-right:0;color:var(--d1-on-accent)}
:where(html[data-theme="claude"]) #view-settings .settings-secondary-label:hover,
:where(html[data-theme="claude"]) #view-settings .flex.gap-4.flex-wrap>button[class*="bg-brand-600"]:hover{background:var(--d1-bean-deep) !important;color:var(--d1-on-accent) !important}
:where(html[data-theme="claude"]) .dark #view-settings .settings-secondary-label,
:where(html[data-theme="claude"]) .dark #view-settings .flex.gap-4.flex-wrap>button[class*="bg-brand-600"]{border:0 !important;background:var(--d1-bean) !important;color:var(--d1-on-accent) !important}
:where(html[data-theme="claude"]) .dark #view-settings .settings-secondary-label:hover,
:where(html[data-theme="claude"]) .dark #view-settings .flex.gap-4.flex-wrap>button[class*="bg-brand-600"]:hover{background:var(--d1-bean-deep) !important;color:var(--d1-on-accent) !important}
/* 主题B：账号页「一键清理全站缓存 (Purge)」并入同一套红豆实心按钮 */
:where(html[data-theme="claude"]) #view-settings button.border-red-200.text-red-600{display:inline-flex;align-items:center;justify-content:center;gap:.375rem;white-space:nowrap;text-align:center;border-color:var(--d1-bean) !important;background:var(--d1-bean) !important;color:var(--d1-on-accent) !important}
:where(html[data-theme="claude"]) #view-settings button.border-red-200.text-red-600:hover{border-color:var(--d1-bean-deep) !important;background:var(--d1-bean-deep) !important;color:var(--d1-on-accent) !important}
/* 所有皮肤：设置页面板标题的标签回到最右侧，与标题同一条底边对齐，并去掉外围胶囊包裹 */
#view-settings .ui-block-head{flex-direction:row;align-items:flex-end !important;justify-content:space-between;gap:.75rem}
#view-settings .ui-block-head>span{margin:0 !important;border:0 !important;border-radius:0 !important;background:none !important;padding:0 !important;box-shadow:none !important;line-height:1.4;flex:0 0 auto;text-align:right;white-space:nowrap}
/* 主题B：界面主题选择按钮在本皮肤内改用暖纸底色 + 红豆描边，而不是蓝色高亮 */
:where(html[data-theme="claude"]) #view-settings .settings-theme-skin-card [data-admin-skin-option][aria-pressed="true"]{border-color:var(--d1-bean);background:rgb(var(--ui-c-n-50));color:var(--d1-bean)}
:where(html[data-theme="claude"]) .dark #view-settings .settings-theme-skin-card [data-admin-skin-option][aria-pressed="true"]{border-color:var(--d1-bean);background:var(--d1-raised-dark);color:#fa9a80}

/* 主题B：日志表格单元格垂直居中（资源类别标签撑高行时，节点/IP/UA 等文字不再贴基线） */
:where(html[data-theme="claude"]) #view-logs #logs-tbody td,
:where(html[data-theme="claude"]) #view-logs thead th{vertical-align:middle}
/* 亮暗切换：换色这一帧先统一关掉所有元素各自的过渡，让颜色一步落地，
   再由 View Transition 做一次整页交叉淡入。否则上百个 transition 各按各的时长
   在 sRGB 里插值，中途发灰、收尾错开，看起来就是闪烁。 */
html[data-theme-switching],
html[data-theme-switching] *,
html[data-theme-switching] *::before,
html[data-theme-switching] *::after{transition:none !important}
::view-transition-old(root),
::view-transition-new(root){animation-duration:.22s;animation-timing-function:cubic-bezier(.22,1,.36,1)}
/* 凭据字段旁的跳转图标：跟随正文色阶，悬停才亮起，不做常驻高饱和色。 */
#app-shell [data-admin-credential-link]{display:inline-flex;align-items:center;margin-left:.375rem;vertical-align:-.15em;color:rgb(var(--ui-c-n-400));transition:color .18s ease}
#app-shell [data-admin-credential-link]:hover{color:#0284c7}
.dark #app-shell [data-admin-credential-link]:hover{color:#7dd3fc}
#app-shell [data-admin-credential-link]:focus-visible{outline:none;border-radius:4px;box-shadow:0 0 0 2px rgba(2,132,199,.3)}
#app-shell [data-admin-credential-link] svg{width:.875rem;height:.875rem}
</style>`;
// 这段脚本被注入到 </head> 前，早于 <body> 里定义 window.App 的编译 bundle。
// 因此补丁不能同步应用：入口只装事件与观察器，真正打补丁的是 scheduleShellRefresh() 排的那一帧。
const ADMIN_RUNTIME_ENHANCEMENT_SCRIPT = `<script data-admin-runtime-enhancements="1">
(() => {
  if (window.__ADMIN_RUNTIME_ENHANCEMENTS_READY__) return;
  window.__ADMIN_RUNTIME_ENHANCEMENTS_READY__ = true;
  installAdminBootstrapFetchDedupe();

  const enqueue = typeof window.requestAnimationFrame === 'function'
    ? window.requestAnimationFrame.bind(window)
    : (callback) => window.setTimeout(callback, 16);
  const brandIconSvg = '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M7.25 5.75h9.5" stroke="currentColor" stroke-width="2.15" stroke-linecap="round"/><path d="M7.25 12h6.75" stroke="currentColor" stroke-width="2.15" stroke-linecap="round"/><path d="M7.25 18.25h9.5" stroke="currentColor" stroke-width="2.15" stroke-linecap="round"/><path d="M7.25 5.75v12.5" stroke="currentColor" stroke-width="2.15" stroke-linecap="round"/></svg>';
  const wikiTutorialUrl = 'https://wiki.8081666.xyz/新手教程';

  const UI_SKIN_STORAGE_KEY = 'adminUiSkin';
  const UI_SKIN_CLASSIC = 'classic';
  const UI_SKIN_CLAUDE = 'claude';
  const UI_SKIN_OPTION_BASE = 'px-4 py-2 rounded-control border text-sm font-medium';
  const UI_SKIN_OPTION_ON =
    'border-brand-300 bg-brand-50 text-brand-700 dark:border-slate-600 dark:bg-slate-800 dark:text-white';
  const UI_SKIN_OPTION_OFF =
    'border-slate-200 bg-white text-slate-600 hover:border-slate-300 hover:bg-slate-50 hover:text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-slate-600 dark:hover:bg-slate-800 dark:hover:text-white';
  const UI_SKIN_FONT_LINKS = [
    { rel: 'preconnect', href: 'https://fonts.googleapis.com' },
    { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossOrigin: 'anonymous' },
    {
      rel: 'stylesheet',
      href: 'https://fonts.googleapis.com/css2?family=Noto+Serif+SC:wght@500;600;700&family=JetBrains+Mono:wght@400;500&family=Nunito:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap'
    },
    { rel: 'stylesheet', href: 'https://unpkg.com/lxgw-wenkai-screen-webfont@1.7.0/style.css' }
  ];

  function readStoredUiSkin() {
    try {
      return localStorage.getItem(UI_SKIN_STORAGE_KEY) === UI_SKIN_CLAUDE
        ? UI_SKIN_CLAUDE
        : UI_SKIN_CLASSIC;
    } catch {
      return UI_SKIN_CLASSIC;
    }
  }

  function normalizeUiSkin(skin = '') {
    return skin === UI_SKIN_CLAUDE ? UI_SKIN_CLAUDE : UI_SKIN_CLASSIC;
  }

  // 服务端把皮肤注入运行时 bootstrap，首帧就能按 KV 配置落主题，不用等 app 启动。
  function readBootstrapUiSkin() {
    try {
      const skin = window.__ADMIN_BOOTSTRAP__?.adminUiSkin;
      return skin === UI_SKIN_CLASSIC || skin === UI_SKIN_CLAUDE ? skin : '';
    } catch {
      return '';
    }
  }

  function ensureUiSkinFonts() {
    if (typeof document?.createElement !== 'function' || !document?.head) return;
    if (document.head.querySelector('link[data-admin-skin-font="1"]')) return;
    for (const item of UI_SKIN_FONT_LINKS) {
      const link = document.createElement('link');
      link.setAttribute('data-admin-skin-font', '1');
      link.rel = item.rel;
      link.href = item.href;
      if (item.crossOrigin) link.crossOrigin = item.crossOrigin;
      document.head.appendChild(link);
    }
  }

  function applyUiSkin(skin, options = {}) {
    const next = normalizeUiSkin(skin);
    if (next === UI_SKIN_CLAUDE) ensureUiSkinFonts();
    document?.documentElement?.setAttribute?.('data-theme', next);
    if (options.persist) {
      try {
        localStorage.setItem(UI_SKIN_STORAGE_KEY, next);
      } catch {}
    }
    return next;
  }

  function resolveCurrentUiSkin(app = window.App) {
    const serverSkin = app?.runtimeConfig?.adminUiSkin;
    if (serverSkin === UI_SKIN_CLASSIC || serverSkin === UI_SKIN_CLAUDE) return serverSkin;
    if (app?.uiSkin === UI_SKIN_CLAUDE) return UI_SKIN_CLAUDE;
    if (document?.documentElement?.getAttribute?.('data-theme') === UI_SKIN_CLAUDE)
      return UI_SKIN_CLAUDE;
    return readStoredUiSkin();
  }

  // 皮肤存 KV；app 拿到 bootstrap 配置后，本机缓存与服务器不一致时以服务器为准。
  function syncServerUiSkin(app = window.App) {
    const serverSkin = app?.runtimeConfig?.adminUiSkin;
    if (serverSkin !== UI_SKIN_CLASSIC && serverSkin !== UI_SKIN_CLAUDE) return;
    if (app?.uiSkin === serverSkin) return;
    if (typeof app?.setUiSkin === 'function') app.setUiSkin(serverSkin);
    else applyUiSkin(serverSkin, { persist: true });
  }

  // 皮肤是整份配置写入，必须过乐观锁：连续点击、同一页面上的设置保存、其它设备的改动
  // 都会让版本号对不上。皮肤本身只是单字段开关，冲突时取一份最新配置与版本号再写一次即可，
  // 不该把「配置版本已变化」甩给用户；同时串行化，避免两次并发写互相踩版本号。
  const uiSkinSaveState = { running: false, target: '', saved: '' };

  async function saveUiSkinConfig(app, skin, config, expectedRevision) {
    const base = config && typeof config === 'object' ? config : app?.runtimeConfig || {};
    return await app.apiCall('saveConfig', {
      config: { ...base, adminUiSkin: skin },
      expectedConfigRevision: String(expectedRevision || ''),
      meta: { section: 'ui', source: 'skin' }
    });
  }

  // 只能拿服务端的当前版本，本地 adminRevisions 正是过期的那一份。
  async function readUiSkinSaveBase(app) {
    const bootstrap = await app.apiCall('getSettingsBootstrap', { forceRefresh: true });
    return {
      config: bootstrap?.config && typeof bootstrap.config === 'object' ? bootstrap.config : null,
      revision: String(bootstrap?.revisions?.configRevision || '')
    };
  }

  async function persistUiSkinPreference(app, skin) {
    if (typeof app?.apiCall !== 'function') return;
    uiSkinSaveState.target = normalizeUiSkin(skin);
    if (uiSkinSaveState.running) return;
    uiSkinSaveState.running = true;
    try {
      while (true) {
        const target = uiSkinSaveState.target;
        // 保存中的点击只记最后一次选择：已经落地或已被更晚的选择覆盖就退出。
        if (!target || target === uiSkinSaveState.saved) break;
        uiSkinSaveState.target = '';
        let result;
        try {
          result = await saveUiSkinConfig(
            app,
            target,
            app.runtimeConfig,
            app.adminRevisions?.configRevision
          );
        } catch (error) {
          if (String(error?.code || '').toUpperCase() !== 'CONFIG_REVISION_CONFLICT') throw error;
          const fresh = await readUiSkinSaveBase(app);
          result = await saveUiSkinConfig(app, target, fresh.config, fresh.revision);
        }
        uiSkinSaveState.saved = normalizeUiSkin(result?.config?.adminUiSkin || target);
        if (result?.revisions && typeof app.applyAdminRevisions === 'function')
          app.applyAdminRevisions(result.revisions);
        if (app.runtimeConfig && typeof app.runtimeConfig === 'object')
          app.runtimeConfig.adminUiSkin = uiSkinSaveState.saved;
      }
    } catch (error) {
      console.error('ui skin save failed', error);
      if (typeof app?.showMessage === 'function')
        app.showMessage('界面主题已在本机生效，但保存到 Worker 配置失败：' + (error?.message || '未知错误'), { tone: 'warning', modal: true });
    } finally {
      uiSkinSaveState.running = false;
    }
  }

  function syncThemeSkinPanel(app = window.App) {
    const root = document?.getElementById?.('admin-theme-skin-root');
    if (!root) return;
    if (!root.dataset.adminThemeSkinReady) {
      root.dataset.adminThemeSkinReady = '1';
      root.innerHTML =
        '<div class="ui-block-head"><div><div class="ui-section-kicker">Theme</div><div class="ui-section-title">界面主题</div></div><span class="ui-chip-muted">全局</span></div>' +
        '<p class="text-xs text-slate-500 mb-3 ml-6">切换管理界面的视觉主题，保存到 Worker 配置后对所有管理端生效，当前浏览器立即应用。</p>' +
        '<div class="ml-6 flex flex-wrap gap-2" role="group" aria-label="\u754c\u9762\u4e3b\u9898">' +
        '<button type="button" data-admin-skin-option="classic">\u7ecf\u5178\u84dd</button>' +
        '<button type="button" data-admin-skin-option="claude">\u6696\u7eb8</button>' +
        '</div>';
      root.querySelectorAll('[data-admin-skin-option]').forEach((button) => {
        button.addEventListener('click', () => {
          const next = normalizeUiSkin(button.getAttribute('data-admin-skin-option'));
          applyUiSkin(next);
          if (typeof app?.setUiSkin === 'function') app.setUiSkin(next);
          else applyUiSkin(next, { persist: true });
          // 先乐观更新运行时配置，避免下一帧的 syncServerUiSkin 把选择回滚成旧值。
          if (app?.runtimeConfig && typeof app.runtimeConfig === 'object') app.runtimeConfig.adminUiSkin = next;
          syncThemeSkinPanel(app);
          persistUiSkinPreference(app, next);
        });
      });
    }
    const active = resolveCurrentUiSkin(app);
    root.querySelectorAll('[data-admin-skin-option]').forEach((button) => {
      const isActive = button.getAttribute('data-admin-skin-option') === active;
      button.setAttribute('aria-pressed', isActive ? 'true' : 'false');
      button.className = UI_SKIN_OPTION_BASE + ' ' + (isActive ? UI_SKIN_OPTION_ON : UI_SKIN_OPTION_OFF);
    });
  }

  // 主题模式存在 localStorage，但 dark 类原本只由 app 挂载时的 bundle 落。
  // 放进 head 阶段后，首帧主题不再依赖 Vue 运行时是否成功起来。
  // 'theme' 与 bundle 的 UI_STORAGE_KEYS.theme 同值。
  function resolveInitialUiThemeMode() {
    let stored = '';
    try {
      stored = localStorage.getItem('theme');
    } catch {}
    if (stored === 'dark' || stored === 'light') return stored;
    try {
      return window.matchMedia?.('(prefers-color-scheme: dark)')?.matches ? 'dark' : 'light';
    } catch {
      return 'light';
    }
  }

  function applyUiThemeMode(mode) {
    const isDark = mode === 'dark';
    for (const target of [document?.documentElement, document?.body]) {
      if (!target?.classList) continue;
      target.classList.remove('dark', 'light');
      if (isDark) target.classList.add('dark');
    }
  }

  try {
    applyUiThemeMode(resolveInitialUiThemeMode());
  } catch (error) {
    console.error('ui theme init failed', error);
  }

  try {
    const bootstrapSkin = readBootstrapUiSkin();
    if (bootstrapSkin) applyUiSkin(bootstrapSkin, { persist: true });
    else applyUiSkin(readStoredUiSkin());
  } catch (error) {
    console.error('ui skin init failed', error);
  }

  const shellHookSelector = '[data-admin-toolbar-group="title"],[data-admin-toolbar-group="actions"],[data-admin-page-title="1"],[data-admin-brand-shell="1"],[data-admin-brand-title="1"],[data-admin-brand-mark="1"],#view-dashboard,#view-nodes,#view-logs,#view-settings,#node-modal';
  let iconFrameId = 0;
  let shellFrameId = 0;
  let nodeModalWasOpen = false;
  let patchedSafetyContractApp = null;
  let tmdbPatchedApp = null;
  const dashboardTrafficState = {
    period: 'day',
    daily: null,
    monthly: null,
    monthlyPeriodKey: '',
    monthlyExpiresAt: 0,
    monthlyAvailable: false,
    pending: false
  };
  const DASHBOARD_MONTHLY_TRAFFIC_CLIENT_TTL_MS = 30 * 60 * 1000;
  // 四层仪表盘请求合并成一次快照读取；60 秒内重复进出直接复用上次结果。
  const DASHBOARD_LAYER_CACHE_TTL_MS = 60 * 1000;
  // 保存后服务端已把完整 config 回传，设置页短时间内不必再拉 bootstrap。
  const SETTINGS_BOOTSTRAP_CACHE_TTL_MS = 10 * 1000;
  // 日志第一页的重复进入不发请求；超过 30 秒或筛选变化才重新拉取。
  const LOG_PAGE_ONE_CACHE_TTL_MS = 30 * 1000;
  const logPageOneCacheState = { signature: '', at: 0 };
  const dashboardLayerState = {
    loadSeq: 0,
    statsLoadedAt: 0,
    runtimeLoadedAt: 0,
    hotspotLoadedAt: 0,
    statsLoading: false,
    runtimeLoading: false,
    hotspotLoading: false
  };

  function normalizeHostPrefixDnsHostname(value = '') {
    const rawText = String(value || '').trim().toLowerCase();
    if (!rawText) return '';
    const text = rawText.endsWith('.') ? rawText.slice(0, -1) : rawText;
    if (!text || text.length > 253 || text.endsWith('.')) return '';
    if (/\\s|[:\\/@*?#\\\\]/.test(text)) return '';
    if (/^(?:\\d{1,3}\\.){3}\\d{1,3}$/.test(text)) {
      const parts = text.split('.').map(Number);
      if (parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)) return '';
    }
    const labels = text.split('.');
    if (labels.some((label) => !label
      || label.length > 63
      || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return '';
    return text;
  }

  function isHostPrefixNodeLinkActive(app, node = {}) {
    const entryMode = String(node?.entryMode || '').trim().toLowerCase();
    return entryMode === 'host_prefix'
      && app?.runtimeConfig?.enableHostPrefixProxy === true
      && !!normalizeHostPrefixDnsHostname(app?.hostDomain);
  }

  function shouldRetainDashboardD1WriteHotspot(hotspot) {
    if (!hotspot || typeof hotspot !== 'object') return false;
    return String(hotspot.status || '').trim().toLowerCase() !== 'idle';
  }

  function retainDashboardD1WriteHotspotInStats(stats, hotspot) {
    const payload = stats && typeof stats === 'object' ? stats : {};
    if (!shouldRetainDashboardD1WriteHotspot(hotspot)) return payload;
    return { ...payload, d1WriteHotspot: hotspot };
  }
  const workerHtmlUpdateState = {
    root: null,
    workerFile: null,
    indexFile: null,
    submitting: false,
    status: '必须同时选择 Worker 脚本和 HTML 文件。',
    tone: ''
  };
  function canRenderIcons() {
    return !!window.lucide && typeof window.lucide.createIcons === 'function';
  }

  function renderIcons(root = document.body) {
    if (!canRenderIcons()) return false;
    try {
      if (root && root.nodeType === Node.ELEMENT_NODE) {
        window.lucide.createIcons({ root });
      } else {
        window.lucide.createIcons({});
      }
      return true;
    } catch (error) {
      console.error('admin runtime lucide refresh failed', error);
      return false;
    }
  }

  function scheduleIconRefresh(root = document.body) {
    if (iconFrameId) return;
    iconFrameId = enqueue(() => {
      iconFrameId = 0;
      renderIcons(root);
    });
  }

  const SENSITIVE_VALUE_PLACEHOLDER = '********';

  function setSensitiveInputVisibility(input, button, revealed) {
    if (!input || !button) return;
    input.type = revealed ? 'text' : 'password';
    button.setAttribute('aria-pressed', revealed ? 'true' : 'false');
    button.setAttribute('aria-label', revealed ? '隐藏敏感信息' : '显示敏感信息');
    button.setAttribute('title', revealed ? '隐藏敏感信息' : '显示敏感信息');
    button.innerHTML = '<i data-lucide="' + (revealed ? 'eye-off' : 'eye') + '" class="h-4 w-4" aria-hidden="true"></i>';
    scheduleIconRefresh(button);
  }

  function syncSensitiveInputPresentation(input, hint = '') {
    if (!input) return;
    const normalizedHint = String(hint || '').trim();
    input.placeholder = SENSITIVE_VALUE_PLACEHOLDER;
    input.dataset.sensitiveHint = normalizedHint;
    if (normalizedHint) input.setAttribute('title', normalizedHint);
    else input.removeAttribute('title');
    input.closest?.('[data-sensitive-input-toggle]')?.querySelector?.('button')?.toggleAttribute('disabled', input.disabled === true);
  }

  function mountSensitiveInputToggle(input) {
    if (!input || input.readOnly || input.dataset.sensitiveToggleBound === 'true') return;
    const basePlaceholder = input.getAttribute('placeholder') || '';
    input.dataset.sensitiveToggleBound = 'true';
    syncSensitiveInputPresentation(input, basePlaceholder);
    input.setAttribute('aria-label', input.getAttribute('aria-label') || '敏感信息');

    const parent = input.parentElement;
    if (!parent) return;
    const wrapper = document.createElement('span');
    wrapper.setAttribute('data-sensitive-input-toggle', '1');
    wrapper.style.cssText = 'position:relative;display:block;min-width:0;';
    parent.insertBefore(wrapper, input);
    wrapper.appendChild(input);
    input.style.paddingRight = '2.75rem';

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'absolute right-2 top-1/2 -translate-y-1/2 inline-flex h-8 w-8 items-center justify-center text-slate-400 transition hover:text-sky-600 focus:outline-none focus:ring-2 focus:ring-sky-500/30 disabled:cursor-not-allowed disabled:opacity-50 dark:text-slate-500 dark:hover:text-sky-300';
    button.disabled = input.disabled;
    button.addEventListener('click', () => {
      setSensitiveInputVisibility(input, button, input.type === 'password');
    });
    wrapper.appendChild(button);
    setSensitiveInputVisibility(input, button, false);
    syncSensitiveInputPresentation(input, basePlaceholder);
  }

  function mountSensitiveInputToggles(root = document) {
    root?.querySelectorAll?.('input[type="password"]:not([readonly])').forEach((input) => mountSensitiveInputToggle(input));
  }

  function scheduleShellRefresh() {
    if (shellFrameId) return;
    shellFrameId = enqueue(() => {
      shellFrameId = 0;
      syncServerUiSkin(window.App);
      applyBrandEnhancements();
      applyToolbarEnhancements();
      applyLayoutEnhancements();
      applySafetyContractEnhancements();
      patchThemeTransitionMethods(window.App);
      patchDnsIpPoolDeleteMethods(window.App);
      mountSensitiveInputToggles(document);
      syncDashboardTrafficToggle(window.App);
    });
  }

  function containsLucidePlaceholder(node) {
    if (!node) return false;
    if (node.matches?.('i[data-lucide]')) return true;
    return !!node.querySelector?.('i[data-lucide]');
  }

  function touchesShellHooks(node) {
    if (!node || node.nodeType !== Node.ELEMENT_NODE) return false;
    if (node.matches?.(shellHookSelector)) return true;
    if (node.closest?.(shellHookSelector)) return true;
    return !!node.querySelector?.(shellHookSelector);
  }

  function touchesDialogLayer(node) {
    if (!node || node.nodeType !== Node.ELEMENT_NODE) return false;
    if (node.matches?.('[data-ui-backdrop], [data-ui-dialog-surface]')) return true;
    return !!node.querySelector?.('[data-ui-backdrop], [data-ui-dialog-surface]');
  }

  function getToolbarNodes() {
    const titleGroup = document.querySelector('[data-admin-toolbar-group="title"]');
    const actionGroup = document.querySelector('[data-admin-toolbar-group="actions"]');
    const titleNode = document.querySelector('[data-admin-page-title="1"]');
    const githubLink = actionGroup?.querySelector('a[href*="github.com/axuitomo/CF-EMBY-PROXY-UI"]') || null;
    const themeButton = actionGroup
      ? [...actionGroup.querySelectorAll('button')].find((button) => button.querySelector('[data-lucide="moon"],[data-lucide="sun"]')) || null
      : null;
    return { titleGroup, actionGroup, titleNode, githubLink, themeButton };
  }

  function getBrandNodes() {
    const brandShell = document.querySelector('[data-admin-brand-shell="1"]');
    if (!brandShell) return {};
    const brandTitle = brandShell.querySelector('[data-admin-brand-title="1"]');
    const brandMark = brandShell.querySelector('[data-admin-brand-mark="1"]');
    return { brandShell, brandTitle, brandMark };
  }

  function applyBrandEnhancements() {
    const { brandTitle, brandMark } = getBrandNodes();
    if (brandTitle) {
      brandTitle.setAttribute('title', String(brandTitle.textContent || '').trim());
    }
    if (!brandMark) return;
    brandMark.setAttribute('data-admin-brand-mark', '1');
    brandMark.setAttribute('aria-hidden', 'true');
    if (brandMark.dataset.adminBrandSvgApplied === '1') return;
    brandMark.dataset.adminBrandSvgApplied = '1';
    brandMark.textContent = '';
    brandMark.innerHTML = brandIconSvg;
  }

  function ensureWikiToolbarLink(actionGroup, themeButton) {
    if (!actionGroup) return null;
    let wikiLink = actionGroup.querySelector('[data-admin-toolbar-action="wiki"]');
    if (!wikiLink) {
      wikiLink = document.createElement('a');
      wikiLink.setAttribute('data-admin-toolbar-action', 'wiki');
      wikiLink.setAttribute('href', wikiTutorialUrl);
      wikiLink.setAttribute('target', '_blank');
      wikiLink.setAttribute('rel', 'noopener noreferrer');
      wikiLink.innerHTML = '<i data-lucide="book-open" aria-hidden="true"></i>';
      actionGroup.insertBefore(wikiLink, themeButton || null);
    }
    wikiLink.setAttribute('title', '打开 WIKI 新手教程');
    wikiLink.setAttribute('aria-label', '打开 WIKI 新手教程');
    return wikiLink;
  }

  function applyToolbarEnhancements() {
    const { titleGroup, actionGroup, titleNode, githubLink, themeButton } = getToolbarNodes();
    if (titleNode) {
      const titleText = String(titleNode.textContent || '').trim();
      titleNode.setAttribute('title', titleText);
    }
    if (githubLink) {
      githubLink.setAttribute('data-admin-toolbar-action', 'github');
      githubLink.setAttribute('aria-label', githubLink.getAttribute('aria-label') || '打开 GitHub 项目主页');
    }
    ensureWikiToolbarLink(actionGroup, themeButton);
    if (themeButton) {
      themeButton.setAttribute('data-admin-toolbar-action', 'theme');
      themeButton.setAttribute('type', 'button');
      const isDark = document.documentElement.classList.contains('dark') || document.body?.classList.contains('dark');
      const nextThemeLabel = isDark ? '切换到亮色模式' : '切换到暗色模式';
      themeButton.setAttribute('data-theme-state', isDark ? 'dark' : 'light');
      themeButton.setAttribute('title', nextThemeLabel);
      themeButton.setAttribute('aria-label', nextThemeLabel);
      if (!themeButton.dataset.adminThemeRefreshBound) {
        themeButton.dataset.adminThemeRefreshBound = '1';
        themeButton.addEventListener('click', () => scheduleShellRefresh());
      }
    }
  }

  function applyNodeToolbarLayout() {
    const search = document.querySelector('#node-search');
    const toolbarRow = search?.parentElement;
    const toolbarMain = toolbarRow?.parentElement;
    const toolbar = toolbarMain?.parentElement;
    if (!toolbarRow || !toolbarMain || !toolbar) return;
    toolbar.setAttribute('data-admin-node-toolbar', '1');
    toolbarMain.setAttribute('data-admin-node-toolbar-main', '1');
    toolbarRow.setAttribute('data-admin-node-toolbar-row', '1');
    const actionGroup = [...toolbar.children].find((child) => child !== toolbarMain) || null;
    actionGroup?.setAttribute('data-admin-node-toolbar-actions', '1');
    // 初始化 DB 复用日志页那条两阶段修复流程（含确认弹窗），排在动作组首位就是为了和
    // 上方的「新建节点」左对齐：两行在 768–1535 断点共用同一列网格起点。
    if (actionGroup) ensureNodeToolbarDbInitButton(actionGroup);
  }

  function ensureNodeToolbarDbInitButton(actionGroup) {
    let button = actionGroup.querySelector('[data-admin-node-db-init="1"]');
    if (!button) {
      button = document.createElement('button');
      button.type = 'button';
      button.setAttribute('data-admin-node-db-init', '1');
      button.setAttribute('title', '初始化 D1 日志表结构');
      button.className = 'inline-flex items-center justify-center whitespace-nowrap rounded-xl bg-slate-200 px-4 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/30 disabled:cursor-not-allowed disabled:opacity-60 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700';
      button.innerHTML = '<i data-lucide="database" class="mr-2 h-4 w-4" aria-hidden="true"></i>初始化 DB';
      button.addEventListener('click', () => {
        const app = window.App;
        if (!app || typeof app.initLogsDbFromUi !== 'function' || button.disabled) return;
        button.disabled = true;
        // 失败提示已经在 initLogsDbFromUi 内部弹过，这里只负责解锁按钮。
        Promise.resolve(app.initLogsDbFromUi()).catch(() => {}).finally(() => {
          button.disabled = false;
        });
      });
    }
    if (actionGroup.firstElementChild !== button) {
      actionGroup.insertBefore(button, actionGroup.firstElementChild);
    }
    return button;
  }

  function formatWorkerHtmlUploadBytes(bytes) {
    const value = Math.max(0, Number(bytes) || 0);
    return value >= 1024 * 1024
      ? (value / (1024 * 1024)).toFixed(2) + ' MiB'
      : Math.round(value / 1024) + ' KiB';
  }

  function buildAdminHardRefreshUrl(revision = '') {
    const url = new URL(window.location.href);
    const normalizedRevision = String(revision || '').trim();
    if (normalizedRevision) url.searchParams.set('__admin_revision', normalizedRevision);
    url.searchParams.set('__admin_reload', Date.now().toString());
    return url;
  }

  function navigateWithAdminCacheBust(revision = '') {
    window.location.replace(buildAdminHardRefreshUrl(revision).toString());
  }

  async function waitForAdminShellRevision(revision = '') {
    const expectedRevision = String(revision || '').trim();
    if (!expectedRevision) return true;
    const delays = [500, 1000, 2000, 4000, 8000];
    for (let attempt = 0; attempt < delays.length; attempt += 1) {
      if (attempt > 0) await new Promise((resolve) => window.setTimeout(resolve, delays[attempt - 1]));
      const probeUrl = buildAdminHardRefreshUrl(expectedRevision);
      probeUrl.searchParams.set('__admin_probe', String(attempt + 1));
      try {
        const response = await window.fetch(probeUrl.toString(), {
          method: 'HEAD',
          credentials: 'same-origin',
          cache: 'reload',
          headers: { Accept: 'text/html' }
        });
        if (response.ok && String(response.headers.get('X-Admin-Shell-Revision') || '').trim() === expectedRevision) return true;
      } catch {
        // Deployment propagation is retried with a bounded backoff.
      }
    }
    return false;
  }

  function validateWorkerHtmlUploadFiles(workerFile, indexFile) {
    // 只看文件类型不看名字：Worker 脚本任意 .js 名、HTML 任意 .html 名都接受。
    if (!workerFile || !indexFile) return '必须同时选择 Worker 脚本和 HTML 文件。';
    if (!String(workerFile.name || '').trim()) return 'Worker 脚本未选择文件。';
    if (!String(indexFile.name || '').trim()) return 'HTML 文件未选择文件。';
    if (workerFile.size > 3 * 1024 * 1024) return 'Worker 脚本超过 3 MiB 上限。';
    if (indexFile.size > 2 * 1024 * 1024) return 'HTML 文件超过 2 MiB 上限。';
    return '';
  }

  function renderWorkerHtmlUpdateState() {
    const state = workerHtmlUpdateState;
    const root = state.root;
    if (!root) return;
    const workerMeta = root.querySelector('[data-admin-worker-file-meta="1"]');
    const indexMeta = root.querySelector('[data-admin-index-file-meta="1"]');
    const status = root.querySelector('[data-admin-worker-html-status="1"]');
    const submitButton = root.querySelector('[data-admin-worker-html-submit="1"]');
    const refreshButton = root.querySelector('[data-admin-worker-html-refresh="1"]');
    const workerInput = root.querySelector('[data-admin-worker-file-input="1"]');
    const indexInput = root.querySelector('[data-admin-index-file-input="1"]');
    const validationError = validateWorkerHtmlUploadFiles(state.workerFile, state.indexFile);
    if (workerMeta) workerMeta.textContent = state.workerFile ? state.workerFile.name + ' · ' + formatWorkerHtmlUploadBytes(state.workerFile.size) : '未选择';
    if (indexMeta) indexMeta.textContent = state.indexFile ? state.indexFile.name + ' · ' + formatWorkerHtmlUploadBytes(state.indexFile.size) : '未选择';
    if (status) {
      status.textContent = state.status || validationError || '两个文件已就绪。';
      status.classList.remove('border-rose-200', 'text-rose-700', 'border-emerald-200', 'text-emerald-700');
      if (state.tone === 'error') status.classList.add('border-rose-200', 'text-rose-700');
      if (state.tone === 'success') status.classList.add('border-emerald-200', 'text-emerald-700');
    }
    if (submitButton) {
      submitButton.disabled = state.submitting || Boolean(validationError);
      const label = submitButton.querySelector('span');
      if (label) label.textContent = state.submitting ? '更新中...' : '同时更新 Worker 和 HTML';
    }
    if (refreshButton) refreshButton.disabled = state.submitting;
    if (workerInput) workerInput.disabled = state.submitting;
    if (indexInput) indexInput.disabled = state.submitting;
    root.setAttribute('aria-busy', state.submitting ? 'true' : 'false');
  }

  async function submitWorkerHtmlUpdate(app) {
    const state = workerHtmlUpdateState;
    const validationError = validateWorkerHtmlUploadFiles(state.workerFile, state.indexFile);
    if (validationError || state.submitting) {
      state.status = validationError || '更新正在执行中。';
      state.tone = 'error';
      renderWorkerHtmlUpdateState();
      return;
    }
    const accepted = typeof app?.askConfirm === 'function'
      ? await app.askConfirm('将同时更新当前 Worker 脚本和管理台 HTML。两个文件必须来自同一版本。', {
          title: '确认 Worker 和 HTML 更新',
          tone: 'warning',
          confirmText: '开始更新'
        })
      : true;
    if (!accepted) return;

    state.submitting = true;
    state.status = '正在读取并校验两个文件...';
    state.tone = '';
    renderWorkerHtmlUpdateState();
    try {
      const fileContents = await Promise.all([state.workerFile.text(), state.indexFile.text()]);
      state.status = '正在更新 HTML 与 Worker...';
      renderWorkerHtmlUpdateState();
      const result = await app.apiCall('updateWorkerAndAdminIndex', {
        workerFileName: state.workerFile.name,
        workerScriptContent: fileContents[0],
        indexFileName: state.indexFile.name,
        indexHtml: fileContents[1]
      });
      if (result?.revisions && typeof app.applyAdminRevisions === 'function') app.applyAdminRevisions(result.revisions);
      state.workerFile = null;
      state.indexFile = null;
      const workerInput = state.root?.querySelector('[data-admin-worker-file-input="1"]');
      const indexInput = state.root?.querySelector('[data-admin-index-file-input="1"]');
      if (workerInput) workerInput.value = '';
      if (indexInput) indexInput.value = '';
      state.status = 'Worker 和 HTML 已同时更新。';
      state.tone = 'success';
      app.showMessage?.('Worker 和 HTML 已更新。', { tone: 'success' });
      const targetRevision = String(result?.html?.revision || '').trim();
      state.status = '更新已提交，正在确认新页面版本...';
      renderWorkerHtmlUpdateState();
      if (await waitForAdminShellRevision(targetRevision)) {
        navigateWithAdminCacheBust(targetRevision);
        return;
      }
      state.status = '更新已完成，但边缘节点尚未确认新页面；请稍后手动刷新。';
    } catch (error) {
      state.status = '更新失败：' + (error?.message || '未知错误');
      state.tone = 'error';
      app.showMessage?.(state.status, { tone: 'error', modal: true });
    } finally {
      state.submitting = false;
      renderWorkerHtmlUpdateState();
    }
  }

  function syncWorkerHtmlUpdatePanel(app = window.App) {
    const root = document.querySelector('#admin-worker-html-update-root');
    if (!root || !app) return;
    if (workerHtmlUpdateState.root !== root) {
      workerHtmlUpdateState.root = root;
      workerHtmlUpdateState.workerFile = null;
      workerHtmlUpdateState.indexFile = null;
      workerHtmlUpdateState.status = '必须同时选择 Worker 脚本和 HTML 文件。';
      workerHtmlUpdateState.tone = '';
    }
    if (!root.dataset.adminWorkerHtmlReady) {
      root.dataset.adminWorkerHtmlReady = '1';
      root.innerHTML = '<div class="ui-block-head"><div><div class="ui-section-kicker">Runtime Update</div><div class="ui-section-title">Worker 和 HTML 更新</div></div><span class="ui-chip-muted">双文件</span></div>'
        + '<div data-admin-worker-html-grid="1">'
        + '<label data-admin-worker-html-file="1"><span class="ui-field-label">Worker 脚本 (.js)</span><input data-admin-worker-file-input="1" type="file" accept=".js,text/javascript,application/javascript"><span data-admin-worker-file-meta="1" class="text-xs text-slate-500">未选择</span></label>'
        + '<label data-admin-worker-html-file="1"><span class="ui-field-label">HTML 文件 (.html)</span><input data-admin-index-file-input="1" type="file" accept=".html,text/html"><span data-admin-index-file-meta="1" class="text-xs text-slate-500">未选择</span></label>'
        + '</div>'
        + '<div data-admin-worker-html-status="1" role="status" aria-live="polite" class="mt-4 rounded-control border border-slate-200 px-4 py-3 text-xs text-slate-600 dark:border-slate-700 dark:text-slate-300"></div>'
        + '<div data-admin-worker-html-actions="1" class="mt-4"><button data-admin-worker-html-refresh="1" type="button" class="settings-secondary-btn h-10 w-10" title="刷新当前页面" aria-label="刷新当前页面"><i data-lucide="refresh-cw" class="w-4 h-4" aria-hidden="true"></i></button><button data-admin-worker-html-submit="1" type="button" class="inline-flex items-center justify-center gap-2 px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white rounded-xl text-sm transition disabled:opacity-50 disabled:pointer-events-none"><i data-lucide="upload-cloud" class="w-4 h-4" aria-hidden="true"></i><span>同时更新 Worker 和 HTML</span></button></div>';
      root.querySelector('[data-admin-worker-file-input="1"]')?.addEventListener('change', (event) => {
        workerHtmlUpdateState.workerFile = event.currentTarget.files?.[0] || null;
        workerHtmlUpdateState.status = validateWorkerHtmlUploadFiles(workerHtmlUpdateState.workerFile, workerHtmlUpdateState.indexFile) || '两个文件已就绪。';
        workerHtmlUpdateState.tone = validateWorkerHtmlUploadFiles(workerHtmlUpdateState.workerFile, workerHtmlUpdateState.indexFile) ? '' : 'success';
        renderWorkerHtmlUpdateState();
      });
      root.querySelector('[data-admin-index-file-input="1"]')?.addEventListener('change', (event) => {
        workerHtmlUpdateState.indexFile = event.currentTarget.files?.[0] || null;
        workerHtmlUpdateState.status = validateWorkerHtmlUploadFiles(workerHtmlUpdateState.workerFile, workerHtmlUpdateState.indexFile) || '两个文件已就绪。';
        workerHtmlUpdateState.tone = validateWorkerHtmlUploadFiles(workerHtmlUpdateState.workerFile, workerHtmlUpdateState.indexFile) ? '' : 'success';
        renderWorkerHtmlUpdateState();
      });
      root.querySelector('[data-admin-worker-html-refresh="1"]')?.addEventListener('click', () => navigateWithAdminCacheBust());
      root.querySelector('[data-admin-worker-html-submit="1"]')?.addEventListener('click', () => submitWorkerHtmlUpdate(app));
      scheduleIconRefresh(root);
    }
    renderWorkerHtmlUpdateState();
  }

  function applySettingsLayout() {
    syncWorkerHtmlUpdatePanel(window.App);
    syncThemeSkinPanel(window.App);
    syncTmdbCredentialPanel(window.App);
    syncCloudflareTokenTest();
    syncCredentialHelpLinks();
  }

  // 凭据字段旁的跳转图标：目标是签发或查看该凭据的官方页面。图标用内联 SVG，
  // 不走 lucide，免得图标库还没替换 <i data-lucide> 时这里留下一个空格子。
  const CREDENTIAL_HELP_ICON =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>';
  const CREDENTIAL_HELP_TARGETS = [
    ['#cfg-tg-token', 'https://t.me/BotFather'],
    ['#cfg-cf-account', 'https://dash.cloudflare.com/?to=/:account/workers-and-pages'],
    ['#cfg-cf-zone', 'https://developers.cloudflare.com/fundamentals/account/find-account-and-zone-ids/'],
    ['#cfg-cf-token', 'https://dash.cloudflare.com/profile/api-tokens'],
    ['#cfg-cf-kv-namespace', 'https://dash.cloudflare.com/?to=/:account/workers/kv/namespaces'],
    ['#cfg-cf-d1-database', 'https://dash.cloudflare.com/?to=/:account/workers/d1'],
  ];

  // title 与 aria-label 直接写地址：悬停或读屏都能知道这枚图标跳去哪。
  function credentialHelpLink(href) {
    return '<a href="' + href + '" target="_blank" rel="noopener noreferrer" data-admin-credential-link="1" title="' + href + '" aria-label="打开 ' + href + '">' + CREDENTIAL_HELP_ICON + '</a>';
  }

  function syncCredentialHelpLinks() {
    for (const [selector, href] of CREDENTIAL_HELP_TARGETS) {
      const input = document.querySelector(selector);
      if (!input) continue;
      // 密码框会被 mountSensitiveInputToggle 包进一层 span，所以标签是容器（不是输入框）的前兄弟。
      const holder = input.parentElement?.hasAttribute('data-sensitive-input-toggle') ? input.parentElement : input;
      const label = holder.previousElementSibling;
      if (!label || label.tagName !== 'LABEL') continue;
      if (label.querySelector('[data-admin-credential-link]')) continue;
      label.insertAdjacentHTML('beforeend', credentialHelpLink(href));
    }
  }

  // 账号设置的 TMDB 凭据：V20 删掉了这三段输入框，但 CONFIG_FORM_BINDINGS 与保存载荷还在，
  // 所以只补 DOM，值直接读写 settingsForm（保存时由字段表带进 payload）。
  const TMDB_CREDENTIAL_FIELDS = [
    ['#cfg-tmdb-read-token', 'tmdbApiReadToken'],
    ['#cfg-tmdb-api-key', 'tmdbApiV3Key'],
    ['#cfg-tmdb-language', 'tmdbLanguage'],
  ];
  const TMDB_CREDENTIAL_FIELD_CLASS =
    'w-full p-2 rounded-control border border-border-soft bg-surface-panel outline-none dark:border-border-dark dark:bg-surface-dark dark:text-white';
  const TMDB_CREDENTIAL_MARKUP =
    '<div class="ui-block-head"><div>' +
    '<div class="ui-section-kicker">TMDB</div>' +
    '<div class="ui-section-title">TMDB 聚合凭据' +
    credentialHelpLink('https://www.themoviedb.org/settings/api') +
    '</div>' +
    '</div><span class="ui-chip-muted">节点级开关</span></div>' +
    '<label class="ui-field-label" for="cfg-tmdb-read-token">TMDB API Read Token</label>' +
    '<input type="password" id="cfg-tmdb-read-token" autocomplete="new-password" class="' +
    TMDB_CREDENTIAL_FIELD_CLASS +
    ' mb-3">' +
    '<label class="ui-field-label" for="cfg-tmdb-api-key">TMDB API Key（v3）</label>' +
    '<input type="password" id="cfg-tmdb-api-key" autocomplete="new-password" class="' +
    TMDB_CREDENTIAL_FIELD_CLASS +
    ' mb-3">' +
    '<label class="ui-field-label" for="cfg-tmdb-language">TMDB 语言</label>' +
    '<input type="text" id="cfg-tmdb-language" placeholder="zh-CN" class="' +
    TMDB_CREDENTIAL_FIELD_CLASS +
    ' mb-3">' +
    '<p class="text-xs leading-5 text-slate-500">节点弹窗「高级设置」里的 TMDB 聚合开关用它把 AnyProviderIdEquals=tmdb.&lt;id&gt; 换成标题 + 年份查询。两项凭据只要填了任意一项就整组覆盖 Worker 环境变量 TMDB_API_READ_TOKEN / TMDB_API_KEY；都留空才用环境变量。语言留空默认 zh-CN。</p>' +
    '<div class="mt-3 flex flex-wrap items-center gap-2" data-admin-credential-test="1">' +
    '<button type="button" class="rounded-control" data-credential-test="tmdb">测试 TMDB 凭据</button>' +
    '<span data-credential-test-result="1" class="text-xs leading-5 text-slate-500"></span>' +
    '</div>';

  function syncTmdbCredentialPanel(app) {
    const form = app?.settingsForm;
    if (!form) return;
    // 位置固定为「后台登录有效期」与「Cloudflare 联动」两块之间。
    const loginPanel = document.querySelector('#cfg-jwt-days')?.closest('.ui-settings-panel');
    if (!loginPanel || !loginPanel.parentElement) return;
    let panel = document.querySelector('[data-admin-tmdb-credentials="1"]');
    if (!panel) {
      panel = document.createElement('div');
      panel.setAttribute('data-admin-tmdb-credentials', '1');
      panel.className = 'ui-settings-panel settings-block h-full';
      panel.innerHTML = TMDB_CREDENTIAL_MARKUP;
      for (const [selector, key] of TMDB_CREDENTIAL_FIELDS) {
        const input = panel.querySelector(selector);
        if (!input) continue;
        input.addEventListener('input', () => {
          const currentForm = window.App?.settingsForm;
          if (currentForm) currentForm[key] = input.value;
        });
      }
    }
    // Vue 重渲染会丢掉注入节点，位置不对就补回去（存在时是幂等的）。
    if (panel.previousElementSibling !== loginPanel) {
      loginPanel.insertAdjacentElement('afterend', panel);
    }
    for (const [selector, key] of TMDB_CREDENTIAL_FIELDS) {
      const input = panel.querySelector(selector);
      // 正在输入时不回写，避免和光标抢值。
      if (!input || document.activeElement === input) continue;
      const next = String(form[key] ?? '');
      if (input.value !== next) input.value = next;
    }
    bindCredentialTests(panel);
  }

  // 「测试 Cloudflare 令牌」要贴着它测的那个输入框，所以落在「Cloudflare 联动」面板里，
  // 而不是跟着 TMDB 凭据面板走（那边测的是另一组凭据）。
  const CLOUDFLARE_TOKEN_TEST_MARKUP =
    '<div class="mb-3 flex flex-wrap items-center gap-2" data-admin-credential-test="1">' +
    '<button type="button" class="rounded-control" data-credential-test="cloudflare">测试 Cloudflare 令牌</button>' +
    '<span data-credential-test-result="1" class="text-xs leading-5 text-slate-500"></span>' +
    '</div>';

  function syncCloudflareTokenTest() {
    const input = document.querySelector('#cfg-cf-token');
    const panel = input?.closest('.ui-settings-panel');
    if (!panel) return;
    // 密码框会被 mountSensitiveInputToggle 包进一层 span，插在包裹层后面才是标签之间的正常行。
    const holder = input.parentElement?.hasAttribute('data-sensitive-input-toggle')
      ? input.parentElement
      : input;
    let row = panel.querySelector('[data-admin-credential-test="1"]');
    if (!row) {
      row = document.createElement('div');
      row.innerHTML = CLOUDFLARE_TOKEN_TEST_MARKUP;
      row = row.firstElementChild;
    }
    // Vue 重渲染会丢掉注入节点，位置不对就补回去（存在时是幂等的）。
    if (row.previousElementSibling !== holder) {
      holder.insertAdjacentElement('afterend', row);
    }
    bindCredentialTests(row);
  }

  // 凭据连通性测试：直接拿页面里当前的值去问一次，填错不用等到节点列表变空才发现。
  function bindCredentialTests(panel) {
    const result = panel.querySelector('[data-credential-test-result="1"]');
    const setResult = (text, tone) => {
      if (!result) return;
      result.textContent = text;
      if (tone) result.setAttribute('data-tone', tone);
      else result.removeAttribute('data-tone');
    };
    panel.querySelectorAll('[data-credential-test]').forEach((button) => {
      if (button.getAttribute('data-admin-credential-test-bound') === '1') return;
      button.setAttribute('data-admin-credential-test-bound', '1');
      button.addEventListener('click', async () => {
        const app = window.App;
        if (!app || typeof app.apiCall !== 'function') return;
        const readForm = (key) => String(app.settingsForm?.[key] ?? '');
        const readInput = (selector, key) =>
          String(document.querySelector(selector)?.value ?? readForm(key));
        const kind = button.getAttribute('data-credential-test');
        button.disabled = true;
        setResult('测试中…', '');
        try {
          if (kind === 'cloudflare') {
            const response = await app.apiCall('testCloudflareApiToken', {
              apiToken: readInput('#cfg-cf-token', 'cfApiToken'),
            });
            setResult('Cloudflare 令牌可用（' + String(response?.status || 'active') + '）', 'ok');
          } else {
            const response = await app.apiCall('testTmdbCredential', {
              readToken: readInput('#cfg-tmdb-read-token', 'tmdbApiReadToken'),
              apiKey: readInput('#cfg-tmdb-api-key', 'tmdbApiV3Key'),
              language: readInput('#cfg-tmdb-language', 'tmdbLanguage'),
            });
            const title = String(response?.title || '');
            setResult(
              'TMDB 可用：' +
                (title || '连通') +
                (response?.language ? '（' + response.language + '）' : '') +
                (response?.credentialKind === 'api_key' ? ' · v3 Key' : ' · Read Token'),
              'ok',
            );
          }
        } catch (error) {
          setResult(
            (kind === 'cloudflare' ? 'Cloudflare 令牌测试失败：' : 'TMDB 凭据测试失败：') +
              String(error?.message || error || '未知错误'),
            'error',
          );
        } finally {
          button.disabled = false;
        }
      });
    });
  }

  function applyNodeAdvancedSettingsLayout() {
    const nodeModal = document.querySelector('#node-modal');
    const linesContainer = document.querySelector('#node-lines-container');
    const linesPanel = linesContainer?.closest('.rounded-2xl.border');
    const playbackInfoField = document.querySelector('#form-playback-info-mode');
    const advancedFields = playbackInfoField?.closest('.grid');
    const headersContainer = document.querySelector('#headers-container');
    const headersPanel = headersContainer?.parentElement;
    if (!linesPanel || !advancedFields || !headersPanel) return;
    linesPanel.setAttribute('data-admin-node-lines-panel', '1');

    let advancedSection = document.querySelector('[data-admin-node-advanced="1"]');
    if (!advancedSection) {
      advancedSection = document.createElement('details');
      advancedSection.setAttribute('data-admin-node-advanced', '1');
      advancedSection.open = false;
      advancedSection.innerHTML = '<summary><span>高级设置</span><i data-lucide="chevron-down" aria-hidden="true"></i></summary><div data-admin-node-advanced-content="1"></div>';
      linesPanel.insertAdjacentElement('afterend', advancedSection);
    }
    const content = advancedSection.querySelector('[data-admin-node-advanced-content="1"]');
    if (!content) return;
    // 高级设置默认折叠：每次重新打开节点弹窗都回到折叠态。
    const nodeModalIsOpen = !!nodeModal?.open;
    if (nodeModalIsOpen && !nodeModalWasOpen) {
      advancedSection.open = false;
      // 每次重开弹窗都重算「继承全局」文案：settingsForm 可能在上次渲染之后才就绪。
      syncNodeInheritCopy(window.App);
    }
    nodeModalWasOpen = nodeModalIsOpen;
    advancedFields.setAttribute('data-admin-node-advanced-fields', '1');
    headersPanel.setAttribute('data-admin-node-advanced-headers', '1');
    if (advancedFields.parentElement !== content) content.appendChild(advancedFields);
    // 入口模式与访问密钥属于低频配置，和 Headers 一起收进高级设置，基础区只留常用字段。
    // 这两个字段在模板里分别包在各自的 div 里，所以按字段而不是按共同父级移动。
    const entryFields = ['#form-entry-mode', '#form-secret']
      .map((selector) => document.querySelector(selector)?.parentElement)
      .filter((field) => field && !field.closest('[data-admin-node-advanced="1"]'));
    if (entryFields.length === 2) {
      for (const field of entryFields) {
        field.setAttribute('data-admin-node-advanced-entry', '1');
        if (field.parentElement !== content) content.insertBefore(field, advancedFields);
      }
    }
    if (headersPanel.parentElement !== content) content.appendChild(headersPanel);
    syncTmdbAggregationControl(window.App, content, advancedFields);
    syncNodeInheritCopy(window.App);
  }

  // 标签颜色自绘下拉：原生 select 的弹出菜单由系统绘制，选项颜色改不动。
  // select 仍是唯一状态源（v-model 绑在它身上），这里只画一个按钮 + 面板去驱动它。
  const TAG_COLOR_TONES = {
    amber: '#d97706',
    emerald: '#059669',
    sky: '#0284c7',
    violet: '#7c3aed',
    rose: '#e11d48',
    slate: '#64748b'
  };

  function closeTagColorPanel() {
    document.querySelector('[data-admin-node-tag-color-panel="1"]')?.remove();
    document.querySelector('[data-admin-node-tag-color-trigger="1"]')?.setAttribute('aria-expanded', 'false');
  }

  function syncTagColorTrigger(select, trigger) {
    if (!select || !trigger) return;
    const option = select.selectedOptions?.[0];
    const tone = TAG_COLOR_TONES[select.value] || TAG_COLOR_TONES.slate;
    const label = String(option?.textContent || '').trim() || '默认';
    const labelNode = trigger.querySelector('[data-admin-node-tag-color-label="1"]');
    const swatch = trigger.querySelector('[data-admin-node-tag-color-swatch="1"]');
    if (labelNode && labelNode.textContent !== label) labelNode.textContent = label;
    if (swatch) swatch.style.color = tone;
    trigger.setAttribute('aria-label', '标签颜色：' + label);
  }

  function openTagColorPanel(select, trigger) {
    closeTagColorPanel();
    const panel = document.createElement('div');
    panel.setAttribute('data-admin-node-tag-color-panel', '1');
    panel.setAttribute('role', 'listbox');
    for (const option of [...select.options]) {
      const item = document.createElement('button');
      item.type = 'button';
      item.setAttribute('data-admin-node-tag-color-option', '1');
      item.setAttribute('role', 'option');
      item.setAttribute('aria-selected', option.value === select.value ? 'true' : 'false');
      const swatch = document.createElement('span');
      swatch.setAttribute('data-admin-node-tag-color-swatch', '1');
      swatch.style.color = TAG_COLOR_TONES[option.value] || TAG_COLOR_TONES.slate;
      const text = document.createElement('span');
      text.textContent = String(option.textContent || '').trim();
      item.append(swatch, text);
      item.addEventListener('click', () => {
        select.value = option.value;
        // 模板用 v-model 绑 select，必须派发 change 才会写回 nodeModalForm.tagColor。
        select.dispatchEvent(new Event('change', { bubbles: true }));
        syncTagColorTrigger(select, trigger);
        closeTagColorPanel();
        trigger.focus();
      });
      panel.appendChild(item);
    }
    // 原生 <dialog> 处于 top layer，挂到 body 会被永远压在下面；挂进 dialog 才能显示在其上。
    (document.querySelector('#node-modal[open]') || document.body).appendChild(panel);
    const rect = trigger.getBoundingClientRect();
    const panelRect = panel.getBoundingClientRect();
    const openUp = rect.bottom + panelRect.height + 8 > window.innerHeight;
    panel.style.left = Math.max(8, Math.min(rect.right - panelRect.width, window.innerWidth - panelRect.width - 8)) + 'px';
    panel.style.top = (openUp ? rect.top - panelRect.height - 4 : rect.bottom + 4) + 'px';
    trigger.setAttribute('aria-expanded', 'true');
    panel.querySelector('[aria-selected="true"]')?.focus?.();
  }

  function mountTagColorTrigger(select) {
    if (!select || select.dataset.adminTagColorMounted === '1') return;
    const row = select.parentElement;
    if (!row) return;
    select.dataset.adminTagColorMounted = '1';
    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.setAttribute('data-admin-node-tag-color-trigger', '1');
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-expanded', 'false');
    trigger.innerHTML = '<span data-admin-node-tag-color-swatch="1" style="width:.75rem;height:.75rem;border-radius:4px;border:1px solid currentColor;display:inline-block;flex:0 0 auto"></span>'
      + '<span data-admin-node-tag-color-label="1" style="flex:1 1 auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"></span>'
      + '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true" style="flex:0 0 auto"><path d="m6 9 6 6 6-6"/></svg>';
    trigger.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (document.querySelector('[data-admin-node-tag-color-panel="1"]')) closeTagColorPanel();
      else openTagColorPanel(select, trigger);
    });
    // select 被别处改动（载入节点、表单重置）时同步按钮文案。
    select.addEventListener('change', () => syncTagColorTrigger(select, trigger));
    row.appendChild(trigger);
    syncTagColorTrigger(select, trigger);
  }

  function applyTagColorDropdown() {
    const select = document.querySelector('#form-tag-color');
    if (select) mountTagColorTrigger(select);
    else closeTagColorPanel();
  }

  function applyNodePrimaryFieldsLayout() {
    const displayName = document.querySelector('#form-display-name');
    const tag = document.querySelector('#form-tag');
    const tagColor = document.querySelector('#form-tag-color');
    const remark = document.querySelector('#form-remark');
    const streamMode = document.querySelector('#form-main-video-stream-mode');
    const basicGrid = displayName?.parentElement?.parentElement;
    const metaGrid = tag?.closest('.grid.grid-cols-1');
    const streamField = streamMode?.parentElement;
    const streamPanel = streamField?.closest('.rounded-2xl.border');
    if (basicGrid) basicGrid.setAttribute('data-admin-node-basic-grid', '1');
    // 标签颜色不再是独立一格：贴在标签输入框右侧，共用同一行的输入区。
    const tagRow = tag?.parentElement;
    if (tagRow && tagColor && tagColor.parentElement === tagRow) tagRow.setAttribute('data-admin-node-tag-field', '1');
    if (metaGrid && remark && streamField) {
      metaGrid.setAttribute('data-admin-node-meta-grid', '1');
      streamField.setAttribute('data-admin-node-stream-field', '1');
      const remarkField = remark.parentElement;
      if (streamField.parentElement !== metaGrid || remarkField?.nextElementSibling !== streamField) {
        remarkField?.insertAdjacentElement('afterend', streamField);
      }
    }
    streamPanel?.remove();
  }
  // 线路表格：表头与数据行共用同一套列宽，数量跟随行数，按钮点击后重算。
  function applyNodeLinesTableLayout() {
    const panel = document.querySelector('#node-modal [data-admin-node-lines-panel="1"]');
    if (!panel) return;
    panel.querySelector('[class*="grid-cols-["]')?.setAttribute('data-admin-node-lines-head', '1');
    const container = document.querySelector('#node-lines-container');
    container?.querySelectorAll('[data-node-line-row="1"]').forEach((row) => {
      row.querySelector('[class*="grid-cols-["]')?.setAttribute('data-admin-node-line-grid', '1');
    });
    const label = panel.querySelector(':scope > div:first-child > div:first-child > label');
    let count = panel.querySelector('[data-admin-node-line-count="1"]');
    if (label && !count) {
      count = document.createElement('span');
      count.setAttribute('data-admin-node-line-count', '1');
      label.insertAdjacentElement('afterend', count);
    }
    if (count) {
      const text = (container?.querySelectorAll('[data-node-line-row="1"]').length || 0) + ' 条线路';
      if (count.textContent !== text) count.textContent = text;
    }
    if (panel.dataset.adminLineChromeBound === '1') return;
    panel.dataset.adminLineChromeBound = '1';
    // 删除/重排只移除节点，不会触发观察器的节点新增分支，这里补一次点击后的重算。
    panel.addEventListener('click', (event) => {
      if (event.target?.closest?.('button')) scheduleShellRefresh();
    });
  }

  // 说明文字默认只留一行：同字段的第二段起折叠，长说明带「展开」。
  function applyNodeModalHintFold() {
    const form = document.querySelector('#node-modal form');
    if (!form) return;
    form.querySelectorAll('[data-admin-hint="1"]').forEach((hint) => hint.removeAttribute('data-admin-hint'));
    const hints = [...form.querySelectorAll('p[class*="text-xs"]')].filter((hint) => {
      if (/text-red/.test(String(hint.className || ''))) return false;
      return String(hint.textContent || '').trim().length > 12;
    });
    hints.forEach((hint) => hint.setAttribute('data-admin-hint', '1'));
    for (const field of new Set(hints.map((hint) => hint.parentElement))) {
      if (!field) continue;
      const own = [...field.children].filter((child) => child.hasAttribute?.('data-admin-hint'));
      // 入口模式与访问密钥的提示不做折叠：这两行本身是操作指引，收起反而看不到。
      const inAdvancedEntry = field.hasAttribute('data-admin-node-advanced-entry');
      const needsToggle = !inAdvancedEntry && (own.length > 1 || own.some((child) => String(child.textContent || '').trim().length > 26));
      let toggle = field.querySelector('[data-admin-hint-toggle="1"]');
      if (!needsToggle) {
        toggle?.remove();
        field.removeAttribute('data-admin-hint-field');
        continue;
      }
      field.setAttribute('data-admin-hint-field', '1');
      if (!toggle) {
        toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.setAttribute('data-admin-hint-toggle', '1');
        toggle.addEventListener('click', () => {
          const open = field.getAttribute('data-admin-hint-open') !== '1';
          toggle.setAttribute('aria-expanded', String(open));
          toggle.textContent = open ? '收起' : '展开';
          if (open) field.setAttribute('data-admin-hint-open', '1');
          else field.removeAttribute('data-admin-hint-open');
        });
        field.appendChild(toggle);
      }
      const open = field.getAttribute('data-admin-hint-open') === '1';
      toggle.setAttribute('aria-expanded', String(open));
      toggle.textContent = open ? '收起' : '展开';
    }
  }

  function applyLayoutEnhancements() {
    applyNodeToolbarLayout();
    applySettingsLayout();
    applyNodePrimaryFieldsLayout();
    applyNodeAdvancedSettingsLayout();
    applyNodeLinesTableLayout();
    applyNodeModalHintFold();
    applyTagColorDropdown();
  }

  function normalizeAdminActionError(responsePayload, status) {
    const error = new Error(responsePayload?.error?.message || 'HTTP ' + status);
    error.code = responsePayload?.error?.code || null;
    error.status = status;
    error.details = responsePayload?.error?.details ?? null;
    return error;
  }

  async function callConfirmedAdminAction(app, action, payload, confirmAction) {
    const requestInit = {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Confirm': confirmAction
      },
      body: JSON.stringify({ action, ...payload })
    };
    const adminPath = String(window.location?.pathname || '/admin');
    let response = await window.fetch(adminPath, requestInit);
    if (response.status === 401 && typeof app?.promptLogin === 'function') {
      await app.promptLogin();
      response = await window.fetch(adminPath, requestInit);
    }
    const responsePayload = await response.json().catch(() => ({}));
    if (!response.ok) throw normalizeAdminActionError(responsePayload, response.status);
    return responsePayload;
  }

  function getTidyResultGroups(result, key) {
    if (Array.isArray(result?.[key])) return result[key];
    return Array.isArray(result?.preview?.[key]) ? result.preview[key] : [];
  }

  function buildTidyExecutionResultMessage(app, result, summaryMessage, refreshIncomplete) {
    const groupDefinitions = [
      ['实际迁移字段', 'fieldGroups', true],
      ['实际删除', 'deleteGroups', false],
      ['实际重写', 'rewriteGroups', false],
      ['实际保留', 'preserveGroups', false]
    ];
    const lines = [summaryMessage];
    for (const [title, key, isFieldGroup] of groupDefinitions) {
      const groups = getTidyResultGroups(result, key);
      lines.push('', title + '：');
      if (!groups.length) {
        lines.push('• 无');
        continue;
      }
      for (const group of groups) {
        const formatter = isFieldGroup ? app.formatTidyFieldGroupText : app.formatTidyPreviewGroupText;
        lines.push(typeof formatter === 'function' ? formatter.call(app, group) : '• ' + String(group?.label || '未命名分组'));
      }
    }
    if (refreshIncomplete) {
      lines.push('', '设置或列表只完成了部分刷新，请手动刷新页面确认最新状态。');
    }
    return lines.join('\\n');
  }

  function collectD1ReadinessLines(status) {
    const readiness = status?.readiness && typeof status.readiness === 'object' ? status.readiness : {};
    const candidates = {
      ...(status?.tables && typeof status.tables === 'object' ? status.tables : {}),
      ...(status?.indexes && typeof status.indexes === 'object' ? status.indexes : {}),
      ...readiness
    };
    const lines = [];
    for (const [key, value] of Object.entries(candidates)) {
      if (typeof value === 'boolean') lines.push('• ' + key + '：' + (value ? '就绪' : '未就绪'));
      if (value && typeof value === 'object' && typeof value.ready === 'boolean') {
        lines.push('• ' + key + '：' + (value.ready ? '就绪' : '未就绪'));
      }
    }
    if (typeof status?.ftsReady === 'boolean' && !Object.prototype.hasOwnProperty.call(candidates, 'fts')) {
      lines.push('• FTS：' + (status.ftsReady ? '就绪' : '未就绪'));
    }
    return [...new Set(lines)];
  }

  function formatD1SchemaStatus(status = {}) {
    const issues = Array.isArray(status?.issues)
      ? status.issues.map((item) => String(item || '').trim()).filter(Boolean)
      : [];
    const lines = ['当前结构：' + (status?.schemaReady === true ? '已就绪' : '未就绪')];
    const readinessLines = collectD1ReadinessLines(status);
    if (readinessLines.length) lines.push('', '表与索引：', ...readinessLines);
    const columns = status?.columns && typeof status.columns === 'object' ? status.columns : {};
    const columnLines = [];
    for (const [tableName, tableColumns] of Object.entries(columns)) {
      if (!tableColumns || typeof tableColumns !== 'object') continue;
      for (const [columnName, ready] of Object.entries(tableColumns)) {
        if (typeof ready === 'boolean') columnLines.push('• ' + tableName + '.' + columnName + '：' + (ready ? '就绪' : '缺失'));
      }
    }
    if (columnLines.length) lines.push('', '列状态：', ...columnLines);
    if (issues.length) lines.push('', '结构问题：', ...issues.map((issue) => '• ' + issue));
    return lines.join('\\n');
  }

  function formatD1InitializationResult(result = {}) {
    const initialization = result?.initialization && typeof result.initialization === 'object'
      ? result.initialization
      : {};
    const createdTables = Array.isArray(initialization.createdTables) ? initialization.createdTables : [];
    const actionLines = createdTables.length ? ['• 新建表：' + createdTables.join('、')] : [];
    const addedColumns = Array.isArray(initialization.addedColumns) ? initialization.addedColumns : [];
    const createdIndexes = Array.isArray(initialization.createdIndexes) ? initialization.createdIndexes : [];
    const repairedIndexes = Array.isArray(initialization.repairedIndexes) ? initialization.repairedIndexes : [];
    const uniqueIndexesCreated = Array.isArray(initialization.uniqueIndexesCreated) ? initialization.uniqueIndexesCreated : [];
    const droppedTriggers = Array.isArray(initialization.droppedTriggers) ? initialization.droppedTriggers : [];
    const rebuiltTables = Array.isArray(initialization.rebuiltTables) ? initialization.rebuiltTables : [];
    if (addedColumns.length) actionLines.push('• 补全列：' + addedColumns.join('、'));
    if (createdIndexes.length) actionLines.push('• 新建索引：' + createdIndexes.join('、'));
    if (repairedIndexes.length) actionLines.push('• 修复索引：' + repairedIndexes.join('、'));
    if (uniqueIndexesCreated.length) actionLines.push('• 补全唯一索引：' + uniqueIndexesCreated.join('、'));
    if (droppedTriggers.length) actionLines.push('• 清理历史触发器：' + droppedTriggers.join('、'));
    for (const item of rebuiltTables) {
      const dataWasDiscarded = item?.willDiscardData === true && item?.dataMode === 'discard';
      if (dataWasDiscarded || item?.allowsDataLoss === true) {
        if (item?.rowCountMeasured === false) {
          actionLines.push('• 重建表：' + String(item?.table || '') + '（已清空全部日志，未扫描旧日志数量）');
          continue;
        }
        const discardedRows = Math.max(0, Number(item?.discardedRows) || 0);
        const discardedLabel = item?.discardedRowsIsLowerBound === true ? '10000+' : String(discardedRows);
        actionLines.push('• 重建表：' + String(item?.table || '') + '（已清空 ' + discardedLabel + ' 行日志）');
      } else actionLines.push('• 重建表：' + String(item?.table || '') + '（' + Math.max(0, Number(item?.rowCount) || 0) + ' 行）');
    }
    if (initialization.ftsRebuilt === true) actionLines.push('• 构建 FTS 全文索引');
    if (initialization.recoveryBookmark) actionLines.push('• 恢复 bookmark：' + String(initialization.recoveryBookmark));
    if (!actionLines.length) actionLines.push('• 当前结构无需调整');
    return formatD1SchemaStatus(result?.status || {}) + '\\n\\n本次初始化：\\n' + actionLines.join('\\n');
  }

  function formatD1RepairIssue(rawIssue = '') {
    const issue = String(rawIssue || '').trim();
    const mappings = [
      [/^missing_table:(.+)$/, '缺少表: $1'],
      [/^missing_column:(.+)$/, '缺少列: $1'],
      [/^invalid_column_affinity:(.+)$/, '列类型不兼容: $1'],
      [/^invalid_primary_key:(.+)$/, '主键结构不兼容: $1'],
      [/^missing_unique_key:(.+)$/, '缺少唯一约束: $1'],
      [/^unique_key_duplicate:(.+)$/, '唯一键存在重复数据: $1'],
      [/^unique_key_empty:(.+)$/, '唯一键存在空值: $1'],
      [/^rebuild_row_limit_exceeded:([^:]+):(.+)$/, '表 $1 超过自动重建上限（$2 行）'],
      [/^fts_contract_invalid$/, 'FTS 结构不兼容'],
      [/^missing_index:(.+)$/, '缺少索引: $1'],
      [/^invalid_index:(.+)$/, '索引定义不兼容: $1'],
      [/^schema_version_ahead:([0-9]+)$/, 'D1 结构版本（v$1）高于当前 Worker，将按当前契约重新认证'],
      [/^legacy_fts_trigger:([^:]+):(.+)$/, '历史 FTS 同步触发器: $2']
    ];
    for (const [pattern, replacement] of mappings) if (pattern.test(issue)) return issue.replace(pattern, replacement) + ' [' + issue + ']';
    return issue;
  }

  function formatD1RepairPlan(plan = {}) {
    const lines = [];
    const low = Array.isArray(plan?.repairableIssues) ? plan.repairableIssues : [];
    const high = Array.isArray(plan?.highRiskIssues) ? plan.highRiskIssues : [];
    const blocked = Array.isArray(plan?.blockingIssues) ? plan.blockingIssues : [];
    if (low.length) lines.push('可安全修复：', ...low.map(issue => '• ' + formatD1RepairIssue(issue)));
    if (high.length) lines.push(...(lines.length ? [''] : []), '需重建表的高风险修复：', ...high.map(issue => '• ' + formatD1RepairIssue(issue)));
    if (blocked.length) lines.push(...(lines.length ? [''] : []), '无法自动修复：', ...blocked.map(issue => '• ' + formatD1RepairIssue(issue)));
    if (!lines.length) lines.push('当前 D1 结构已符合契约。');
    return lines.join('\\n');
  }

  function formatD1RepairError(error, fallbackTitle = 'D1 结构修复失败') {
    const details = error?.details && typeof error.details === 'object' ? error.details : {};
    const repairPlan = details.repairPlan && typeof details.repairPlan === 'object'
      ? details.repairPlan
      : { blockingIssues: details.blockingIssues, repairableIssues: [], highRiskIssues: [] };
    const lines = [fallbackTitle + ': ' + (error?.message || '未知错误')];
    const hasIssues = ['repairableIssues', 'highRiskIssues', 'blockingIssues']
      .some(key => Array.isArray(repairPlan?.[key]) && repairPlan[key].length > 0);
    if (hasIssues) lines.push('', formatD1RepairPlan(repairPlan));
    const remainingIssues = Array.isArray(details.issues) ? details.issues : [];
    if (remainingIssues.length) lines.push('', '最终校验仍存在问题：', ...remainingIssues.map(issue => '• ' + formatD1RepairIssue(issue)));
    if (details.recoveryBookmark) lines.push('', '恢复 bookmark：' + String(details.recoveryBookmark));
    if (error?.code) lines.push('', '错误代码：' + String(error.code));
    return lines.join('\\n');
  }

  function getDashboardTrafficNodes() {
    const count = document.querySelector('#dash-traffic-count');
    const card = count?.closest?.('.glass-card') || null;
    if (!card) return {};
    return {
      card,
      label: card.querySelector('p'),
      count,
      hint: card.querySelector('#dash-traffic-hint'),
      badges: card.querySelector('#dash-traffic-meta'),
      detail: card.querySelector('#dash-traffic-detail'),
      toggle: card.querySelector('[data-dashboard-traffic-toggle="1"]')
    };
  }

  function snapshotDashboardTrafficCard(nodes = getDashboardTrafficNodes()) {
    if (!nodes.card || !nodes.count) return null;
    return {
      count: String(nodes.count.textContent || ''),
      hint: String(nodes.hint?.textContent || ''),
      title: String(nodes.count.getAttribute('title') || ''),
      detail: String(nodes.detail?.textContent || ''),
      badgeHtml: String(nodes.badges?.innerHTML || '')
    };
  }

  function renderDashboardTrafficBadges(nodes, badges = [], app = window.App) {
    if (!nodes.badges) return;
    nodes.badges.replaceChildren();
    const normalizedBadges = Array.isArray(badges) ? badges : [];
    for (const badge of normalizedBadges) {
      if (!badge?.label) continue;
      const span = document.createElement('span');
      span.className = 'px-2.5 py-1 rounded-full text-[11px] font-medium ' + (app?.getDashboardBadgeClass?.(badge.tone) || 'bg-slate-100 text-slate-600');
      span.textContent = String(badge.label);
      nodes.badges.appendChild(span);
    }
  }

  function renderDashboardTrafficCard(view = {}, period = 'day', app = window.App) {
    const nodes = getDashboardTrafficNodes();
    if (!nodes.card || !nodes.count) return false;
    nodes.label.textContent = period === 'month'
      ? '本月视频流量 (CF Zone 总流量)'
      : '今日视频流量 (CF Zone 总流量)';
    nodes.count.textContent = String(view.count || '0 B');
    nodes.count.setAttribute('title', String(view.title || ''));
    if (nodes.hint) {
      nodes.hint.textContent = String(view.hint || '\u00a0');
      nodes.hint.setAttribute('title', String(view.title || ''));
    }
    if (nodes.detail) nodes.detail.textContent = String(view.detail || ' ');
    if (view.badgeHtml !== undefined && nodes.badges) nodes.badges.innerHTML = String(view.badgeHtml || '');
    else renderDashboardTrafficBadges(nodes, view.badges, app);
    return true;
  }

  function buildMonthlyTrafficCardView(payload = {}, app = window.App) {
    const title = [
      payload.trafficSourceText,
      payload.cfAnalyticsStatus,
      payload.cfAnalyticsError,
      payload.cfAnalyticsDetail,
      payload.warning
    ].filter(Boolean).join(' | ');
    const statusBadge = app?.getTrafficStatusBadge?.(payload) || {
      label: payload.cfAnalyticsLoaded ? '流量状态: Cloudflare 正常' : '流量状态: 查询失败',
      tone: payload.cfAnalyticsLoaded ? 'emerald' : 'red'
    };
    const freshnessBadge = app?.getStatsFreshnessBadge?.(payload) || {
      label: payload.cacheStatus === 'cache' ? '月统计: 缓存命中' : '月统计: 实时汇总',
      tone: payload.cacheStatus === 'cache' ? 'blue' : 'emerald'
    };
    return {
      count: payload.traffic || '0 B',
      hint: payload.trafficSourceText || payload.cfAnalyticsStatus || payload.cfAnalyticsError || '\u00a0',
      title,
      detail: [payload.cfAnalyticsStatus, payload.cfAnalyticsError, payload.cfAnalyticsDetail, payload.warning].filter(Boolean).join('\\n') || ' ',
      badges: [statusBadge, freshnessBadge]
    };
  }

  function updateDashboardTrafficToggleButton(nodes = getDashboardTrafficNodes()) {
    const button = nodes.toggle;
    if (!button) return;
    const showingMonth = dashboardTrafficState.period === 'month';
    const nextLabel = showingMonth ? '切换为今日流量' : '切换为本月流量';
    button.title = nextLabel;
    button.setAttribute('aria-label', nextLabel);
    button.setAttribute('aria-pressed', showingMonth ? 'true' : 'false');
    button.setAttribute('aria-busy', dashboardTrafficState.pending ? 'true' : 'false');
    button.disabled = dashboardTrafficState.pending;
    const icon = button.querySelector('i,svg');
    if (icon) icon.classList.toggle('animate-spin', dashboardTrafficState.pending);
  }

  function getDashboardMonthPeriodKey(app = window.App, timestamp = Date.now()) {
    const configuredOffset = Number(app?.runtimeConfig?.scheduleUtcOffsetMinutes ?? 480);
    const utcOffsetMinutes = Number.isFinite(configuredOffset) ? Math.trunc(configuredOffset) : 480;
    const shifted = new Date(Math.max(0, Number(timestamp) || Date.now()) + utcOffsetMinutes * 60 * 1000);
    return shifted.getUTCFullYear() + '-' + String(shifted.getUTCMonth() + 1).padStart(2, '0');
  }

  function isDashboardMonthlyTrafficCacheFresh(app = window.App, timestamp = Date.now()) {
    const now = Math.max(0, Number(timestamp) || Date.now());
    return dashboardTrafficState.monthlyAvailable === true
      && !!dashboardTrafficState.monthly
      && dashboardTrafficState.monthlyPeriodKey === getDashboardMonthPeriodKey(app, now)
      && Number(dashboardTrafficState.monthlyExpiresAt) > now;
  }

  async function toggleDashboardTrafficPeriod(app = window.App) {
    if (!app || dashboardTrafficState.pending) return;
    if (dashboardTrafficState.period === 'month') {
      dashboardTrafficState.period = 'day';
      if (dashboardTrafficState.daily) renderDashboardTrafficCard(dashboardTrafficState.daily, 'day', app);
      updateDashboardTrafficToggleButton();
      return;
    }

    dashboardTrafficState.daily = snapshotDashboardTrafficCard() || dashboardTrafficState.daily;
    dashboardTrafficState.period = 'month';
    const expectedPeriodKey = getDashboardMonthPeriodKey(app);
    if (isDashboardMonthlyTrafficCacheFresh(app)) {
      renderDashboardTrafficCard(dashboardTrafficState.monthly, 'month', app);
      updateDashboardTrafficToggleButton();
      return;
    }

    const retainedMonthly = dashboardTrafficState.monthlyAvailable === true
      && dashboardTrafficState.monthlyPeriodKey === expectedPeriodKey
      ? dashboardTrafficState.monthly
      : null;
    dashboardTrafficState.pending = true;
    renderDashboardTrafficCard(retainedMonthly || {
        count: '加载中...',
        hint: '正在汇总本月 CF Zone 流量',
        title: '本月流量按需加载',
        detail: ' ',
        badges: [{ label: '月统计: 加载中', tone: 'slate' }]
      }, 'month', app);
    updateDashboardTrafficToggleButton();
    try {
      const payload = await app.apiCall('getMonthlyTrafficStats');
      const monthlyView = buildMonthlyTrafficCardView(payload, app);
      const payloadPeriodKey = String(payload?.periodKey || expectedPeriodKey).trim() || expectedPeriodKey;
      const currentPeriodKey = getDashboardMonthPeriodKey(app);
      const querySucceeded = payload?.cfAnalyticsLoaded === true
        && String(payload?.cacheStatus || 'live').trim().toLowerCase() !== 'stale'
        && payloadPeriodKey === currentPeriodKey;
      if (querySucceeded) {
        dashboardTrafficState.monthly = monthlyView;
        dashboardTrafficState.monthlyPeriodKey = payloadPeriodKey;
        dashboardTrafficState.monthlyExpiresAt = Date.now() + DASHBOARD_MONTHLY_TRAFFIC_CLIENT_TTL_MS;
        dashboardTrafficState.monthlyAvailable = true;
      } else if (!retainedMonthly) {
        dashboardTrafficState.monthly = monthlyView;
        dashboardTrafficState.monthlyPeriodKey = payloadPeriodKey;
        dashboardTrafficState.monthlyExpiresAt = 0;
        dashboardTrafficState.monthlyAvailable = false;
      }
      if (dashboardTrafficState.period === 'month') {
        renderDashboardTrafficCard(querySucceeded ? monthlyView : (retainedMonthly || monthlyView), 'month', app);
      }
      if (payload?.cfAnalyticsLoaded !== true) {
        app.showMessage?.('本月流量查询失败: ' + (payload?.cfAnalyticsError || payload?.cfAnalyticsStatus || '未知错误'), { tone: 'error' });
      }
    } catch (error) {
      const failureView = {
        count: '加载失败',
        hint: '本月流量查询失败',
        title: String(error?.message || '未知错误'),
        detail: String(error?.message || '未知错误'),
        badges: [{ label: '月统计: 查询失败', tone: 'red' }]
      };
      if (!retainedMonthly) {
        dashboardTrafficState.monthly = failureView;
        dashboardTrafficState.monthlyPeriodKey = expectedPeriodKey;
        dashboardTrafficState.monthlyExpiresAt = 0;
        dashboardTrafficState.monthlyAvailable = false;
      }
      if (dashboardTrafficState.period === 'month') {
        renderDashboardTrafficCard(retainedMonthly || failureView, 'month', app);
      }
      app.showMessage?.('本月流量查询失败: ' + (error?.message || '未知错误'), { tone: 'error' });
    } finally {
      dashboardTrafficState.pending = false;
      updateDashboardTrafficToggleButton();
      scheduleIconRefresh(getDashboardTrafficNodes().card || document.body);
    }
  }

  function syncDashboardTrafficToggle(app = window.App) {
    const nodes = getDashboardTrafficNodes();
    if (!app || !nodes.card || !nodes.count) return;
    nodes.card.setAttribute('data-dashboard-traffic-card', '1');
    nodes.label?.setAttribute('data-dashboard-traffic-label', '1');
    if (!nodes.toggle) {
      const button = document.createElement('button');
      button.type = 'button';
      button.setAttribute('data-dashboard-traffic-toggle', '1');
      button.innerHTML = '<i data-lucide="repeat-2" aria-hidden="true"></i>';
      button.addEventListener('click', () => toggleDashboardTrafficPeriod(app));
      nodes.card.appendChild(button);
      nodes.toggle = button;
      scheduleIconRefresh(nodes.card);
    }
    if (dashboardTrafficState.period === 'day' && !dashboardTrafficState.pending) {
      dashboardTrafficState.daily = snapshotDashboardTrafficCard(nodes) || dashboardTrafficState.daily;
      if (String(nodes.label?.textContent || '') !== '今日视频流量 (CF Zone 总流量)') {
        nodes.label.textContent = '今日视频流量 (CF Zone 总流量)';
      }
    } else if (dashboardTrafficState.period === 'month' && dashboardTrafficState.monthly) {
      const monthlyCount = String(dashboardTrafficState.monthly.count || '0 B');
      if (
        String(nodes.count.textContent || '') !== monthlyCount
        || String(nodes.label?.textContent || '') !== '本月视频流量 (CF Zone 总流量)'
      ) {
        renderDashboardTrafficCard(dashboardTrafficState.monthly, 'month', app);
      }
    }
    updateDashboardTrafficToggleButton(nodes);
  }

  const GET_PROBE_PATH = '/emby/system/info/public';
  const NODE_GET_PROBE_CONCURRENCY = 4;
  const HEAD_PROBE_REASONS = new Set([
    'ok',
    'http_error',
    'timeout',
    'tls_error',
    'network_error',
    'invalid_target'
  ]);

  function normalizeHeadProbePath(value = '') {
    // 兜底路径命中时 worker 会回传实际探测路径，卡片按实际显示。
    return String(value || '').trim() || GET_PROBE_PATH;
  }

  async function runWithConcurrency(items = [], concurrency = 1, task = null) {
    const entries = Array.isArray(items) ? items : [];
    if (!entries.length || typeof task !== 'function') return;
    const workerCount = Math.min(
      entries.length,
      Math.max(1, Math.floor(Number(concurrency) || 1))
    );
    let cursor = 0;
    const worker = async () => {
      while (cursor < entries.length) {
        const index = cursor;
        cursor += 1;
        await task(entries[index], index);
      }
    };
    await Promise.all(Array.from({ length: workerCount }, () => worker()));
  }

  function normalizeHeadProbeResult(value = {}, fallbackPath = '') {
    const container = value && typeof value === 'object' ? value : {};
    const source = container.probe && typeof container.probe === 'object' ? container.probe : container;
    const rawReason = String(source.reason || '').trim().toLowerCase();
    const legacyLatency = Number(container.latencyMs);
    const hasLegacyLatency = container.latencyMs !== null
      && container.latencyMs !== undefined
      && String(container.latencyMs).trim() !== ''
      && Number.isFinite(legacyLatency)
      && legacyLatency >= 0
      && legacyLatency !== 9999;
    const statusCode = Number(source.statusCode);
    // 403 是源站拦住探测而不是节点故障：按可达处理，卡片也不再显示 403。
    const ok = source.ok === true || (!rawReason && hasLegacyLatency) || statusCode === 403;
    const reason = ok ? 'ok' : HEAD_PROBE_REASONS.has(rawReason) ? rawReason : 'network_error';
    const rawElapsedMs = Number(source.elapsedMs ?? (hasLegacyLatency ? legacyLatency : Number.NaN));
    const elapsedMs = Number.isFinite(rawElapsedMs) && rawElapsedMs >= 0 ? Math.round(rawElapsedMs) : null;
    const methodUsed = String(source.methodUsed || '').trim().toUpperCase();
    return {
      ok,
      reason,
      statusCode: Number.isInteger(statusCode) && statusCode >= 100 && statusCode <= 599 ? statusCode : null,
      elapsedMs,
      methodUsed: methodUsed === 'HEAD' || methodUsed === 'GET' ? methodUsed : null,
      probePath: normalizeHeadProbePath(source.probePath || fallbackPath)
    };
  }

  function buildClientHeadProbeFailure(probePath = '', startedAt = Date.now()) {
    return {
      ok: false,
      reason: 'network_error',
      statusCode: null,
      elapsedMs: Math.max(0, Date.now() - Number(startedAt || Date.now())),
      methodUsed: 'GET',
      probePath: normalizeHeadProbePath(probePath)
    };
  }

  function hasHeadProbeValue(value = {}) {
    if (!value || typeof value !== 'object') return false;
    if (value.probe && typeof value.probe === 'object') return true;
    if (String(value.reason || '').trim()) return true;
    return value.latencyMs !== null
      && value.latencyMs !== undefined
      && String(value.latencyMs).trim() !== '';
  }

  function formatHeadProbeResult(value = {}) {
    if (!hasHeadProbeValue(value)) return '--';
    const probe = normalizeHeadProbeResult(value);
    const elapsed = probe.elapsedMs === null ? '' : ' · ' + probe.elapsedMs + ' ms';
    if (probe.ok) return probe.elapsedMs === null ? '--' : probe.elapsedMs + ' ms';
    if (probe.reason === 'http_error') return 'HTTP ' + (probe.statusCode || '错误') + elapsed;
    if (probe.reason === 'timeout') return '超时' + elapsed;
    if (probe.reason === 'tls_error') return 'TLS 错误' + elapsed;
    if (probe.reason === 'invalid_target') return '目标无效';
    return '网络错误' + elapsed;
  }

  function formatHeadProbeTitle(value = {}) {
    if (!hasHeadProbeValue(value)) return '尚未进行 GET 测试';
    const probe = normalizeHeadProbeResult(value);
    const details = [formatHeadProbeResult(probe)];
    if (probe.methodUsed) details.push('方法 ' + probe.methodUsed);
    if (probe.probePath) details.push('路径 ' + probe.probePath);
    return details.join(' · ');
  }

  const UI_REQUEST_TIMEOUT_MS = 60000;
  // 上传类请求跳过超时：中断提示无法证明服务端没写入，重试可能重复部署。
  const UI_REQUEST_NO_TIMEOUT_ACTIONS = new Set(['updateWorkerAndAdminIndex', 'uploadAdminIndex']);

  function withUiRequestTimeout(app, action, task, timeoutMs = UI_REQUEST_TIMEOUT_MS) {
    if (UI_REQUEST_NO_TIMEOUT_ACTIONS.has(action)) return task;
    let timer = 0;
    const timeout = new Promise((_, reject) => {
      const arm = () => {
        timer = window.setTimeout(() => {
          // 重新登录期间请求被有意挂起，不算超时。
          if (app?.promptDialog?.open) {
            arm();
            return;
          }
          const error = new Error('请求超时，操作可能仍在后台执行；请刷新页面确认结果，避免重复提交。');
          error.code = 'UI_REQUEST_TIMEOUT';
          reject(error);
        }, timeoutMs);
      };
      arm();
    });
    return Promise.race([task, timeout]).finally(() => window.clearTimeout(timer));
  }

  let settingsBootstrapSyncedAt = 0;

  // 启动时 onMounted 与路由加载会各请求一次设置 bootstrap；这里合并成一次网络请求。
  const SETTINGS_BOOTSTRAP_FETCH_TTL_MS = 5 * 1000;
  function installAdminBootstrapFetchDedupe() {
    if (typeof window === 'undefined' || typeof window.fetch !== 'function' || window.fetch.__adminBootstrapDedupe) return;
    const originalFetch = window.fetch.bind(window);
    const inFlight = new Map();
    const recent = new Map();
    const dedupeFetch = function adminBootstrapFetchDedupe(input, init) {
      const method = String(init?.method || 'GET').toUpperCase();
      const body = typeof init?.body === 'string' ? init.body : '';
      if (method !== 'POST' || !body.includes('"action":"getSettingsBootstrap"')) {
        // 任何其它管理请求都可能改变配置，顺手让短缓存失效。
        recent.clear();
        return originalFetch(input, init);
      }
      const key = String(input?.url || input || '') + '|' + body;
      const hit = recent.get(key);
      if (hit && Date.now() - hit.at < SETTINGS_BOOTSTRAP_FETCH_TTL_MS) return Promise.resolve(hit.response.clone());
      let pending = inFlight.get(key);
      if (!pending) {
        pending = originalFetch(input, init).then((response) => {
          if (response?.ok) recent.set(key, { at: Date.now(), response: response.clone() });
          return response;
        }).finally(() => inFlight.delete(key));
        inFlight.set(key, pending);
      }
      return pending.then((response) => response.clone());
    };
    dedupeFetch.__adminBootstrapDedupe = true;
    window.fetch = dedupeFetch;
  }

  function readFreshSettingsBootstrap(app) {
    if (settingsBootstrapSyncedAt <= 0 || Date.now() - settingsBootstrapSyncedAt > SETTINGS_BOOTSTRAP_CACHE_TTL_MS) return null;
    const data = app?.adminBootstrapCache?.data;
    if (!data || typeof data !== 'object') return null;
    return {
      config: data.config && typeof data.config === 'object' ? { ...data.config } : {},
      hostDomain: String(data.hostDomain || ''),
      nodes: Array.isArray(data.nodes) ? data.nodes.slice() : [],
      runtimeStatus: data.runtimeStatus && typeof data.runtimeStatus === 'object' ? { ...data.runtimeStatus } : {},
      revisions: data.revisions && typeof data.revisions === "object" ? { ...data.revisions } : {},
      generatedAt: String(data.generatedAt || "")
    };
  }

  // saveConfig 已返回完整 config，回填缓存后设置页刷新不必再拉 bootstrap。
  function updateAdminBootstrapCache(app, config, revisions) {
    const cache = app?.adminBootstrapCache;
    if (!cache || typeof cache !== 'object' || !cache.data || typeof cache.data !== 'object') return;
    app.adminBootstrapCache = {
      cachedAt: Date.now(),
      data: {
        ...cache.data,
        config: { ...config },
        revisions: { ...(revisions && typeof revisions === 'object' ? revisions : app.adminRevisions) }
      }
    };
    settingsBootstrapSyncedAt = Date.now();
  }

  function buildCurrentLogPageSignature(app) {
    if (typeof app?.buildLogPaginationSignature !== 'function') return '';
    let range = { startDate: app.logStartDate, endDate: app.logEndDate };
    if (typeof app.ensureLogDateRange === 'function') {
      try {
        range = app.ensureLogDateRange() || range;
      } catch {
        range = { startDate: app.logStartDate, endDate: app.logEndDate };
      }
    }
    return app.buildLogPaginationSignature({
      keyword: app.logSearchKeyword || '',
      searchMode: typeof app.getRuntimeLogSearchMode === 'function' ? app.getRuntimeLogSearchMode() : 'fts',
      requestGroup: app.logsRequestGroupFilter || '',
      statusGroup: app.logsStatusGroupFilter || '',
      startDate: range?.startDate || '',
      endDate: range?.endDate || ''
    });
  }

  // 日志第一页：同筛选条件 30 秒内复用，避免每次进入都清缓存再重拉。
  function patchLogPageCache(app) {
    if (!app || app.__adminLogPageCachePatched || typeof app.loadLogs !== 'function') return;
    app.__adminLogPageCachePatched = true;
    const originalLoadLogs = app.loadLogs.bind(app);
    app.loadLogs = function loadLogsWithFirstPageCache(page = this.logPage, routeToken = null, force = false) {
      const targetPage = Math.max(1, parseInt(page, 10) || 1);
      if (force || targetPage !== 1) return originalLoadLogs(page, routeToken, force);
      // 关闭日志功能时由原逻辑清空列表，不能拿旧缓存顶替。
      if (typeof this.isLogFeatureEnabled === 'function' && !this.isLogFeatureEnabled()) return originalLoadLogs(page, routeToken, force);
      const signature = buildCurrentLogPageSignature(this);
      const cached = signature
        && signature === logPageOneCacheState.signature
        && Date.now() - logPageOneCacheState.at < LOG_PAGE_ONE_CACHE_TTL_MS
        && typeof this.getCachedLogPage === 'function'
        ? this.getCachedLogPage(1, signature)
        : null;
      if (cached && typeof this.applyCachedLogPage === 'function') {
        if (typeof this.isRouteLoadCurrent === 'function' && !this.isRouteLoadCurrent(routeToken)) return Promise.resolve(null);
        this.logsLoadSeq = (Number(this.logsLoadSeq) || 0) + 1;
        this.logsPageLoading = false;
        this.applyCachedLogPage(cached, signature);
        return Promise.resolve(cached);
      }
      const result = originalLoadLogs(page, routeToken, force);
      // 先记录签名：跨 realm 的 promise 回调会晚于 await 恢复，不能等到这里再写状态。
      if (signature) {
        logPageOneCacheState.signature = signature;
        logPageOneCacheState.at = Date.now();
      }
      return result;
    };
  }

  function patchSafetyContractMethods(app) {
    if (!app || patchedSafetyContractApp === app) return;
    patchedSafetyContractApp = app;

    if (typeof app.apiCall === 'function') {
      const originalApiCall = app.apiCall.bind(app);
      app.apiCall = async function apiCallWithNodeResourceWarnings(action, payload = {}) {
        const normalizedAction = String(action || '');
        let requestPayload = payload && typeof payload === 'object' ? payload : {};
        // forceRefresh 是失败重试用的：缓存里的版本号正是冲突掉的那一份，必须回源。
        if (normalizedAction === 'getSettingsBootstrap' && requestPayload.forceRefresh !== true) {
          const cachedBootstrap = readFreshSettingsBootstrap(app);
          if (cachedBootstrap) return cachedBootstrap;
        }
        if (normalizedAction === 'saveConfig') {
          requestPayload = {
            ...requestPayload,
            mutationId: String(requestPayload.mutationId || ('cfg-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10)))
          };
        }
        let result;
        try {
          result = await withUiRequestTimeout(app, normalizedAction, originalApiCall(action, requestPayload));
        } catch (error) {
          if (normalizedAction === 'saveConfig' && String(error?.code || '').toUpperCase() === 'CONFIG_REVISION_CONFLICT') {
            error.message = '配置版本已变化，请刷新设置确认差异后重新提交；当前编辑内容已保留。';
          }
          throw error;
        }
        if (normalizedAction === 'getSettingsBootstrap' || normalizedAction === 'getAdminBootstrap') {
          settingsBootstrapSyncedAt = Date.now();
        }
        if (normalizedAction === 'saveConfig' && result?.config && typeof result.config === 'object') {
          updateAdminBootstrapCache(app, result.config, result.revisions);
          // 配置变了，仪表盘数字可能同时变化，下一次进入重新取。
          dashboardLayerState.statsLoadedAt = 0;
          dashboardLayerState.runtimeLoadedAt = 0;
          dashboardLayerState.hotspotLoadedAt = 0;
        }
        if (normalizedAction === 'getNode' && Array.isArray(result?.warnings) && result.warnings.length > 0) {
          const warning = result.warnings.find((item) => item?.code === 'NODE_RESOURCE_LIMIT_EXCEEDED') || result.warnings[0];
          const field = String(warning?.field || 'record');
          const actual = warning?.actual == null ? '?' : String(warning.actual);
          const limit = warning?.limit == null ? '?' : String(warning.limit);
          this.showMessage('该旧节点超过 Worker 资源限制（' + field + ': ' + actual + '/' + limit + '），仍可读取和代理，但不会进入内存缓存或自动回写。', { tone: 'warning' });
        }
        return result;
      };
    }

    patchLogPageCache(app);

    app.runD1SchemaRepairFlow = async function runTwoPhaseD1SchemaRepairFlow(options = {}) {
      const readSnapshot = async () => {
        const snapshot = await this.apiCall('getD1SchemaStatus');
        return {
          snapshot,
          status: snapshot?.status && typeof snapshot.status === 'object' ? snapshot.status : {},
          repairPlan: snapshot?.repairPlan && typeof snapshot.repairPlan === 'object' ? snapshot.repairPlan : {}
        };
      };
      const showBlocked = async repairPlan => {
        await this.showMessage(formatD1RepairPlan(repairPlan), {
          title: 'D1 结构无法自动修复',
          tone: 'error',
          modal: true
        });
      };

      let { snapshot, status, repairPlan } = await readSnapshot();
      if (Array.isArray(repairPlan.blockingIssues) && repairPlan.blockingIssues.length > 0) {
        await showBlocked(repairPlan);
        return { completed: false, blocked: true, status, repairPlan };
      }
      if (status.schemaReady === true || repairPlan.phase === 'ready' || repairPlan.risk === 'none') {
        if (options.showNoop !== false) await this.showMessage(formatD1SchemaStatus(status) + '\\n\\n当前结构无需调整。', {
          title: '初始化 DB 结果',
          tone: 'success',
          modal: true
        });
        return { completed: true, status, repairPlan, result: snapshot };
      }

      const accepted = await this.askConfirm(formatD1RepairPlan(repairPlan), {
        title: '初始化 DB',
        tone: 'warning',
        confirmText: '开始安全修复'
      });
      if (!accepted) return { completed: false, cancelled: true, status, repairPlan };

      let result = null;
      if (repairPlan.phase === 'safe') {
        result = await this.apiCall('initLogsDb', { repairMode: 'safe' });
        if (result?.revisions) this.applyAdminRevisions(result.revisions);
        if (result?.pendingHighRisk === true) {
          ({ snapshot, status, repairPlan } = await readSnapshot());
          if (Array.isArray(repairPlan.blockingIssues) && repairPlan.blockingIssues.length > 0) {
            await showBlocked(repairPlan);
            return { completed: false, blocked: true, status, repairPlan, result };
          }
        } else {
          await this.showMessage(formatD1InitializationResult(result), {
            title: '初始化 DB 结果',
            tone: result?.schemaReady === true ? 'success' : 'error',
            modal: true
          });
          return { completed: result?.schemaReady === true, status: result?.status || status, repairPlan, result };
        }
      }

      if (repairPlan.phase === 'destructive' || repairPlan.risk === 'high') {
        const rebuildSteps = Array.isArray(repairPlan.steps)
          ? repairPlan.steps.filter(step => step?.kind === 'rebuild_table' || step?.kind === 'recreate_log_table')
          : [];
        const hasLossyLogsRebuild = rebuildSteps.some(step => step?.willDiscardData === true && step?.dataMode === 'discard');
        const highRiskMessage = [
          '以下表需要执行高风险主键修复：',
          ...rebuildSteps.map(step => step?.willDiscardData === true && step?.dataMode === 'discard'
            ? '• ' + String(step?.target || '') + '（直接销毁重建，将清空全部日志，不扫描旧日志，不创建本地备份）'
            : '• ' + String(step?.target || '') + '（使用影子表无损复制 ' + Math.max(0, Number(step?.estimatedRows) || 0) + ' 行）'),
          '',
          ...(hasLossyLogsRebuild ? ['执行成功后，旧日志只能通过 D1 Time Travel bookmark 恢复。', ''] : []),
          '执行前必须成功获取 D1 Time Travel bookmark。'
        ].join('\\n');
        const highRiskAccepted = await this.askConfirm(highRiskMessage, {
          title: '确认重建 D1 表',
          tone: 'warning',
          confirmText: hasLossyLogsRebuild ? '确认重建并清空日志' : '确认重建'
        });
        if (!highRiskAccepted) return { completed: false, cancelled: true, status, repairPlan };
        const repairToken = String(repairPlan.repairToken || '').trim();
        if (!repairToken) {
          const error = new Error('高风险修复令牌缺失，请重新检查 D1 结构。');
          error.code = 'D1_SCHEMA_REPAIR_PLAN_STALE';
          throw error;
        }
        result = await callConfirmedAdminAction(this, 'initLogsDb', {
          repairMode: 'confirmed-destructive',
          repairToken
        }, 'repairD1Schema');
      } else if (!result) result = await this.apiCall('initLogsDb', { repairMode: 'safe' });

      if (result?.revisions) this.applyAdminRevisions(result.revisions);
      await this.showMessage(formatD1InitializationResult(result), {
        title: '初始化 DB 结果',
        tone: result?.schemaReady === true ? 'success' : 'error',
        modal: true
      });
      return { completed: result?.schemaReady === true, status: result?.status || status, repairPlan, result };
    };

    if (typeof app.formatTidyPreviewGroupText === 'function') {
      const originalFormatTidyPreviewGroupText = app.formatTidyPreviewGroupText.bind(app);
      app.formatTidyPreviewGroupText = function formatBoundedTidyPreviewGroupText(group = {}) {
        if (group?.countIsLowerBound !== true) return originalFormatTidyPreviewGroupText(group);
        const label = String(group?.label || '').trim() || '未命名分组';
        const samples = Array.isArray(group?.samples) ? group.samples.map((item) => String(item || '').trim()).filter(Boolean) : [];
        const note = String(group?.note || '').trim();
        return '• ' + label + '：10000+ 项' + (samples.length ? '：' + samples.join('、') + (group?.truncated ? ' 等' : '') : '') + (note ? '（' + note + '）' : '');
      };
    }

    if (typeof app.buildTidyPreviewConfirmDialog === 'function') {
      const originalBuildTidyPreviewConfirmDialog = app.buildTidyPreviewConfirmDialog.bind(app);
      app.buildTidyPreviewConfirmDialog = function buildBoundedTidyPreviewConfirmDialog(preview = {}, scope = 'kv') {
        const dialog = originalBuildTidyPreviewConfirmDialog(preview, scope);
        const lowerBoundKeys = new Set([
          ...Array.isArray(preview?.fieldGroups) ? preview.fieldGroups : [],
          ...Array.isArray(preview?.deleteGroups) ? preview.deleteGroups : [],
          ...Array.isArray(preview?.rewriteGroups) ? preview.rewriteGroups : [],
          ...Array.isArray(preview?.preserveGroups) ? preview.preserveGroups : []
        ].filter((group) => group?.countIsLowerBound === true).map((group) => String(group?.key || '')));
        for (const section of Array.isArray(dialog?.sections) ? dialog.sections : []) {
          for (const item of Array.isArray(section?.items) ? section.items : []) {
            if (!lowerBoundKeys.has(String(item?.key || ''))) continue;
            item.countLabel = '10000+';
            item.label = String(item.label || '').trim() + '（10000+）';
          }
        }
        return dialog;
      };
    }

    app.buildD1TidySuccessMessage = function buildBudgetedD1TidySuccessMessage(summary = {}) {
      const parts = [
        'D1 整理完成：删除 ' + (Number(summary.deletedExpiredLogCount) || 0) + ' 条超保留期日志',
        '本轮处理 ' + (Number(summary?.budget?.processedRows) || 0) + ' 行'
      ];
      if (Number(summary.deletedExpiredStatsHourlyCount) > 0) parts.push('清理 ' + Number(summary.deletedExpiredStatsHourlyCount) + ' 条过期统计桶');
      if (summary.rebuiltLogsFts === true) parts.push('重建 proxy_logs_fts');
      if (summary.statsRebuildStatus === 'reset_for_new_logs') parts.push('统计已清空并将从新日志重新累计');
      if (summary.hasMore === true) {
        const scopes = Array.isArray(summary.remainingScopes) ? summary.remainingScopes.filter(Boolean).join('、') : '';
        parts.push('本轮达到维护预算，仍有待处理数据' + (scopes ? '（' + scopes + '）' : '') + '，可再次预览并继续执行');
      }
      return parts.join('，') + '。';
    };

    // Older shells call this helper while hydrating settings, but did not expose it.
    // Keep the preview field populated from either the current or legacy repository key.
    if (typeof app.syncReleaseSourcePreviewInSettingsForm !== 'function') {
      app.syncReleaseSourcePreviewInSettingsForm = function syncReleaseSourcePreviewInSettingsForm() {
        const form = this.settingsForm && typeof this.settingsForm === 'object' ? this.settingsForm : {};
        const source = String(form.githubRepo || form.releaseRepo || form.repo || '').trim();
        if (source && form.githubRepo !== source) form.githubRepo = source;
        return source;
      };
    }

    if (typeof app.buildNodeLinkPath === 'function') {
      const buildNodeLinkPath = app.buildNodeLinkPath.bind(app);
      app.isHostPrefixNodeLinkActive = function isHostPrefixNodeLinkActiveForApp(node = {}) {
        return isHostPrefixNodeLinkActive(this, node);
      };
      app.buildHostPrefixNodeOrigin = function buildEffectiveHostPrefixNodeOrigin(node = {}) {
        const nodeName = String(node?.name || '').trim().toLowerCase();
        const host = normalizeHostPrefixDnsHostname(this.hostDomain);
        return nodeName && host ? 'https://' + nodeName + '.' + host : '';
      };
      app.buildNodeLink = function buildEffectiveNodeLink(node = {}, kind = 'main') {
        const normalizedNode = node && typeof node === 'object' ? node : {};
        const hostPrefixActive = this.isHostPrefixNodeLinkActive(normalizedNode);
        if (hostPrefixActive) {
          const origin = this.buildHostPrefixNodeOrigin(normalizedNode);
          if (origin) {
            const path = buildNodeLinkPath(normalizedNode, kind);
            return path ? origin + path : origin;
          }
        }
        const pathNode = hostPrefixActive ? normalizedNode : { ...normalizedNode, entryMode: 'kv_route' };
        return String(window.location?.origin || '') + buildNodeLinkPath(pathNode, kind);
      };
    }

    if (typeof app.applyDashboardStatsState === 'function') {
      const applyDashboardStatsState = app.applyDashboardStatsState.bind(app);
      app.applyDashboardStatsState = function applyDashboardStatsStateWithTrafficPeriod(...args) {
        const retainedHotspot = this.dashboardD1WriteHotspot;
        const stats = retainDashboardD1WriteHotspotInStats(args[0], retainedHotspot);
        const result = applyDashboardStatsState(stats, ...args.slice(1));
        enqueue(() => {
          const nodes = getDashboardTrafficNodes();
          if (dashboardTrafficState.period === 'day') {
            dashboardTrafficState.daily = snapshotDashboardTrafficCard(nodes) || dashboardTrafficState.daily;
          } else if (dashboardTrafficState.monthly) {
            renderDashboardTrafficCard(dashboardTrafficState.monthly, 'month', app);
          }
          syncDashboardTrafficToggle(app);
        });
        return result;
      };
    }
    app.toggleDashboardTrafficPeriodFromUi = () => toggleDashboardTrafficPeriod(app);

    const originalGetNodeLatencyMeta = typeof app.getNodeLatencyMeta === 'function'
      ? app.getNodeLatencyMeta.bind(app)
      : null;
    const originalApplyNodesState = typeof app.applyNodesState === 'function'
      ? app.applyNodesState.bind(app)
      : null;
    app.normalizeNodeProbeResult = function normalizeNodeProbeResult(value = {}, fallbackPath = '') {
      return normalizeHeadProbeResult(value, fallbackPath);
    };
    app.formatNodeProbeResult = function formatNodeProbeResult(value = {}) {
      return formatHeadProbeResult(value);
    };
    app.getNodeProbeTitle = function getNodeProbeTitle(value = {}) {
      return formatHeadProbeTitle(value);
    };
    app.getNodeProbeMeta = function getNodeProbeMeta(line = {}, healthCount = 0) {
      if (!hasHeadProbeValue(line)) {
        return originalGetNodeLatencyMeta
          ? originalGetNodeLatencyMeta(null, healthCount)
          : { dotClass: 'bg-slate-200 dark:bg-slate-700', textClass: 'text-slate-500 dark:text-slate-400 font-medium', text: '--', titleClass: '' };
      }
      const probe = normalizeHeadProbeResult(line);
      if (probe.ok) {
        const meta = originalGetNodeLatencyMeta
          ? originalGetNodeLatencyMeta(probe.elapsedMs, healthCount)
          : { dotClass: 'bg-emerald-500', textClass: 'text-emerald-600 dark:text-emerald-400 font-medium', titleClass: '' };
        return { ...meta, text: formatHeadProbeResult(probe) };
      }
      return {
        dotClass: 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)] dark:shadow-[0_0_8px_rgba(248,113,113,0.4)]',
        textClass: 'text-red-600 dark:text-red-400 font-medium',
        text: formatHeadProbeResult(probe),
        titleClass: Number(healthCount) > 3 ? 'text-red-600 dark:text-red-400' : ''
      };
    };
    app.getNodePingRuntimeEntry = function getNodePingRuntimeEntryWithProbe(nodeName, lineId = '') {
      const key = this.buildNodePingRuntimeKey(nodeName, lineId);
      if (!key) return null;
      const entry = this.nodePingRuntimeMap && typeof this.nodePingRuntimeMap === 'object'
        ? this.nodePingRuntimeMap[key]
        : null;
      if (!entry || typeof entry !== 'object') return null;
      const ttlMs = this.getNodePingRuntimeTtlMs();
      const updatedAtMs = Date.parse(String(entry.latencyUpdatedAt || ''));
      if (ttlMs > 0 && Number.isFinite(updatedAtMs) && Date.now() - updatedAtMs > ttlMs) return null;
      const probe = normalizeHeadProbeResult(entry);
      const latencyUpdatedAt = this.normalizeNodePingRuntimeTimestamp(entry.latencyUpdatedAt);
      if (!hasHeadProbeValue(entry) && !latencyUpdatedAt) return null;
      return {
        latencyMs: probe.ok ? probe.elapsedMs : null,
        latencyUpdatedAt,
        ...(hasHeadProbeValue(entry) ? { probe } : {})
      };
    };
    app.getNodeLines = function getNodeLinesWithProbe(node = {}) {
      const lines = this.getNodeConfigLines(node);
      const nodeName = this.normalizeNodeKey(node?.name);
      if (!nodeName) return lines;
      return lines.map((line) => {
        const runtime = this.getNodePingRuntimeEntry(nodeName, line?.id);
        return runtime ? { ...line, ...runtime } : line;
      });
    };
    app.setNodeLineRuntimeProbe = function setNodeLineRuntimeProbe(nodeName, lineId, value = {}, updatedAt = '') {
      const key = this.buildNodePingRuntimeKey(nodeName, lineId);
      if (!key) return null;
      const probe = normalizeHeadProbeResult(value);
      const latencyUpdatedAt = this.normalizeNodePingRuntimeTimestamp(updatedAt) || new Date().toISOString();
      const entry = {
        latencyMs: probe.ok ? probe.elapsedMs : null,
        latencyUpdatedAt,
        probe
      };
      this.nodePingRuntimeMap = {
        ...(this.nodePingRuntimeMap && typeof this.nodePingRuntimeMap === 'object' ? this.nodePingRuntimeMap : {}),
        [key]: entry
      };
      return entry;
    };
    app.applyPingNodeResponse = function applyPingNodeResponseWithProbe(nodeOrName, payload = {}, _legacyLatency, updatedAt = '') {
      const inputNode = typeof nodeOrName === 'string'
        ? this.nodes.find((node) => this.normalizeNodeKey(node?.name) === this.normalizeNodeKey(nodeOrName))
        : nodeOrName;
      const response = payload && typeof payload === 'object' ? payload : {};
      const node = inputNode && typeof inputNode === 'object'
        ? inputNode
        : response.node && typeof response.node === 'object'
          ? this.hydrateNode(response.node)
          : null;
      const lineId = this.normalizeNodeKey(response.line?.id || response.activeLineId || this.getActiveNodeLine(node)?.id || '');
      const nodeName = String(node?.name || response.node?.name || (typeof nodeOrName === 'string' ? nodeOrName : '')).trim();
      const timestamp = this.normalizeNodePingRuntimeTimestamp(updatedAt || response.line?.latencyUpdatedAt) || new Date().toISOString();
      return lineId && nodeName
        ? this.setNodeLineRuntimeProbe(nodeName, lineId, response, timestamp)
        : null;
    };
    app.recordNodeHealthResult = function recordNodeHealthResultWithProbe(nodeName, value = {}, target = null) {
      const key = this.normalizeNodeKey(nodeName);
      const state = target && typeof target === 'object' ? target : this.nodeHealth;
      if (!key) return state;
      const probe = normalizeHeadProbeResult(value);
      state[key] = !probe.ok || Number(probe.elapsedMs) > 300 ? (state[key] || 0) + 1 : 0;
      return state;
    };
    if (originalApplyNodesState) {
      app.applyNodesState = function applyNodesStatePreservingProbe(...args) {
        const previousRuntime = this.nodePingRuntimeMap && typeof this.nodePingRuntimeMap === 'object'
          ? this.nodePingRuntimeMap
          : {};
        const result = originalApplyNodesState(...args);
        const nextRuntime = { ...(this.nodePingRuntimeMap || {}) };
        for (const [key, entry] of Object.entries(nextRuntime)) {
          if (previousRuntime[key]?.probe) nextRuntime[key] = { ...entry, probe: previousRuntime[key].probe };
        }
        this.nodePingRuntimeMap = nextRuntime;
        return result;
      };
    }
    app.checkSingleNodeHealth = async function checkSingleNodeHealthWithProbe(nodeOrName) {
      const token = this.beginNodePingRequest(nodeOrName, 'single');
      if (!token) return;
      const startedAt = Date.now();
      const probePath = GET_PROBE_PATH;
      try {
        const timeout = Number(this.getEffectiveSettingValue('pingTimeout')) || 10000;
        const node = typeof nodeOrName === 'string'
          ? this.nodes.find((item) => this.normalizeNodeKey(item?.name) === this.normalizeNodeKey(nodeOrName))
          : nodeOrName;
        const activeLine = this.getActiveNodeLine(node);
        const target = this.getNodeModalLineResolvedTarget(activeLine) || '';
        const request = target
          ? { target, timeout, forceRefresh: true, probePath }
          : { ...this.buildActiveLinePingPayload(nodeOrName), timeout, forceRefresh: true, probePath };
        const payload = await this.apiCall('pingNode', request);
        const probe = normalizeHeadProbeResult(payload, probePath);
        this.applyPingNodeResponse(node || nodeOrName, { ...payload, probe });
        this.recordNodeHealthResult(nodeOrName, probe);
      } catch {
        const probe = buildClientHeadProbeFailure(probePath, startedAt);
        this.applyPingNodeResponse(nodeOrName, { probe });
        this.recordNodeHealthResult(nodeOrName, probe);
      } finally {
        this.finishNodePingRequest(nodeOrName, token);
      }
    };
    app.checkAllNodesHealth = async function checkAllNodesHealthWithProbe() {
      const timeout = Number(this.getEffectiveSettingValue('pingTimeout')) || 10000;
      const probePath = GET_PROBE_PATH;
      const nodes = Array.isArray(this.nodes) ? this.nodes.slice() : [];
      if (!nodes.length) return;
      const health = { ...(this.nodeHealth || {}) };
      const tokens = new Map();
      for (const node of nodes) {
        const nodeName = this.normalizeNodeKey(node?.name);
        if (!nodeName) continue;
        const token = this.beginNodePingRequest(nodeName, 'batch');
        if (token) tokens.set(nodeName, token);
      }
      await runWithConcurrency(nodes, NODE_GET_PROBE_CONCURRENCY, async (node) => {
        const nodeName = this.normalizeNodeKey(node?.name);
        const token = nodeName ? tokens.get(nodeName) : '';
        if (!nodeName || !token) return;
        const startedAt = Date.now();
        try {
          const activeLine = this.getActiveNodeLine(node);
          const target = this.getNodeModalLineResolvedTarget(activeLine) || '';
          const request = target
            ? { target, timeout, forceRefresh: true, probePath }
            : { ...this.buildActiveLinePingPayload(node), timeout, forceRefresh: true, probePath };
          const payload = await this.apiCall('pingNode', request);
          const probe = normalizeHeadProbeResult(payload, probePath);
          this.applyPingNodeResponse(node, { ...payload, probe });
          this.recordNodeHealthResult(node.name, probe, health);
        } catch {
          const probe = buildClientHeadProbeFailure(probePath, startedAt);
          this.applyPingNodeResponse(node, { probe });
          this.recordNodeHealthResult(node.name, probe, health);
        } finally {
          this.finishNodePingRequest(nodeName, token);
        }
      });
      this.nodeHealth = health;
    };
    app.pingAllNodeLinesInModal = async function pingAllNodeLinesInModalWithProbe() {
      const lines = this.nodeModalLines.filter((line) => this.validateNodeModalLineTarget(line));
      if (!lines.length) {
        this.showMessage('请先至少填写一条有效的 http/https 目标源站', { tone: 'warning' });
        return;
      }
      const autoSort = this.isNodePanelPingAutoSortEnabled();
      const timeout = Number(this.getEffectiveSettingValue('pingTimeout')) || 10000;
      const probePath = GET_PROBE_PATH;
      this.nodeModalPingAllPending = true;
      this.nodeModalPingAllText = 'GET 测试中...';
      try {
        for (let index = 0; index < lines.length; index += 1) {
          const line = lines[index];
          const target = this.getNodeModalLineResolvedTarget(line);
          const startedAt = Date.now();
          this.nodeModalPingAllText = 'GET 测试中 ' + (index + 1) + '/' + lines.length;
          try {
            const payload = await this.apiCall('pingNode', {
              target,
              timeout,
              forceRefresh: true,
              probePath
            });
            const probe = normalizeHeadProbeResult(payload, probePath);
            line.probe = probe;
            line.latencyMs = probe.ok ? probe.elapsedMs : null;
          } catch {
            line.probe = buildClientHeadProbeFailure(probePath, startedAt);
            line.latencyMs = null;
          }
          const draft = this.splitNodeModalLineDraft(target);
          line.target = draft.target;
          line.port = draft.port;
          line.latencyUpdatedAt = new Date().toISOString();
        }
        if (autoSort) {
          this.nodeModalLines = this.sortLinesByLatency(this.nodeModalLines);
          this.syncNodeModalLinesState(this.nodeModalLines[0]?.id || '');
        } else {
          this.syncNodeModalLinesState();
        }
      } finally {
        this.nodeModalPingAllPending = false;
        this.nodeModalPingAllText = '全局 GET 测试';
      }
    };

    if (typeof app.loadDashboard === 'function') {
      app.loadDashboard = async function loadDashboardInLayers(routeToken = null, options = {}) {
        const forceRefresh = options?.forceRefresh === true;
        if (forceRefresh && this.dashboardRefreshPending) return null;
        const loadSeq = ++dashboardLayerState.loadSeq;
        const routeIsCurrent = () => loadSeq === dashboardLayerState.loadSeq && this.isRouteLoadCurrent(routeToken);
        const previousHotspot = this.dashboardD1WriteHotspot;
        const previousStatsAvailable = dashboardLayerState.statsLoadedAt > 0 || String(this.dashboardView?.nodes?.meta || '').includes('统计时间');
        const previousRuntimeText = String(this.dashboardRuntimeView?.updatedText || '').trim();
        const previousRuntimeAvailable = dashboardLayerState.runtimeLoadedAt > 0 || (!!previousRuntimeText && !previousRuntimeText.includes('未加载'));
        const showHotspot = this.runtimeConfig?.dashboardShowD1WriteHotspot === true;
        const now = Date.now();
        const layerIsFresh = (loadedAt) => loadedAt > 0 && now - loadedAt < DASHBOARD_LAYER_CACHE_TTL_MS;
        const statsFresh = layerIsFresh(dashboardLayerState.statsLoadedAt);
        const runtimeFresh = layerIsFresh(dashboardLayerState.runtimeLoadedAt);
        const hotspotFresh = layerIsFresh(dashboardLayerState.hotspotLoadedAt);
        if (forceRefresh) this.dashboardRefreshPending = true;

        const refreshHotspot = async () => {
          dashboardLayerState.hotspotLoading = true;
          if (!dashboardLayerState.hotspotLoadedAt) {
            this.dashboardD1WriteHotspot = {
              ...(previousHotspot && typeof previousHotspot === 'object' ? previousHotspot : {}),
              status: 'loading',
              summary: 'D1 写入热点加载中',
              detail: '',
              available: false
            };
          }
          try {
            const hotspot = await this.apiCall('getDashboardD1WriteHotspot', { forceRefresh });
            if (!routeIsCurrent()) return;
            this.dashboardD1WriteHotspot = hotspot && typeof hotspot === 'object' ? hotspot : {};
            dashboardLayerState.hotspotLoadedAt = Date.now();
          } catch (error) {
            if (!routeIsCurrent() || dashboardLayerState.hotspotLoadedAt > 0) return;
            this.dashboardD1WriteHotspot = {
              ...(this.dashboardD1WriteHotspot || {}),
              status: 'failed',
              summary: 'D1 写入热点加载失败',
              detail: error?.message || '未知错误',
              available: false
            };
          } finally {
            if (loadSeq === dashboardLayerState.loadSeq) dashboardLayerState.hotspotLoading = false;
          }
        };

        // 60 秒内重复进入：复用上次结果，0 个请求（热点过期时最多 1 个）。
        if (!forceRefresh && statsFresh && runtimeFresh) {
          if (showHotspot && !hotspotFresh) void refreshHotspot();
          return null;
        }

        dashboardLayerState.statsLoading = true;
        dashboardLayerState.runtimeLoading = true;
        let snapshotFresh = false;

        if (!forceRefresh) {
          try {
            const payload = await this.apiCall('getDashboardCachedSnapshot');
            if (!routeIsCurrent()) return null;
            const snapshot = payload?.snapshot && typeof payload.snapshot === 'object' ? payload.snapshot : null;
            if (snapshot) {
              const cacheMeta = snapshot.cacheMeta && typeof snapshot.cacheMeta === 'object' ? snapshot.cacheMeta : {};
              snapshotFresh = String(cacheMeta.cacheStatus || '').trim().toLowerCase() === 'cache';
              if (snapshot.stats && typeof snapshot.stats === 'object') {
                this.applyDashboardStatsState({ ...snapshot.stats, cacheStatus: cacheMeta.cacheStatus || 'cache' });
                dashboardLayerState.statsLoadedAt = Date.now();
              }
              if (snapshot.runtimeStatus && typeof snapshot.runtimeStatus === 'object') {
                this.applyRuntimeStatusState(snapshot.runtimeStatus);
                dashboardLayerState.runtimeLoadedAt = Date.now();
              }
              this.dashboardCacheMeta = cacheMeta;
            }
          } catch (error) {
            console.warn('dashboard cached snapshot unavailable', error);
          }
          if (!routeIsCurrent()) return null;
          // D1 快照仍在 1 小时有效期内：它就是原生路径会返回的内容，不再重复拉活数据。
          if (snapshotFresh) {
            dashboardLayerState.statsLoading = false;
            dashboardLayerState.runtimeLoading = false;
            if (showHotspot && !hotspotFresh) void refreshHotspot();
            return null;
          }
        }

        const needStats = forceRefresh || !statsFresh;
        const needRuntime = forceRefresh || !runtimeFresh;
        if (!needStats) dashboardLayerState.statsLoading = false;
        if (!needRuntime) dashboardLayerState.runtimeLoading = false;

        const statsTask = needStats ? this.apiCall('getDashboardCoreStats', { forceRefresh }).then((stats) => {
          if (!routeIsCurrent()) return stats;
          this.applyDashboardStatsState(stats && typeof stats === 'object' ? stats : {});
          dashboardLayerState.statsLoadedAt = Date.now();
          return stats;
        }).catch((error) => {
          if (routeIsCurrent() && !previousStatsAvailable) this.applyDashboardErrorState(error?.message || '仪表盘统计加载失败');
          throw error;
        }).finally(() => {
          if (loadSeq === dashboardLayerState.loadSeq) dashboardLayerState.statsLoading = false;
        }) : Promise.resolve(null);

        const runtimeTask = needRuntime ? this.apiCall('getRuntimeStatus', { forceRefresh }).then((payload) => {
          if (!routeIsCurrent()) return payload;
          const runtimeStatus = payload?.status && typeof payload.status === 'object' ? payload.status : {};
          this.applyRuntimeStatusState(runtimeStatus);
          this.patchAdminBootstrapCache({ runtimeStatus: this.runtimeStatus });
          dashboardLayerState.runtimeLoadedAt = Date.now();
          return payload;
        }).catch((error) => {
          if (routeIsCurrent() && !previousRuntimeAvailable) this.applyRuntimeStatusErrorState(error?.message || '运行状态加载失败');
          throw error;
        }).finally(() => {
          if (loadSeq === dashboardLayerState.loadSeq) dashboardLayerState.runtimeLoading = false;
        }) : Promise.resolve(null);

        if (showHotspot && (forceRefresh || !hotspotFresh)) void refreshHotspot();

        const results = await Promise.allSettled([statsTask, runtimeTask]);
        if (forceRefresh && routeIsCurrent()) {
          const failures = results.filter((item) => item.status === 'rejected' && item.reason);
          if (failures.length) {
            this.showMessage('仪表盘部分刷新失败，已保留其余可用状态。', { tone: 'warning', modal: true });
          }
        }
        // 强制刷新同一时刻只有一个在飞，被后来的普通加载顶掉也必须解锁，否则刷新按钮永久失效。
        if (forceRefresh) this.dashboardRefreshPending = false;
        return results;
      };
    }

    app.runPreviewedTidy = async function runPreviewedTidyWithPlanToken(rawScope = 'kv') {
      const scope = String(rawScope || 'kv').trim().toLowerCase() === 'd1' ? 'd1' : 'kv';
      const title = scope === 'd1' ? '整理 D1 数据' : '整理 KV 数据';
      const action = scope === 'd1' ? 'tidyD1Data' : 'tidyKvData';
      const confirmText = scope === 'd1' ? '开始整理 D1' : '开始整理 KV';
      try {
        let preview = await this.apiCall('previewTidyData', { scope });
        if (scope === 'd1' && preview?.requiresSchemaInitialization === true) {
          const repair = await this.runD1SchemaRepairFlow({ showNoop: false });
          if (repair?.completed !== true) return;
          preview = await this.apiCall('previewTidyData', { scope });
          if (preview?.requiresSchemaInitialization === true) {
            const error = new Error('D1 初始化后仍未通过兼容检查，请检查 Schema 状态');
            error.code = 'D1_SCHEMA_INCOMPATIBLE';
            throw error;
          }
        }
        const dialog = this.buildTidyPreviewConfirmDialog(preview, scope);
        const message = this.buildTidyPreviewConfirmText(preview, scope);
        const quotaBlocked = preview?.quotaBudget?.blocked === true;
        const accepted = await this.askConfirm(message, {
          title,
          tone: 'warning',
          confirmText: quotaBlocked ? '关闭' : confirmText,
          summary: dialog.summary,
          sections: dialog.sections,
          warnings: dialog.warnings
        });
        if (!accepted || quotaBlocked) return;
        const planToken = String(preview?.planToken || '');
        const executionPayload = { planToken };
        const result = await this.apiCall(action, executionPayload);
        const refreshTasks = [this.loadSettings()];
        if (scope === 'kv') {
          refreshTasks.push(this.loadNodes());
        } else {
          if (String(this.currentHash || '') === '#logs') refreshTasks.push(this.loadLogs(1));
          if (String(this.currentHash || '') === '#dashboard') refreshTasks.push(this.loadDashboard(null, { forceRefresh: true }));
        }
        const refreshIncomplete = (await Promise.allSettled(refreshTasks)).some((item) => item.status === 'rejected');
        const summaryMessage = scope === 'd1'
          ? this.buildD1TidySuccessMessage(result?.summary || {})
          : this.buildKvTidySuccessMessage(result);
        const resultMessage = buildTidyExecutionResultMessage(this, result, summaryMessage, refreshIncomplete);
        await this.showMessage(resultMessage, {
          title: scope === 'd1' ? 'D1 整理结果' : 'KV 整理结果',
          tone: refreshIncomplete ? 'warning' : 'success',
          modal: true
        });
      } catch (error) {
        console.error('runPreviewedTidy failed', error);
        const errorCode = String(error?.code || '');
        const scopeLabel = scope === 'd1' ? 'D1' : 'KV';
        const planRecoveryMessage = errorCode === 'TIDY_PLAN_STALE'
          ? scopeLabel + ' 整理计划已过期或数据已变化，请重新预览并确认后再执行。'
          : errorCode === 'TIDY_PLAN_INVALID'
            ? scopeLabel + ' 整理计划凭证无效，请重新预览并确认后再执行。'
            : '';
        const schemaRepairMessage = errorCode.startsWith('D1_SCHEMA_REPAIR_')
          ? formatD1RepairError(error, title + '失败')
          : '';
        this.showMessage(planRecoveryMessage || schemaRepairMessage || title + '失败: ' + (error?.message || '未知错误'), { tone: 'error', modal: true });
      }
    };

    app.exportNodes = async function exportNodes() {
      try {
        const result = await this.apiCall('exportConfig');
        this.downloadJson(Array.isArray(result?.nodes) ? result.nodes : [], 'emby_nodes_' + Date.now() + '.json');
      } catch (error) {
        console.error('exportNodes failed', error);
        this.showMessage('节点导出失败: ' + (error?.message || '未知错误'), { tone: 'error', modal: true });
      }
    };

    app.exportFull = async function exportFullWithSecrets() {
      const accepted = await this.askConfirm('完整备份将包含服务密钥，请仅保存到可信位置。', {
        title: '导出完整备份', tone: 'danger', confirmText: '确认导出'
      });
      if (!accepted) return;
      try {
        const result = await callConfirmedAdminAction(this, 'exportConfig', { includeSecrets: true }, 'exportConfig');
        if (result) this.downloadJson(result, 'emby_proxy_full_backup_' + Date.now() + '.json');
      } catch (error) {
        console.error('exportFull failed', error);
        this.showMessage('完整备份导出失败: ' + (error?.message || '未知错误'), { tone: 'error', modal: true });
      }
    };

    app.exportSettingsWithSecrets = async function exportSettingsWithSecrets() {
      const accepted = await this.askConfirm('设置与密钥备份会包含 Cloudflare API Token、Telegram Bot Token 等敏感密钥。请仅保存到可信位置。', {
        title: '导出设置与密钥', tone: 'danger', confirmText: '确认导出'
      });
      if (!accepted) return;
      try {
        const result = await callConfirmedAdminAction(this, 'exportSettings', { includeSecrets: true }, 'exportSettings');
        if (result) this.downloadJson(result, 'emby_proxy_settings_with_secrets_' + Date.now() + '.json');
      } catch (error) {
        console.error('exportSettingsWithSecrets failed', error);
        this.showMessage('设置与密钥导出失败: ' + (error?.message || '未知错误'), { tone: 'error', modal: true });
      }
    };

    app.initLogsDbFromUi = async function initializeDatabaseFromUi() {
      try {
        await this.runD1SchemaRepairFlow();
      } catch (error) {
        console.error('initLogsDbFromUi failed', error);
        this.showMessage(formatD1RepairError(error, '初始化 DB 失败'), { tone: 'error', modal: true });
      }
    };

  }

  function syncPlaybackInfoModeCopy() {
    const select = document.querySelector('#form-playback-info-mode');
    if (!select) return;
    const passthrough = select.querySelector('option[value="passthrough"]');
    const rewrite = select.querySelector('option[value="rewrite"]');
    if (passthrough) passthrough.textContent = '透传';
    if (rewrite) rewrite.textContent = '改写模式';
  }
  // 前三个字段的「继承全局」跟的是设置页的全局默认值，选中前就能看到会继承到什么。
  const NODE_INHERIT_GLOBAL_LABELS = {
    'form-playback-info-mode': () => formatNodeInheritGlobalMode('defaultPlaybackInfoMode', { rewrite: '改写', passthrough: '透传' }),
    'form-media-auth-mode': () => formatNodeInheritGlobalMode('defaultMediaAuthMode', { emby: 'Emby', jellyfin: 'Jellyfin', passthrough: '透传', auto: '自动识别' }),
    'form-real-client-ip-mode': () => formatNodeInheritGlobalMode('defaultRealClientIpMode', { forward: '透传', strip: '仅 X-Real-IP', disable: '不透传' }),
    // 主视频流策略没有全局默认值：inherit 由该节点自身的直连标记决定，所以按节点算。
    'form-main-video-stream-mode': () => formatNodeVideoStreamInheritLabel(window.App)
  };
  // 与 Worker 的 isNodeDirectSourceEnabled 同语义：proxyMode/direct 标记优先，其次看标签与备注里的「直连」。
  function isNodeMarkedDirectSource(node = {}) {
    const proxyMode = String(node?.proxyMode || node?.mode || '').trim().toLowerCase();
    if (['direct', 'source-direct', 'origin-direct', 'node-direct'].includes(proxyMode)) return true;
    if (node?.direct === true || node?.sourceDirect === true || node?.directSource === true || node?.direct2xx === true) return true;
    const explicitText = (Array.isArray(node?.tags) ? node.tags.join(' ') : String(node?.tag || '')) + ' ' + String(node?.remark || '');
    return /(?:^|[\\s[(【])(?:直连|source-direct|origin-direct|node-direct)(?:$|[\\s\\])】])/i.test(explicitText);
  }

  function formatNodeVideoStreamInheritLabel(app) {
    const form = app?.nodeModalForm;
    if (!form) return '继承全局';
    // 已保存节点带着 proxyMode/direct 这类表单里没有的标记，按名字回查一次。
    const name = String(form.originalName || form.name || '').trim().toLowerCase();
    const saved = name && Array.isArray(app?.nodes)
      ? app.nodes.find((node) => String(node?.name || '').trim().toLowerCase() === name)
      : null;
    // 标签和备注以表单草稿为准：用户正在改的内容才是保存后的结果。
    const merged = { ...(saved || {}), tag: form.tag, tags: undefined, remark: form.remark };
    return isNodeMarkedDirectSource(merged) ? '继承全局（直连）' : '继承全局（反代）';
  }
  function readNodeInheritGlobalMode(app, key, labelMap) {
    const read = (source) => {
      const value = source && typeof source === 'object' ? source[key] : '';
      return String(value || '').trim().toLowerCase();
    };
    // settingsForm 只在设置页真正渲染后才被填充（可能是空对象），所以逐层回退而不是只读它。
    const value = read(app?.settingsForm) || read(app?.runtimeConfig) || read(app?.config);
    // 未知值不直接透给用户看，否则界面会冒出 something_unknown 这种内部标识。
    return labelMap[value] || '';
  }

  function formatNodeInheritGlobalMode(key, labelMap) {
    const label = readNodeInheritGlobalMode(window.App, key, labelMap);
    return label ? '继承全局（' + label + '）' : '继承全局';
  }

  // 节点「TMDB 聚合」开关：节点保存载荷是模板里的固定字段表，没有可改的组装函数，
  // 所以给 apiCall 打一次性补丁：只给节点保存那一次调用补上字段，其余原样透传。
  function patchTmdbNodeMethods(app) {
    if (!app || tmdbPatchedApp === app) return;
    const originalBuildNodeModalFormState = app.buildNodeModalFormState;
    const originalApiCall = app.apiCall;
    if (typeof originalBuildNodeModalFormState !== 'function' || typeof originalApiCall !== 'function') return;
    app.buildNodeModalFormState = function (...args) {
      const state = originalBuildNodeModalFormState.apply(this, args);
      const source = state?.hydratedNode || args[0] || {};
      if (state?.form) state.form.tmdbAggregationEnabled = source?.tmdbAggregationEnabled === true;
      return state;
    };
    // 一次性替换，而不是每次保存前后换入换出：两个保存重叠时，后者的 finally 会还原掉
    // 前者的包装，于是那次保存悄悄丢掉开关。'originalName' 只有节点保存载荷才带。
    app.apiCall = function (action, payload, ...rest) {
      if (action === 'save' && payload && typeof payload === 'object' && 'originalName' in payload) {
        const enabled =
          document.querySelector('[data-admin-node-tmdb-aggregation="1"] input')?.checked === true ||
          this?.nodeModalForm?.tmdbAggregationEnabled === true;
        if (this?.nodeModalForm) this.nodeModalForm.tmdbAggregationEnabled = enabled;
        return originalApiCall.call(this, action, { ...payload, tmdbAggregationEnabled: enabled }, ...rest);
      }
      return originalApiCall.call(this, action, payload, ...rest);
    };
    tmdbPatchedApp = app;
  }

  function syncTmdbAggregationControl(app, content, advancedFields) {
    if (!app || !content || !advancedFields) return;
    patchTmdbNodeMethods(app);
    if (app.nodeModalForm) {
      const currentName = String(app.nodeModalForm.originalName || app.nodeModalForm.name || '')
        .trim()
        .toLowerCase();
      const currentNode = (Array.isArray(app.nodes) ? app.nodes : []).find(
        (node) => String(node?.name || '').trim().toLowerCase() === currentName,
      );
      if (typeof app.nodeModalForm.tmdbAggregationEnabled !== 'boolean') {
        app.nodeModalForm.tmdbAggregationEnabled = currentNode?.tmdbAggregationEnabled === true;
      }
    }
    let field = document.querySelector('[data-admin-node-tmdb-aggregation="1"]');
    if (!field) {
      field = document.createElement('label');
      field.setAttribute('data-admin-node-tmdb-aggregation', '1');
      field.className =
        'col-span-full flex items-start justify-between gap-4 border-b border-slate-100 pb-3.5 dark:border-slate-800';
      field.innerHTML =
        '<span class="min-w-0"><span class="block text-sm text-slate-500">TMDB 聚合</span><span class="mt-1 block text-xs leading-5 text-slate-400">把列表请求里的 AnyProviderIdEquals=tmdb.&lt;id&gt; 换成 TMDB 的标题 + 年份再向本节点查询；集与季请求不改写。凭据取「账号设置」里的 TMDB 两项，留空时读 Worker 环境变量。</span></span><span class="relative mt-0.5 inline-flex h-5 w-9 shrink-0 items-center"><input type="checkbox" class="peer absolute inset-0 h-full w-full cursor-pointer opacity-0"><span class="pointer-events-none absolute inset-0 rounded-full bg-slate-200 transition-colors peer-checked:bg-brand-600 peer-focus-visible:ring-2 peer-focus-visible:ring-brand-400 peer-focus-visible:ring-offset-2 dark:bg-slate-700"></span><span class="pointer-events-none absolute left-0.5 h-4 w-4 rounded-full bg-white shadow-sm transition-transform peer-checked:translate-x-4"></span></span>';
    }
    const input = field.querySelector('input');
    if (input) {
      const syncValue = () => {
        if (app.nodeModalForm) app.nodeModalForm.tmdbAggregationEnabled = input.checked === true;
      };
      input.onchange = syncValue;
      input.onclick = syncValue;
      const renderKey = String(app.nodeModalRenderKey ?? '');
      if (field.dataset.renderKey !== renderKey) {
        input.checked = app.nodeModalForm?.tmdbAggregationEnabled === true;
        field.dataset.renderKey = renderKey;
      }
    }
    if (field.parentElement !== advancedFields) advancedFields.prepend(field);
  }

  function syncNodeInheritCopy(app) {
    if (!app) return;
    for (const [id, resolveLabel] of Object.entries(NODE_INHERIT_GLOBAL_LABELS)) {
      const inherit = document.querySelector('#' + id + ' option[value="inherit"]');
      if (!inherit) continue;
      const text = resolveLabel();
      if (inherit.textContent !== text) inherit.textContent = text;
    }
    // 主视频流策略的继承结果取决于标签/备注，这两项是输入框，改完要立即重算。
    bindNodeVideoStreamInheritInputs();
  }

  let nodeVideoStreamInheritBound = false;
  function bindNodeVideoStreamInheritInputs() {
    if (nodeVideoStreamInheritBound) return;
    const tag = document.querySelector('#form-tag');
    const remark = document.querySelector('#form-remark');
    if (!tag || !remark) return;
    nodeVideoStreamInheritBound = true;
    for (const input of [tag, remark]) {
      input.addEventListener('input', () => syncNodeInheritCopy(window.App));
    }
  }

  function applySafetyContractEnhancements() {
    const app = window.App;
    if (!app) return;
    patchSafetyContractMethods(app);
    syncPlaybackInfoModeCopy();
    syncNodeInheritCopy(app);
  }

  // 亮暗切换不能靠逐元素的颜色过渡：它们的时长和缓动是为 hover 定的，
  // 一次换色会让上百个元素各跑各的，且 sRGB 插值中途过灰。这里先关掉全部过渡
  // 让颜色一步落地，再用 View Transition 的一次全页交叉淡入代替逐元素插值。
  let patchedThemeTransitionApp = null;

  function swapUiTheme(applyThemeChange) {
    const root = document?.documentElement;
    if (!root?.setAttribute) {
      applyThemeChange();
      return;
    }
    root.setAttribute('data-theme-switching', '1');
    let settled = false;
    const settle = () => {
      if (settled) return;
      settled = true;
      root.removeAttribute('data-theme-switching');
    };
    let reduceMotion = false;
    try {
      reduceMotion = !!window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches;
    } catch {}
    let transition = null;
    if (!reduceMotion) {
      try {
        transition = document.startViewTransition?.(applyThemeChange) || null;
      } catch (error) {
        console.error('theme view transition failed', error);
      }
    }
    if (!transition) {
      applyThemeChange();
      // 过渡已经关掉，颜色这一帧就落完了；下一帧再放开，放开时已没有属性变化可过渡。
      enqueue(() => enqueue(settle));
      return;
    }
    transition.finished.then(settle, settle);
  }

  // 工具栏按钮走 App.toggleTheme()；替换成带过渡守护的版本，别处调用同一函数也一并生效。
  function patchThemeTransitionMethods(app) {
    if (!app || patchedThemeTransitionApp === app) return;
    patchedThemeTransitionApp = app;
    if (typeof app.toggleTheme !== 'function') return;
    const originalToggleTheme = app.toggleTheme.bind(app);
    app.toggleTheme = function toggleThemeWithoutColorFlicker() {
      swapUiTheme(originalToggleTheme);
    };
  }

  let patchedDnsIpPoolDeleteApp = null;

  // 优选 IP 工作台删除后残留：getDnsIpWorkspace 会把浏览器本地池并进 sharedPoolItems 返回
  // （为给本地 IP 补探活结果），客户端又把这份合列表当成「共享快照」存进
  // dnsIpSourceSharedPoolItems。于是删掉本地池条目时，服务端 fetch 缓存里根本没有这个 IP，
  // deletedIps 是空的，那份影子副本就留在共享列表里，只有刷新页面才消失。
  // 这里按本地池的实际删除结果，把同名影子副本一并清掉（两侧都有的 IP 已被接口删掉，重复清理无害）。
  function patchDnsIpPoolDeleteMethods(app) {
    if (!app || patchedDnsIpPoolDeleteApp === app) return;
    if (typeof app.deleteSelectedDnsIpPoolItems !== 'function') return;
    patchedDnsIpPoolDeleteApp = app;
    const originalDelete = app.deleteSelectedDnsIpPoolItems.bind(app);
    const readLocalPoolKeys = (target) => new Set(
      (Array.isArray(target?.dnsIpLocalPoolItems) ? target.dnsIpLocalPoolItems : [])
        .map((item) => String(item?.ip || '').trim().toLowerCase())
        .filter(Boolean)
    );
    const poolItemKey = (item) => String(item?.ip || '').trim().toLowerCase();
    app.deleteSelectedDnsIpPoolItems = async function deleteSelectedDnsIpPoolItemsWithoutStaleSharedCopies(...args) {
      const localKeysBefore = readLocalPoolKeys(this);
      const result = await originalDelete(...args);
      const localKeysAfter = readLocalPoolKeys(this);
      const removedLocalKeys = new Set([...localKeysBefore].filter((key) => !localKeysAfter.has(key)));
      if (!removedLocalKeys.size) return result;
      const sharedItems = Array.isArray(this.dnsIpSourceSharedPoolItems) ? this.dnsIpSourceSharedPoolItems : [];
      const keptSharedItems = sharedItems.filter((item) => !removedLocalKeys.has(poolItemKey(item)));
      if (keptSharedItems.length !== sharedItems.length) this.setDnsIpSourceSharedPoolItems(keptSharedItems);
      return result;
    };
  }

  let dialogTitleSeq = 0;

  // 弹层是自绘 div，这里补上原生 dialog 的语义、焦点和 Esc 关闭。
  function syncDialogAccessibility() {
    const surfaces = Array.prototype.slice.call(
      document.querySelectorAll?.('[data-ui-backdrop] [data-ui-dialog-surface]') || []
    );
    // 弹层是 #app-shell 的子节点，不能给 shell 加 inert（会连弹层一起失效）。
    for (const surface of surfaces) {
      if (!surface?.dataset || surface.dataset.adminDialogA11y === '1') continue;
      surface.dataset.adminDialogA11y = '1';
      surface.setAttribute('role', 'dialog');
      surface.setAttribute('aria-modal', 'true');
      const title = surface.querySelector('h3');
      if (title) {
        if (!title.id) {
          dialogTitleSeq += 1;
          title.id = 'admin-dialog-title-' + dialogTitleSeq;
        }
        surface.setAttribute('aria-labelledby', title.id);
      }
      const active = document.activeElement;
      if (active && surface.contains?.(active)) continue;
      const target =
        surface.querySelector('input:not([type="hidden"]), textarea, select') ||
        surface.querySelector('button:last-of-type');
      try {
        target?.focus?.({ preventScroll: true });
      } catch (error) {
        console.error('apply dialog focus failed', error);
      }
    }
  }

  function handleDialogEscapeKey(event) {
    if (!event || event.key !== 'Escape' || event.defaultPrevented) return;
    const backdrops = Array.prototype.slice
      .call(document.querySelectorAll?.('[data-ui-backdrop]') || [])
      .filter((node) => node?.querySelector?.('[data-ui-dialog-surface]'));
    if (backdrops.length === 0) return;
    // 弹层按 z-index 递增顺序渲染，最后一个就是最上层。
    const top = backdrops[backdrops.length - 1];
    event.preventDefault?.();
    top.click?.();
  }

  document.addEventListener?.('keydown', handleDialogEscapeKey);
  // 自绘下拉是 fixed 定位的独立面板：点外部、按 Esc、滚动或改窗口尺寸都要收起，否则会飘在错位置。
  document.addEventListener?.('pointerdown', (event) => {
    const panel = document.querySelector('[data-admin-node-tag-color-panel="1"]');
    if (!panel) return;
    if (panel.contains(event.target) || event.target?.closest?.('[data-admin-node-tag-color-trigger="1"]')) return;
    closeTagColorPanel();
  }, true);
  document.addEventListener?.('keydown', (event) => {
    if (event.key === 'Escape' && document.querySelector('[data-admin-node-tag-color-panel="1"]')) {
      event.preventDefault?.();
      closeTagColorPanel();
    }
  }, true);
  window.addEventListener?.('scroll', closeTagColorPanel, true);
  window.addEventListener?.('resize', closeTagColorPanel);
  syncDialogAccessibility();

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      scheduleIconRefresh(document.body);
      scheduleShellRefresh();
    }, { once: true });
  } else {
    scheduleIconRefresh(document.body);
    scheduleShellRefresh();
  }

  window.addEventListener('load', () => {
    scheduleIconRefresh(document.body);
    scheduleShellRefresh();
  }, { once: true });

  if (typeof MutationObserver === 'function') {
    const observer = new MutationObserver((records) => {
      let shouldRefreshIcons = false;
      let shouldRefreshShell = false;
      let shouldSyncDialogs = false;
      for (const record of records) {
        if (record.type === 'attributes') {
          if (containsLucidePlaceholder(record.target)) shouldRefreshIcons = true;
          if (record.target === document.documentElement || record.target === document.body || touchesShellHooks(record.target)) {
            shouldRefreshShell = true;
          }
          continue;
        }
        for (const node of record.addedNodes) {
          if (!node || node.nodeType !== Node.ELEMENT_NODE) continue;
          if (containsLucidePlaceholder(node)) shouldRefreshIcons = true;
          if (touchesShellHooks(node)) shouldRefreshShell = true;
          if (touchesDialogLayer(node)) shouldSyncDialogs = true;
        }
        for (const node of record.removedNodes) {
          if (!node || node.nodeType !== Node.ELEMENT_NODE) continue;
          if (touchesDialogLayer(node)) shouldSyncDialogs = true;
        }
      }
      if (shouldRefreshIcons) scheduleIconRefresh(document.body);
      if (shouldRefreshShell) scheduleShellRefresh();
      if (shouldSyncDialogs) syncDialogAccessibility();
    });

    const observe = () => {
      if (document.documentElement) {
        observer.observe(document.documentElement, {
          childList: true,
          subtree: true,
          attributes: true,
          attributeFilter: ['class', 'open']
        });
      }
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', observe, { once: true });
    } else {
      observe();
    }
  }
})();
</script>`;

export { ADMIN_RUNTIME_ENHANCEMENT_STYLE, ADMIN_RUNTIME_ENHANCEMENT_SCRIPT };
