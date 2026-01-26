/**
 * EMBY-PROXY-PRO V11.3 (Data Management Edition)
 * 核心特性：
 * 1. 数据导入/导出 (JSON格式)
 * 2. 原生 WebSocketPair 转发
 * 3. 视频切片 Header 瘦身 & 禁用 Buffer
 * 4. JWT 安全管理后台
 */

const STATIC_REGEX = /\.(?:jpg|jpeg|gif|png|svg|ico|webp|js|css|woff2?|ttf|otf|map|webmanifest|json)$/i;
const STREAMING_REGEX = /\.(?:mp4|m4v|m4s|m4a|ogv|webm|mkv|mov|avi|wmv|flv|ts|m3u8|mpd)$/i;
const LOG_TRIGGER_REGEX = /(\/web\/index\.html|\/System\/Info|\/Sessions\/Capabilities|\/Users\/Authenticate)/i;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const segments = path.split('/').filter(p => p).map(p => decodeURIComponent(p));

    // --- 1. 管理后台逻辑 ---
    if (segments[0] === "admin") {
      if (segments[1] === "login" && request.method === "POST") return await handleLogin(request, env);
      
      const cookie = request.headers.get("Cookie");
      const token = parseCookie(cookie, "auth_token");
      const isValid = await verifyJwt(token, env.ADMIN_PASS);

      if (!isValid) {
        if (request.method === "POST") return new Response("Unauthorized", { status: 401 });
        return renderLoginPage();
      }
      if (request.method === "POST") return await handleApi(request, env);
      return renderAdminUI(env);
    }

    // --- 2. 代理主逻辑 ---
    if (segments.length >= 1) {
      const nodeName = segments[0];
      const nodeData = await getNodeConfigWithCache(nodeName, env, ctx);

      if (nodeData) {
        let authorized = false;
        let subIndex = 1;
        if (nodeData.secret) {
          if (segments[1] === nodeData.secret) { authorized = true; subIndex = 2; }
        } else { authorized = true; }

        if (authorized) {
          const remainingPath = "/" + segments.slice(subIndex).join('/');
          
          if (remainingPath === "/" || remainingPath === "") {
             const prefix = nodeData.secret ? `/${nodeName}/${nodeData.secret}` : `/${nodeName}`;
             return Response.redirect(url.origin + prefix + "/web/index.html", 302);
          }

          if (LOG_TRIGGER_REGEX.test(remainingPath)) {
            ctx.waitUntil(safeAddLog(env, request, nodeName, nodeData.target));
          }
          return await handleProxy(request, nodeData, remainingPath, nodeName, nodeData.secret);
        }
      }
    }
    return new Response("403 Forbidden / Access Denied", { status: 403 });
  }
};

// ==========================================
// JWT & Crypto Helpers
// ==========================================
async function handleLogin(request, env) {
  try {
    const formData = await request.formData();
    const password = formData.get("password");
    if (password === env.ADMIN_PASS) {
      const jwt = await generateJwt(env.ADMIN_PASS, 60 * 60 * 24 * 7);
      return new Response("Login Success", {
        status: 302,
        headers: {
          "Location": "/admin",
          "Set-Cookie": `auth_token=${jwt}; Path=/; Max-Age=${60 * 60 * 24 * 7}; HttpOnly; Secure; SameSite=Strict`
        }
      });
    }
    return renderLoginPage("密码错误");
  } catch (e) { return renderLoginPage("请求无效"); }
}

async function generateJwt(secret, expiresIn) {
  const header = { alg: "HS256", typ: "JWT" };
  const payload = { sub: "admin", exp: Math.floor(Date.now() / 1000) + expiresIn };
  const encHeader = base64UrlEncode(JSON.stringify(header));
  const encPayload = base64UrlEncode(JSON.stringify(payload));
  const key = await importKey(secret);
  const signature = await sign(key, `${encHeader}.${encPayload}`);
  return `${encHeader}.${encPayload}.${signature}`;
}

async function verifyJwt(token, secret) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [encHeader, encPayload, signature] = parts;
  const key = await importKey(secret);
  const expSignature = await sign(key, `${encHeader}.${encPayload}`);
  if (signature !== expSignature) return false;
  try {
    const payload = JSON.parse(base64UrlDecode(encPayload));
    if (payload.exp < Math.floor(Date.now() / 1000)) return false;
    return true;
  } catch (e) { return false; }
}

function base64UrlEncode(str) { return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}
async function importKey(secret) {
  const enc = new TextEncoder();
  return await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}
async function sign(key, data) {
  const enc = new TextEncoder();
  const signature = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
}
function parseCookie(cookieString, key) {
  if (!cookieString) return null;
  const cookies = cookieString.split(';');
  for (let cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === key) return value;
  }
  return null;
}

// ==========================================
// 业务逻辑
// ==========================================

async function getNodeConfigWithCache(nodeName, env, ctx) {
  const cache = caches.default;
  const cacheUrl = new URL(`https://internal-config-cache/${nodeName}`); 
  let response = await cache.match(cacheUrl);
  if (response) return await response.json();

  const nodeData = await env.ENI_KV.get(`node:${nodeName}`, { type: "json" });
  if (nodeData) {
    const jsonStr = JSON.stringify(nodeData);
    const cacheResp = new Response(jsonStr, { headers: { "Cache-Control": "public, max-age=60" } });
    ctx.waitUntil(cache.put(cacheUrl, cacheResp));
  }
  return nodeData;
}

async function handleProxy(request, node, path, name, key) {
  const targetBase = new URL(node.target);
  const url = new URL(request.url);
  const finalUrl = new URL(path, targetBase);
  finalUrl.search = url.search;

  const upgradeHeader = request.headers.get("Upgrade");
  const isWS = upgradeHeader && upgradeHeader.toLowerCase() === "websocket";
  const isStreaming = STREAMING_REGEX.test(finalUrl.pathname);
  const isStatic = STATIC_REGEX.test(finalUrl.pathname);

  // CORS Preflight
  if (request.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers") || "Content-Type, Authorization",
        "Access-Control-Max-Age": "86400"
      }
    });
  }

  const newHeaders = new Headers(request.headers);
  newHeaders.set("Host", targetBase.host);
  newHeaders.delete("cf-connecting-ip"); 
  newHeaders.delete("cf-ipcountry");
  
  const realIp = request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "127.0.0.1";
  newHeaders.set("X-Real-IP", realIp);
  newHeaders.set("X-Forwarded-For", realIp);
  newHeaders.set("X-Emby-Proxy", "Worker-V11.3");

  if (isStreaming) {
      newHeaders.delete("Cookie");
      newHeaders.delete("Referer");
      newHeaders.delete("User-Agent"); 
  }

  if (isWS) {
      try {
          const [client, server] = Object.values(new WebSocketPair());
          const wsTarget = new URL(finalUrl);
          wsTarget.protocol = wsTarget.protocol === 'https:' ? 'wss:' : 'ws:';
          const wsSession = new WebSocket(wsTarget.toString(), "emby-websocket");
          server.accept();
          server.addEventListener('message', event => wsSession.send(event.data));
          wsSession.addEventListener('message', event => server.send(event.data));
          wsSession.addEventListener('close', () => server.close());
          server.addEventListener('close', () => wsSession.close());
          wsSession.addEventListener('error', () => server.close());
          return new Response(null, { status: 101, webSocket: client });
      } catch (e) {
          return new Response("WebSocket Tunnel Error", { status: 502 });
      }
  }

  let cfOptions = {};
  if (isStreaming) {
    cfOptions = { cacheEverything: false, cacheTtl: 0 };
  } else if (isStatic) {
    cfOptions = { cacheEverything: true, cacheTtlByStatus: { "200-299": 86400, "404": 1, "500-599": 0 } };
  } else {
    cfOptions = { cacheTtl: 0 };
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    let response = await fetch(new Request(finalUrl.toString(), {
      method: request.method, headers: newHeaders, body: request.body, redirect: "manual", signal: controller.signal
    }), { cf: cfOptions });

    clearTimeout(timeoutId);

    let modifiedHeaders = new Headers(response.headers);
    modifiedHeaders.set("Access-Control-Allow-Origin", "*");
    
    if (isStreaming) {
        modifiedHeaders.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    }

    const location = modifiedHeaders.get("Location");
    if (location && (response.status >= 300 && response.status < 400)) {
      const prefix = key ? `/${name}/${key}` : `/${name}`;
      if (location.startsWith("/")) {
        modifiedHeaders.set("Location", `${prefix}${location}`);
      } else {
        try {
          const locURL = new URL(location);
          if (locURL.host === targetBase.host) {
            modifiedHeaders.set("Location", `${prefix}${locURL.pathname}${locURL.search}`);
          }
        } catch (e) {}
      }
    }

    return new Response(response.body, { 
        status: response.status, 
        statusText: response.statusText, 
        headers: modifiedHeaders 
    });

  } catch (err) {
    return new Response(`Proxy Error: ${err.message}`, { status: 502 });
  }
}

async function safeAddLog(env, request, name, target) {
  try {
    const ip = request.headers.get("cf-connecting-ip") || "Unknown";
    const country = request.cf ? request.cf.country : "CN";
    const city = request.cf ? request.cf.city : "Unknown";
    const timeStr = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false });
    
    let logsData = await env.ENI_KV.get("system:logs");
    let logs = logsData ? JSON.parse(logsData) : [];
    
    if (logs.length > 0) {
       const lastLog = logs[0];
       if (lastLog.ip === ip && lastLog.time.substring(0, 16) === timeStr.substring(0, 16)) return;
    }

    const newLog = { time: timeStr, ip, geo: `${city} [${country}]`, node: name, target };
    logs.unshift(newLog);
    if (logs.length > 50) logs = logs.slice(0, 50);
    await env.ENI_KV.put("system:logs", JSON.stringify(logs));
  } catch (e) {}
}

async function handleApi(request, env) {
  const data = await request.json();
  // [新增] 批量导入接口
  if (data.action === "import") {
    const nodes = data.nodes;
    if (Array.isArray(nodes)) {
        const cache = caches.default;
        for (const n of nodes) {
           if (n.name && n.target) {
               // 清理缓存以确保配置即时生效
               await cache.delete(`https://internal-config-cache/${n.name}`);
               await env.ENI_KV.put(`node:${n.name}`, JSON.stringify({ secret: n.secret || "", target: n.target }));
           }
        }
    }
    return new Response(JSON.stringify({ success: true }));
  }
  
  if (data.action === "save") {
    const cache = caches.default;
    await cache.delete(`https://internal-config-cache/${data.name}`);
    await env.ENI_KV.put(`node:${data.name}`, JSON.stringify({ secret: data.path || "", target: data.target }));
    return new Response(JSON.stringify({ success: true }));
  }
  if (data.action === "delete") {
    await env.ENI_KV.delete(`node:${data.name}`);
    return new Response(JSON.stringify({ success: true }));
  }
  if (data.action === "list") {
    const list = await env.ENI_KV.list({ prefix: "node:" });
    const nodes = await Promise.all(list.keys.map(async (k) => ({
      name: k.name.replace("node:", ""),
      ...(await env.ENI_KV.get(k.name, { type: "json" }))
    })));
    const logs = await env.ENI_KV.get("system:logs", { type: "json" }) || [];
    return new Response(JSON.stringify({ nodes, logs }));
  }
}

// ==========================================
// UI Functions
// ==========================================

function renderLoginPage(error = "") {
  return new Response(`
<!DOCTYPE html>
<html data-theme="black">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login</title>
  <link href="https://cdn.jsdelivr.net/npm/daisyui@3.9.4/dist/full.css" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>body { background-color: #050505; font-family: sans-serif; }</style>
</head>
<body class="min-h-screen flex items-center justify-center">
  <div class="card w-96 bg-base-900 shadow-xl border border-white/10">
    <div class="card-body">
      <div class="flex justify-center mb-4">
        <div class="w-16 h-16 rounded-xl bg-gradient-to-br from-[#52B54B] to-[#3e8d38] flex items-center justify-center text-white shadow-lg">
           <svg viewBox="0 0 100 100" class="h-8 w-8 fill-current ml-1"><path d="M84.3,44.4L24.7,4.8c-4.4-2.9-10.3,0.2-10.3,5.6v79.2c0,5.3,5.9,8.5,10.3,5.6l59.7-39.6C88.4,53.1,88.4,47.1,84.3,44.4z" /></svg>
        </div>
      </div>
      <h2 class="card-title justify-center text-white mb-2">EMBY PROXY</h2>
      <form action="/admin/login" method="POST">
        <div class="form-control">
          <input type="password" name="password" placeholder="Admin Password" class="input input-bordered w-full bg-base-100 focus:border-[#52B54B]" required />
        </div>
        ${error ? `<div class="text-error text-xs mt-2 text-center">${error}</div>` : ''}
        <div class="form-control mt-6">
          <button class="btn btn-primary bg-[#52B54B] border-0 hover:bg-[#3e8d38] text-white">Login</button>
        </div>
      </form>
    </div>
  </div>
</body>
</html>`, { headers: { "Content-Type": "text/html" } });
}

function renderAdminUI(env) {
  const cstDate = new Date().toLocaleString("en-US", {timeZone: "Asia/Shanghai"});
  const hour = new Date(cstDate).getHours();
  const theme = (hour >= 6 && hour < 18) ? "lofi" : "black"; 
  const isDark = theme === "black";
  const embyGreen = "#52B54B";

  return new Response(`
<!DOCTYPE html>
<html data-theme="${theme}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EMBY-PROXY-UI</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@3.9.4/dist/full.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@300;400;700;900&family=JetBrains+Mono:wght@400;700&display=swap');
        body { 
            font-family: 'Noto Sans SC', system-ui, -apple-system, sans-serif; 
            background-color: ${isDark ? '#050505' : '#f8fafc'};
            background-image: ${isDark ? 'radial-gradient(#ffffff08 1px, transparent 1px)' : 'radial-gradient(#00000008 1px, transparent 1px)'};
            background-size: 20px 20px;
        }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .glass-panel {
            background: ${isDark ? 'rgba(20, 20, 20, 0.7)' : 'rgba(255, 255, 255, 0.8)'};
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid ${isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.05)'};
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }
        .status-dot {
            width: 6px; height: 6px; border-radius: 50%;
            background-color: ${embyGreen};
            box-shadow: 0 0 12px ${embyGreen};
            animation: pulse 3s infinite ease-in-out;
        }
        @keyframes pulse { 0% { opacity: 0.3; transform: scale(0.8); } 50% { opacity: 1; transform: scale(1.2); } 100% { opacity: 0.3; transform: scale(0.8); } }
        .terminal-box { background-color: #0d1117; border: 1px solid #30363d; color: #c9d1d9; }
        .scrollbar-hide::-webkit-scrollbar { display: none; }
    </style>
</head>
<body class="min-h-screen p-4 lg:p-10 transition-colors duration-500 flex flex-col items-center">
    <div class="max-w-[1500px] w-full space-y-6">
        <header class="navbar glass-panel rounded-2xl px-8 py-5 flex justify-between items-center">
            <div class="flex items-center gap-4">
                <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-[#52B54B] to-[#3e8d38] flex items-center justify-center text-white shadow-lg shadow-emerald-900/20">
                    <svg viewBox="0 0 100 100" class="h-7 w-7 fill-current ml-1">
                        <path d="M84.3,44.4L24.7,4.8c-4.4-2.9-10.3,0.2-10.3,5.6v79.2c0,5.3,5.9,8.5,10.3,5.6l59.7-39.6C88.4,53.1,88.4,47.1,84.3,44.4z" />
                    </svg>
                </div>
                <div>
                    <h1 class="text-2xl font-black tracking-tight ${isDark ? 'text-white' : 'text-slate-800'}">EMBY-PROXY-UI</h1>
                    <div class="flex items-center gap-2 mt-1">
                        <div class="status-dot"></div>
                        <span class="text-xs font-medium opacity-50 tracking-wider">系统运行正常 · 北京时间</span>
                    </div>
                </div>
            </div>
            <div class="hidden md:block">
                <div class="font-mono text-xs opacity-40 bg-base-content/5 px-3 py-1.5 rounded-md" id="clock">Connecting...</div>
            </div>
        </header>

        <main class="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            <aside class="lg:col-span-4 xl:col-span-3 flex flex-col gap-6">
                <div class="card glass-panel shadow-xl">
                    <div class="card-body p-6 space-y-4">
                        <div class="flex items-center justify-between border-b border-base-content/10 pb-3 mb-2">
                            <h2 class="text-sm font-bold opacity-60">新增代理</h2>
                            <span class="text-[10px] font-mono opacity-40">DEPLOY</span>
                        </div>
                        <div class="form-control w-full space-y-1">
                            <label class="label p-0 mb-1"><span class="label-text text-xs font-bold opacity-70">代理名称 (英文)</span></label>
                            <input id="inName" type="text" placeholder="例如: HK-Emby" class="input input-bordered input-sm w-full bg-base-100/50 focus:border-[${embyGreen}] font-medium" />
                        </div>
                        <div class="form-control w-full space-y-1">
                            <label class="label p-0 mb-1"><span class="label-text text-xs font-bold opacity-70">访问密钥 (可选)</span></label>
                            <input id="inPath" type="password" placeholder="留空则公开访问" class="input input-bordered input-sm w-full bg-base-100/50 focus:border-[${embyGreen}] font-medium" />
                        </div>
                        <div class="form-control w-full space-y-1">
                            <label class="label p-0 mb-1"><span class="label-text text-xs font-bold opacity-70">服务器地址 (Target)</span></label>
                            <input id="inTarget" type="text" placeholder="http://1.2.3.4:8096" class="input input-bordered input-sm w-full bg-base-100/50 focus:border-[${embyGreen}] font-mono text-xs" />
                        </div>
                        <button onclick="saveNode()" class="btn btn-neutral w-full mt-4 bg-gradient-to-r from-slate-800 to-slate-900 text-white border-0 shadow-lg hover:shadow-xl hover:scale-[1.02] transition-all duration-300">
                            立即部署
                        </button>
                    </div>
                </div>
            </aside>

            <section class="lg:col-span-8 xl:col-span-9 flex flex-col gap-6 h-full">
                <div class="card glass-panel shadow-xl overflow-hidden min-h-[280px]">
                    <div class="px-6 py-4 border-b border-base-content/5 flex justify-between items-center bg-base-content/5">
                        <h2 class="text-sm font-bold opacity-70">活跃代理列表</h2>
                        <div class="flex items-center gap-2">
                             <button onclick="exportData()" class="btn btn-xs btn-ghost text-xs opacity-60 hover:opacity-100 font-mono tracking-wide" title="导出备份">
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-3 w-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                                导出
                             </button>
                             <button onclick="document.getElementById('importFile').click()" class="btn btn-xs btn-ghost text-xs opacity-60 hover:opacity-100 font-mono tracking-wide" title="从 JSON 导入">
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-3 w-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" /></svg>
                                导入
                             </button>
                             <input type="file" id="importFile" style="display:none" accept=".json" onchange="importData(this)" />
                             <div id="nodes-label" class="badge badge-success gap-1 badge-sm text-white border-0 ml-2" style="background-color: ${embyGreen}">
                                <span class="animate-pulse w-1.5 h-1.5 rounded-full bg-white"></span> 连接中
                             </div>
                        </div>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="table w-full">
                            <thead>
                                <tr class="text-xs uppercase opacity-50 bg-base-200/30 font-medium">
                                    <th class="pl-6 py-4">代理 ID</th>
                                    <th>入口地址 (点击复制)</th>
                                    <th class="text-right pr-6">操作</th>
                                </tr>
                            </thead>
                            <tbody id="nodeTable" class="text-sm font-medium opacity-90"></tbody>
                        </table>
                    </div>
                </div>

                <div class="card terminal-box shadow-2xl overflow-hidden rounded-xl flex flex-col h-[320px]">
                    <div class="px-4 py-2 border-b border-white/10 flex justify-between items-center bg-[#161b22]">
                        <div class="flex gap-2">
                            <div class="w-3 h-3 rounded-full bg-[#ff5f56]"></div>
                            <div class="w-3 h-3 rounded-full bg-[#ffbd2e]"></div>
                            <div class="w-3 h-3 rounded-full bg-[#27c93f]"></div>
                        </div>
                        <div class="flex items-center gap-2 text-[10px] font-mono text-slate-500">
                            <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                            access.log (Real-IP)
                        </div>
                    </div>
                    <div id="logViewer" class="p-4 overflow-y-auto font-mono text-[11px] space-y-2 scrollbar-hide flex-1"></div>
                </div>
            </section>
        </main>
    </div>

    <script>
        // 全局变量缓存节点数据，供导出使用
        let currentNodes = [];

        async function refresh() {
            try {
                const res = await fetch('/admin', { method: 'POST', body: JSON.stringify({ action: 'list' }) });
                if (res.status === 401) { location.reload(); return; }
                const data = await res.json();
                
                // 更新全局数据
                currentNodes = data.nodes;

                const nodeHtml = data.nodes.map(n => {
                    const fullLink = window.location.origin + '/' + n.name + (n.secret ? '/' + n.secret : '');
                    const isSecured = !!n.secret;
                    return \`
                        <tr class="hover:bg-base-content/5 transition-colors border-b border-base-content/5 last:border-0 group">
                            <td class="pl-6 py-3">
                                <div class="flex items-center gap-3">
                                    <div class="w-2 h-2 rounded-full \${isSecured ? 'bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.5)]' : 'bg-[#52B54B] shadow-[0_0_8px_rgba(82,181,75,0.5)]'}"></div>
                                    <span class="font-bold tracking-wide">\${n.name}</span>
                                    \${isSecured ? '<span class="px-1.5 py-0.5 rounded text-[9px] bg-amber-500/10 text-amber-500 font-bold border border-amber-500/20">密</span>' : ''}
                                </div>
                            </td>
                            <td>
                                <button onclick="copy('\${fullLink}')" class="text-left font-mono text-xs opacity-60 hover:opacity-100 hover:text-[#52B54B] transition-colors select-all truncate max-w-[200px] md:max-w-xs bg-base-content/5 px-2 py-1 rounded">
                                    \${fullLink}
                                </button>
                            </td>
                            <td class="text-right pr-6">
                                <button onclick="deleteNode('\${n.name}')" class="btn btn-ghost btn-xs text-rose-500 opacity-60 hover:opacity-100 hover:bg-rose-500/10">
                                    删除
                                </button>
                            </td>
                        </tr>
                    \`;
                }).join('');
                
                document.getElementById('nodeTable').innerHTML = nodeHtml || '<tr><td colspan="3" class="text-center py-12 opacity-30 text-xs">暂无活跃代理，请在左侧添加</td></tr>';
                document.getElementById('nodes-label').innerHTML = \`<span class="w-1.5 h-1.5 rounded-full bg-white"></span> \${data.nodes.length} 个运行中\`;

                const logHtml = data.logs.map(l => \`
                    <div class="flex gap-3 hover:bg-white/5 p-1 rounded cursor-default items-center">
                        <span class="text-emerald-500 w-[60px] shrink-0 opacity-80">\${l.time}</span>
                        <span class="text-cyan-400 w-[110px] shrink-0 font-bold bg-cyan-400/10 px-1 rounded text-center">\${l.ip}</span>
                        <span class="text-slate-500 w-[120px] shrink-0 truncate text-[10px]">\${l.geo}</span>
                        <span class="text-amber-400 w-[80px] shrink-0 font-bold">\${l.node}</span>
                        <span class="text-slate-600 shrink-0 select-none">→</span>
                        <span class="text-slate-400 truncate flex-1 italic opacity-60">\${l.target}</span>
                    </div>
                \`).join('');
                document.getElementById('logViewer').innerHTML = logHtml || '<div class="opacity-30 text-center mt-12 text-slate-600">// 等待流量接入...</div>';
            } catch(e) { console.error(e); }
        }

        async function saveNode() {
            const btn = document.querySelector('button[onclick="saveNode()"]');
            const originalText = btn.innerText;
            btn.innerText = "部署中...";
            btn.disabled = true;
            const name = document.getElementById('inName').value.trim();
            const path = document.getElementById('inPath').value.trim();
            const target = document.getElementById('inTarget').value.trim();
            if(name && target) {
                const res = await fetch('/admin', { method: 'POST', body: JSON.stringify({ action: 'save', name, path, target }) });
                if (res.status === 401) { location.reload(); return; }
                document.getElementById('inName').value = '';
                document.getElementById('inPath').value = '';
                document.getElementById('inTarget').value = '';
                await refresh();
            }
            btn.innerText = originalText;
            btn.disabled = false;
        }

        async function deleteNode(name) {
            if(!confirm('确定要删除代理 [' + name + '] 吗？')) return;
            const res = await fetch('/admin', { method: 'POST', body: JSON.stringify({ action: 'delete', name }) });
            if (res.status === 401) { location.reload(); return; }
            refresh();
        }

        // [新增] 导出功能
        async function exportData() {
            if(!currentNodes || currentNodes.length === 0) {
                alert("当前列表为空，无法导出");
                return;
            }
            const blob = new Blob([JSON.stringify(currentNodes, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'emby_nodes_backup.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }

        // [新增] 导入功能
        async function importData(input) {
            const file = input.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = async (e) => {
                try {
                    const nodes = JSON.parse(e.target.result);
                    if (!Array.isArray(nodes)) throw new Error('文件格式错误：必须是 JSON 数组');
                    
                    if(!confirm(\`确认导入 \${nodes.length} 个节点吗？\n如果存在同名节点，将被覆盖。\n(导入后会自动刷新)\`)) {
                        input.value = '';
                        return;
                    }
                    
                    // 调用后端批量导入
                    const res = await fetch('/admin', { 
                        method: 'POST', 
                        body: JSON.stringify({ action: 'import', nodes }) 
                    });
                    
                    if (res.status === 401) { location.reload(); return; }
                    
                    const result = await res.json();
                    if(result.success) {
                        alert('导入成功！');
                        await refresh();
                    } else {
                        alert('导入失败，请检查文件。');
                    }
                } catch (err) {
                    alert('导入失败: ' + err.message);
                }
            };
            reader.readAsText(file);
            input.value = ''; // 重置文件选择器，允许重复导入同一文件
        }

        function copy(text) { 
            navigator.clipboard.writeText(text);
            const el = document.activeElement;
            const original = el.innerText;
            el.innerText = "已复制 ✓";
            setTimeout(() => el.innerText = original, 1000);
        }

        function updateClock() {
            const now = new Date();
            const timeString = now.toLocaleTimeString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false });
            document.getElementById('clock').innerText = timeString + " CST";
        }

        refresh();
        setInterval(refresh, 5000);
        setInterval(updateClock, 1000);
    </script>
</body>
</html>
  `, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
}
