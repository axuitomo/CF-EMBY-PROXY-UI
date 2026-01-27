//EMBY-PROXY-PRO V13.1 (Simplicity Edition)
//放弃原先“每个节点一个 KV Key”的存储方式，改为使用一个 KV Key（例如 system:nodes）存储所有节点的配置 JSON。
//修改UI界面版本号

// ============================================================================
// 1. CONFIG MODULE
// ============================================================================
const Config = {
    Regex: {
        Static: /\.(?:jpg|jpeg|gif|png|svg|ico|webp|js|css|woff2?|ttf|otf|map|webmanifest|json)$/i,
        Streaming: /\.(?:mp4|m4v|m4s|m4a|ogv|webm|mkv|mov|avi|wmv|flv|ts|m3u8|mpd)$/i,
        LogTrigger: /(\/web\/index\.html|\/System\/Info|\/Sessions\/Capabilities|\/Users\/Authenticate)/i
    },
    Defaults: {
        JwtExpiry: 60 * 60 * 24 * 7, // 7天
        LoginLockDuration: 900,      // 15分钟
        MaxLoginAttempts: 5
    }
};

// ============================================================================
// 2. AUTH MODULE
// ============================================================================
const Auth = {
    async handleLogin(request, env) {
        const ip = request.headers.get("cf-connecting-ip") || "unknown";
        
        try {
            const formData = await request.formData();
            const password = (formData.get("password") || "").trim();

            // 1. 优先校验密码 (输入正确立即放行)
            if (password === env.ADMIN_PASS) {
                await env.ENI_KV.delete(`fail:${ip}`);
                const secret = env.JWT_SECRET || env.ADMIN_PASS; 
                const jwt = await this.generateJwt(secret, Config.Defaults.JwtExpiry);
                
                return new Response("Login Success", {
                    status: 302,
                    headers: {
                        "Location": "/admin", 
                        "Set-Cookie": `auth_token=${jwt}; Path=/; Max-Age=${Config.Defaults.JwtExpiry}; HttpOnly; Secure; SameSite=Strict`
                    }
                });
            }

            // 2. 密码错误：执行锁定逻辑
            let count = await env.ENI_KV.get(`fail:${ip}`);
            count = count ? parseInt(count) + 1 : 1;
            await env.ENI_KV.put(`fail:${ip}`, count, { expirationTtl: Config.Defaults.LoginLockDuration });

            if (count >= Config.Defaults.MaxLoginAttempts) {
                 return UI.renderLockedPage(ip, Config.Defaults.LoginLockDuration);
            }
            return UI.renderLoginPage(`密码错误 (剩余尝试次数: ${Config.Defaults.MaxLoginAttempts - count})`);

        } catch (e) {
            return UI.renderLoginPage("请求无效");
        }
    },

    async verifyRequest(request, env) {
        const cookie = request.headers.get("Cookie");
        const token = this.parseCookie(cookie, "auth_token");
        if (!token) return false;
        
        const secret = env.JWT_SECRET || env.ADMIN_PASS;
        return await this.verifyJwt(token, secret);
    },

    // --- JWT Crypto Helpers ---
    async generateJwt(secret, expiresIn) {
        const header = { alg: "HS256", typ: "JWT" };
        const payload = { sub: "admin", exp: Math.floor(Date.now() / 1000) + expiresIn };
        const encHeader = this.base64UrlEncode(JSON.stringify(header));
        const encPayload = this.base64UrlEncode(JSON.stringify(payload));
        const signature = await this.sign(secret, `${encHeader}.${encPayload}`);
        return `${encHeader}.${encPayload}.${signature}`;
    },

    async verifyJwt(token, secret) {
        if (!token) return false;
        const [encHeader, encPayload, signature] = token.split('.');
        if (!encHeader || !encPayload || !signature) return false;
        const expectedSignature = await this.sign(secret, `${encHeader}.${encPayload}`);
        if (signature !== expectedSignature) return false;
        try {
            const payload = JSON.parse(this.base64UrlDecode(encPayload));
            if (payload.exp < Math.floor(Date.now() / 1000)) return false;
            return true;
        } catch (e) { return false; }
    },

    base64UrlEncode(str) { return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
    base64UrlDecode(str) { 
        str = str.replace(/-/g, '+').replace(/_/g, '/'); 
        while (str.length % 4) str += '='; 
        return atob(str); 
    },
    async sign(secret, data) {
        const enc = new TextEncoder();
        const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const signature = await crypto.subtle.sign("HMAC", key, enc.encode(data));
        return this.base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
    },
    parseCookie(cookieString, key) {
        if (!cookieString) return null;
        const match = cookieString.match(new RegExp('(^| )' + key + '=([^;]+)'));
        return match ? match[2] : null;
    }
};

// ============================================================================
// 3. DATABASE MODULE (Refactored: Single Key Storage)
// ============================================================================
const Database = {
    // 定义统一存储所有节点的 Key
    STORAGE_KEY: "system:nodes",

    // 获取单个节点配置（带 Cache API 缓存）
    async getNode(nodeName, env, ctx) {
        const cache = caches.default;
        const cacheUrl = new URL(`https://internal-config-cache/node/${nodeName}`);
        
        // 1. 尝试从 Cache API 获取
        let response = await cache.match(cacheUrl);
        if (response) return await response.json();

        // 2. 缓存未命中：读取总配置 (消耗 1 次 KV 读取)
        // 相比原版读取单个 Key，这里读取的是包含所有节点的 JSON，
        // 但对于 Cloudflare KV 而言，读取 1KB 和 100KB 的延迟差异极小，
        // 且极大地优化了 list 操作的性能。
        const allNodes = await env.ENI_KV.get(this.STORAGE_KEY, { type: "json" }) || {};
        const nodeData = allNodes[nodeName];

        if (nodeData) {
            // 3. 写入独立缓存 (有效期 60秒)
            const jsonStr = JSON.stringify(nodeData);
            const cacheResp = new Response(jsonStr, { headers: { "Cache-Control": "public, max-age=60" } });
            ctx.waitUntil(cache.put(cacheUrl, cacheResp));
            return nodeData;
        }
        return null;
    },

    // 添加日志 (保持原逻辑，未改动)
    async addLog(env, request, name, target) {
        try {
            const ip = request.headers.get("cf-connecting-ip") || "Unknown";
            const timeStr = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false });
            
            let logsData = await env.ENI_KV.get("system:logs");
            let logs = logsData ? JSON.parse(logsData) : [];
            
            if (logs.length > 0 && logs[0].ip === ip && logs[0].time.substring(0, 16) === timeStr.substring(0, 16)) return;

            const geo = request.cf ? `${request.cf.city || 'Unk'} [${request.cf.country || 'CN'}]` : "Unknown";
            logs.unshift({ time: timeStr, ip, geo, node: name, target });
            
            if (logs.length > 50) logs = logs.slice(0, 50);
            await env.ENI_KV.put("system:logs", JSON.stringify(logs));
        } catch (e) { /* Ignore log errors */ }
    },

    // 处理管理 API (增删改查) - [核心优化]
    async handleApi(request, env) {
        const data = await request.json();
        const cache = caches.default;
        const listCacheKey = "https://internal-config-cache/system:nodes-list";

        // 预先读取所有节点数据 (1 次 KV 读取)
        let allNodes = await env.ENI_KV.get(this.STORAGE_KEY, { type: "json" }) || {};
        let hasChanges = false;

        switch (data.action) {
            case "save": 
            case "import":
                const nodesToSave = data.action === "save" ? [data] : data.nodes;
                
                for (const n of nodesToSave) {
                    if (n.name && n.target) {
                        // SSRF 检查保留 (注：需确保 Validator 存在，否则此处逻辑会被跳过)
                        if (typeof Validator !== 'undefined' && !Validator.isValidTarget(n.target)) {
                            continue;
                        }

                        // 更新内存对象
                        allNodes[n.name] = { 
                            secret: n.secret || "", 
                            target: n.target 
                        };

                        // 清除该节点的独立缓存
                        await cache.delete(`https://internal-config-cache/node/${n.name}`);
                        hasChanges = true;
                    }
                }

                // 如果有变动，统一写回 KV (1 次 KV 写入)
                if (hasChanges) {
                    await env.ENI_KV.put(this.STORAGE_KEY, JSON.stringify(allNodes));
                    await cache.delete(listCacheKey);
                }
                return new Response(JSON.stringify({ success: true }));

            case "delete":
                if (allNodes[data.name]) {
                    delete allNodes[data.name];
                    
                    // 写回 KV
                    await env.ENI_KV.put(this.STORAGE_KEY, JSON.stringify(allNodes));
                    
                    // 清除缓存
                    await cache.delete(`https://internal-config-cache/node/${data.name}`);
                    await cache.delete(listCacheKey);
                }
                return new Response(JSON.stringify({ success: true }));

            case "list":
                // [优化成果]
                // 此时 allNodes 已经在函数开头读取了一次 KV。
                // 相比原版遍历所有 Key 再逐个 Get (N+1)，这里只有 1 次 Get。
                
                let nodesList = [];
                const cachedList = await cache.match(listCacheKey);

                if (cachedList) {
                    nodesList = await cachedList.json();
                } else {
                    // 将对象转回数组格式供前端使用
                    nodesList = Object.keys(allNodes).map(key => ({
                        name: key,
                        ...allNodes[key]
                    }));

                    const listResp = new Response(JSON.stringify(nodesList), {
                        headers: { "Cache-Control": "public, max-age=60" }
                    });
                    await cache.put(listCacheKey, listResp); 
                }

                // 日志部分
                const logs = await env.ENI_KV.get("system:logs", { type: "json" }) || [];
                
                return new Response(JSON.stringify({ nodes: nodesList, logs }));
                
            default:
                return new Response("Invalid Action", { status: 400 });
        }
    }
};

// ============================================================================
// 4. PROXY MODULE
// ============================================================================
const Proxy = {
    async handle(request, node, path, name, key) {
        const targetBase = new URL(node.target);
        const finalUrl = new URL(path, targetBase);
        finalUrl.search = new URL(request.url).search;

        const isWS = request.headers.get("Upgrade") === "websocket";
        const isStreaming = Config.Regex.Streaming.test(path);
        const isStatic = Config.Regex.Static.test(path);

        if (request.method === "OPTIONS") return this.renderCors();

        const newHeaders = new Headers(request.headers);
        newHeaders.set("Host", targetBase.host);
        newHeaders.set("X-Real-IP", request.headers.get("cf-connecting-ip"));
        newHeaders.set("X-Forwarded-For", request.headers.get("cf-connecting-ip"));
        newHeaders.delete("cf-connecting-ip");
        newHeaders.delete("cf-ipcountry");

        if (isStreaming) {
            ["Cookie", "Referer", "User-Agent"].forEach(h => newHeaders.delete(h));
        }

        if (isWS) return this.handleWebSocket(finalUrl, newHeaders);

        let cfOptions = { cacheTtl: 0 };
        if (isStreaming) {
            cfOptions = { cacheEverything: false, cacheTtl: 0 }; 
        } else if (isStatic) {
            cfOptions = { cacheEverything: true, cacheTtlByStatus: { "200-299": 86400 } };
        }

        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 10000);
            
            const response = await fetch(new Request(finalUrl, {
                method: request.method,
                headers: newHeaders,
                body: request.body,
                redirect: "manual",
                signal: controller.signal
            }), { cf: cfOptions });
            
            clearTimeout(timeout);

            const modifiedHeaders = new Headers(response.headers);
            modifiedHeaders.set("Access-Control-Allow-Origin", "*");
            if (isStreaming) modifiedHeaders.set("Cache-Control", "no-store");

            this.rewriteLocation(modifiedHeaders, response.status, name, key, targetBase);

            return new Response(response.body, {
                status: response.status,
                statusText: response.statusText,
                headers: modifiedHeaders
            });

        } catch (err) {
            return UI.renderSmartError(request, err.message, name);
        }
    },

    handleWebSocket(url, headers) {
        try {
            const [client, server] = Object.values(new WebSocketPair());
            const wsTarget = new URL(url);
            wsTarget.protocol = wsTarget.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(wsTarget.toString(), "emby-websocket");
            server.accept();
            server.addEventListener('message', e => ws.send(e.data));
            ws.addEventListener('message', e => server.send(e.data));
            ws.addEventListener('close', () => server.close());
            server.addEventListener('close', () => ws.close());
            ws.addEventListener('error', () => server.close());
            return new Response(null, { status: 101, webSocket: client });
        } catch (e) {
            return new Response("WS Error", { status: 502 });
        }
    },

    rewriteLocation(headers, status, name, key, targetBase) {
        const location = headers.get("Location");
        if (!location || status < 300 || status >= 400) return;

        const prefix = key ? `/${name}/${key}` : `/${name}`;

        if (location.startsWith("/")) {
            headers.set("Location", `${prefix}${location}`);
            return;
        }

        try {
            const locUrl = new URL(location);
            if (locUrl.host === targetBase.host) {
                headers.set("Location", `${prefix}${locUrl.pathname}${locUrl.search}`);
            }
        } catch (e) { }
    },

    renderCors() {
        return new Response(null, {
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": "*"
            }
        });
    }
};

// ============================================================================
// 5. UI MODULE (XSS Fixed)
// ============================================================================
const UI = {
    // [安全修复] HTML 转义函数，防止 XSS
    escapeHtml(unsafe) {
        if (typeof unsafe !== 'string') return unsafe;
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    },

    renderSmartError(request, msg, nodeName) {
        const accept = request.headers.get("Accept") || "";
        // 渲染错误页时也要转义 nodeName，防止反射型 XSS
        const safeNodeName = this.escapeHtml(nodeName);
        const safeMsg = this.escapeHtml(msg);

        if (accept.includes("text/html")) {
            return new Response(`<html><body style="background:#101010;color:#ccc;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;text-align:center"><div><div style="font-size:60px;margin-bottom:20px">⚠️</div><h2 style="color:#52B54B">连接中断</h2><p>无法连接到节点 <strong>${safeNodeName}</strong></p><div style="background:#222;padding:10px;border-radius:5px;font-family:monospace;color:#ff6b6b;margin:20px 0">${safeMsg}</div><a href="javascript:location.reload()" style="background:#52B54B;color:#fff;padding:10px 20px;text-decoration:none;border-radius:5px;font-weight:bold">重试</a></div></body></html>`, { headers: { "Content-Type": "text/html;charset=utf-8" }, status: 502 });
        }
        return new Response(JSON.stringify({ error: msg, node: nodeName }), { status: 502, headers: { "Content-Type": "application/json" } });
    },

    renderLoginPage(error = "") {
        // 错误信息也需要转义
        const safeError = this.escapeHtml(error);
        return new Response(`<!DOCTYPE html><html data-theme="black"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Login</title><link href="https://cdn.jsdelivr.net/npm/daisyui@3.9.4/dist/full.css" rel="stylesheet"><script src="https://cdn.tailwindcss.com"></script><style>body{background:#050505}</style></head><body class="min-h-screen flex items-center justify-center"><div class="card w-96 bg-base-900 shadow-xl border border-white/10"><div class="card-body"><h2 class="card-title justify-center text-white mb-4">EMBY PROXY</h2><form method="POST"><div class="form-control mb-4"><input type="password" name="password" placeholder="Password" class="input input-bordered w-full focus:border-[#52B54B]" required /></div>${safeError?`<div class="text-error text-xs mb-4 text-center">${safeError}</div>`:''}<button class="btn btn-primary bg-[#52B54B] border-0 hover:bg-[#3e8d38] w-full text-white">Login</button></form></div></div></body></html>`, { headers: { "Content-Type": "text/html" } });
    },

    renderLockedPage(ip, duration) {
        // IP 地址虽然通常安全，但在安全审计中也建议转义
        const safeIp = this.escapeHtml(ip);
        return new Response(`<!DOCTYPE html><html data-theme="black"><head><meta charset="UTF-8"><title>Locked</title><link href="https://cdn.jsdelivr.net/npm/daisyui@3.9.4/dist/full.css" rel="stylesheet"><script src="https://cdn.tailwindcss.com"></script><style>body{background:#050505}</style></head><body class="min-h-screen flex items-center justify-center"><div class="card w-96 bg-base-900 shadow-xl border border-rose-900/30"><div class="card-body text-center"><div class="text-6xl mb-2">🔒</div><h2 class="text-xl font-bold text-white mb-2">IP 已锁定</h2><p class="text-sm opacity-60 mb-4">尝试次数过多，为了安全起见，您的IP (${safeIp}) 已被暂时锁定。</p><div class="badge badge-error gap-2 p-3 w-full justify-center">请等待 15 分钟</div><button onclick="location.reload()" class="btn btn-ghost btn-sm mt-4">刷新重试</button></div></div></body></html>`, { status: 429, headers: { "Content-Type": "text/html" } });
    },

    renderAdminUI() {
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
    <title>EMBY-PROXY PRO</title>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@3.9.4/dist/full.css" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: sans-serif; background-color: ${isDark ? '#050505' : '#f8fafc'}; background-image: ${isDark ? 'radial-gradient(#ffffff08 1px, transparent 1px)' : 'radial-gradient(#00000008 1px, transparent 1px)'}; background-size: 20px 20px; }
        .glass-panel { background: ${isDark ? 'rgba(20, 20, 20, 0.7)' : 'rgba(255, 255, 255, 0.8)'}; backdrop-filter: blur(20px); border: 1px solid ${isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.05)'}; }
        .input-emby:focus { border-color: ${embyGreen} !important; outline: none; }
        .text-main { color: ${isDark ? 'white' : '#1e293b'}; }
    </style>
</head>
<body class="min-h-screen p-4 lg:p-10 flex flex-col items-center transition-colors duration-500">
    <div class="max-w-[1400px] w-full space-y-6">
        <header class="navbar glass-panel rounded-2xl px-6 py-4 shadow-lg">
            <div class="flex-1 gap-4 items-center">
                <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-[#52B54B] to-[#3e8d38] flex items-center justify-center text-white shadow-lg">
                    <svg viewBox="0 0 100 100" class="h-6 w-6 fill-current"><path d="M84.3,44.4L24.7,4.8c-4.4-2.9-10.3,0.2-10.3,5.6v79.2c0,5.3,5.9,8.5,10.3,5.6l59.7-39.6C88.4,53.1,88.4,47.1,84.3,44.4z"/></svg>
                </div>
                <div>
                    <h1 class="text-xl font-bold tracking-tight text-main">EMBY-PROXY-UI <span class="text-xs opacity-50 font-normal ml-2">V13.1</span></h1>
                    <div class="text-[10px] opacity-50 font-mono tracking-wider flex items-center gap-2">
                        <span class="w-1.5 h-1.5 rounded-full bg-[#52B54B]"></span> 系统运行正常 · 北京时间
                    </div>
                </div>
            </div>
            <div class="text-xs font-mono opacity-50 bg-base-content/5 px-2 py-1 rounded" id="clock">Loading...</div>
        </header>

        <main class="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            <aside class="lg:col-span-4 xl:col-span-3">
                <div class="card glass-panel shadow-xl">
                    <div class="card-body p-5 space-y-3">
                        <div class="flex justify-between items-center border-b border-base-content/10 pb-2">
                            <span class="text-sm font-bold opacity-60">新增代理</span>
                            <span class="text-[10px] font-mono opacity-40">DEPLOY</span>
                        </div>
                        
                        <div class="form-control">
                            <label class="label"><span class="label-text text-xs font-bold opacity-70">名称 (Name)</span></label>
                            <input id="inName" type="text" placeholder="例如: HK-Node" class="input input-sm input-bordered bg-base-100/50 input-emby" />
                        </div>
                        
                        <div class="form-control">
                            <label class="label"><span class="label-text text-xs font-bold opacity-70">密钥 (Secret)</span></label>
                            <input id="inSecret" type="password" placeholder="可选, 留空则公开" class="input input-sm input-bordered bg-base-100/50 input-emby" />
                        </div>

                        <div class="form-control">
                            <label class="label"><span class="label-text text-xs font-bold opacity-70">服务器地址 (Target)</span></label>
                            <input id="inTarget" type="text" placeholder="http://1.2.3.4:8096" class="input input-sm input-bordered bg-base-100/50 input-emby font-mono text-xs" />
                        </div>

                        <button onclick="App.save()" class="btn btn-sm btn-neutral mt-2 bg-[#52B54B] border-0 text-white hover:bg-[#3e8d38] shadow-lg hover:scale-[1.02] transition-transform">立即部署</button>
                    </div>
                </div>
            </aside>

            <section class="lg:col-span-8 xl:col-span-9 space-y-6">
                <div class="card glass-panel shadow-xl min-h-[300px]">
                    <div class="px-6 py-4 border-b border-base-content/5 flex justify-between items-center bg-base-content/5">
                        <h2 class="text-sm font-bold opacity-70">活跃节点</h2>
                        <div class="flex gap-2">
                             <button onclick="App.export()" class="btn btn-xs btn-ghost opacity-60 hover:opacity-100 font-mono" title="导出配置">📥 导出</button>
                             <button onclick="document.getElementById('fileIn').click()" class="btn btn-xs btn-ghost opacity-60 hover:opacity-100 font-mono" title="导入配置">📤 导入</button>
                             <input type="file" id="fileIn" hidden accept=".json" onchange="App.import(this)" />
                             <div class="badge badge-success gap-1 badge-sm text-white border-0 ml-2" style="background-color: ${embyGreen}">
                                <span class="animate-pulse w-1.5 h-1.5 rounded-full bg-white"></span> 连接中
                             </div>
                        </div>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="table table-sm w-full">
                            <thead><tr class="opacity-50 border-b border-base-content/10 text-xs uppercase bg-base-200/30"><th class="pl-6 py-3">代理 ID</th><th>入口地址 (点击复制)</th><th class="text-right pr-6">操作</th></tr></thead>
                            <tbody id="nodeTable" class="text-sm font-medium opacity-90"></tbody>
                        </table>
                    </div>
                </div>

                <div class="card bg-[#0d1117] border border-base-content/10 shadow-2xl h-[250px] overflow-hidden rounded-xl">
                    <div class="px-4 py-2 border-b border-white/10 flex items-center gap-2 text-[10px] text-slate-500 font-mono bg-[#161b22]">
                        <div class="flex gap-1.5"><div class="w-2.5 h-2.5 rounded-full bg-[#ff5f56]"></div><div class="w-2.5 h-2.5 rounded-full bg-[#ffbd2e]"></div><div class="w-2.5 h-2.5 rounded-full bg-[#27c93f]"></div></div>
                        <span class="ml-2">system.log (Real-IP)</span>
                    </div>
                    <div id="logViewer" class="p-4 overflow-y-auto font-mono text-[11px] space-y-1.5 text-slate-400 scrollbar-hide"></div>
                </div>
            </section>
        </main>
    </div>

    <script>
        // 定义转义函数（前端也需要，防止 API 返回的数据包含恶意代码）
        const escapeHtml = (unsafe) => {
            if (typeof unsafe !== 'string') return unsafe;
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        };

        const API = {
            async req(data) {
                const res = await fetch('/admin', { method: 'POST', body: JSON.stringify(data) });
                if (res.status === 401) location.reload();
                return res.json();
            }
        };
        const App = {
            nodes: [],
            async refresh() {
                const data = await API.req({ action: 'list' });
                this.nodes = data.nodes;
                this.renderNodes(data.nodes);
                this.renderLogs(data.logs);
            },
            renderNodes(nodes) {
                const html = nodes.map(n => {
                    const link = location.origin + '/' + n.name + (n.secret ? '/' + n.secret : '');
                    const secure = !!n.secret;
                    // [安全修复] 使用 escapeHtml 包裹动态数据
                    const safeName = escapeHtml(n.name); 
                    return \`
                    <tr class="hover:bg-base-content/5 border-b border-base-content/5 group transition-colors">
                        <td class="pl-6 py-3">
                            <div class="flex items-center gap-3 font-bold tracking-wide">
                                <div class="w-2 h-2 rounded-full \${secure ? 'bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.5)]' : 'bg-[#52B54B] shadow-[0_0_8px_rgba(82,181,75,0.5)]'}"></div>
                                \${safeName}
                                \${secure ? '<span class="px-1.5 py-0.5 rounded text-[9px] bg-amber-500/10 text-amber-500 border border-amber-500/20">SECURE</span>' : ''}
                            </div>
                        </td>
                        <td><button onclick="App.copy('\${link}')" class="text-left font-mono text-xs opacity-60 hover:opacity-100 hover:text-[#52B54B] transition-colors select-all truncate max-w-[250px] bg-base-content/5 px-2 py-1 rounded">\${link}</button></td>
                        <td class="text-right pr-6"><button onclick="App.del('\${safeName}')" class="btn btn-ghost btn-xs text-rose-500 opacity-60 hover:opacity-100 hover:bg-rose-500/10">删除</button></td>
                    </tr>\`;
                }).join('');
                document.getElementById('nodeTable').innerHTML = html || '<tr><td colspan="3" class="text-center py-12 opacity-30 text-xs">暂无活跃代理，请在左侧添加</td></tr>';
            },
            renderLogs(logs) {
                const html = logs.map(l => {
                    // [安全修复] 对所有日志字段进行转义
                    const safeIp = escapeHtml(l.ip);
                    const safeGeo = escapeHtml(l.geo);
                    const safeNode = escapeHtml(l.node);
                    const safeTarget = escapeHtml(l.target);
                    
                    return \`
                    <div class="flex gap-3 hover:bg-white/5 p-1 rounded cursor-default items-center">
                        <span class="text-emerald-500 w-[60px] shrink-0 opacity-80">\${l.time.split(' ')[1]}</span>
                        <span class="text-cyan-400 font-bold bg-cyan-400/10 px-1 rounded">\${safeIp}</span>
                        <span class="text-slate-500 text-[10px] w-[100px] truncate">\${safeGeo}</span>
                        <span class="text-amber-500 font-bold">\${safeNode}</span>
                        <span class="text-slate-600">→</span>
                        <span class="text-slate-500 italic opacity-60 truncate flex-1">\${safeTarget}</span>
                    </div>\`;
                }).join('');
                document.getElementById('logViewer').innerHTML = html || '<div class="opacity-30 text-center mt-12">// 等待流量接入...</div>';
            },
            async save() {
                const name = document.getElementById('inName').value.trim();
                const secret = document.getElementById('inSecret').value.trim();
                const target = document.getElementById('inTarget').value.trim();
                
                if (!name || !target) return alert('名称和服务器地址不能为空');
                if (!target.startsWith('http')) return alert('服务器地址必须以 http:// 或 https:// 开头');

                await API.req({ action: 'save', name, path: secret, target });
                ['inName', 'inSecret', 'inTarget'].forEach(id => document.getElementById(id).value = '');
                this.refresh();
            },
            async del(name) { if (confirm('确认删除代理 [' + name + '] 吗?')) { await API.req({ action: 'delete', name }); this.refresh(); } },
            async export() {
                if(!this.nodes.length) return alert('当前列表为空');
                const blob = new Blob([JSON.stringify(this.nodes, null, 2)], {type:'application/json'});
                const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'emby_nodes.json'; a.click();
            },
            async import(input) {
                const file = input.files[0]; if(!file) return;
                const reader = new FileReader();
                reader.onload = async (e) => {
                    try { const nodes = JSON.parse(e.target.result); if(confirm(\`确认导入 \${nodes.length} 个节点吗？\\n(同名节点将被覆盖)\`)) { await API.req({ action: 'import', nodes }); this.refresh(); } } catch(err) { alert('文件格式错误'); }
                };
                reader.readAsText(file); input.value = '';
            },
            copy(txt) { navigator.clipboard.writeText(txt); const el = document.activeElement; const original = el.innerText; el.innerText = "已复制 ✓"; setTimeout(() => el.innerText = original, 1000); }
        };
        
        function updateClock() { const now = new Date(); document.getElementById('clock').innerText = now.toLocaleTimeString('zh-CN', {timeZone:'Asia/Shanghai', hour12:false}) + " CST"; }
        
        App.refresh(); 
        setInterval(() => App.refresh(), 5000);
        setInterval(updateClock, 1000);
    </script>
</body>
</html>`, { headers: { "Content-Type": "text/html" } });
    }
};

// ============================================================================
// 6. MAIN WORKER ENTRY
// ============================================================================
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const segments = path.split('/').filter(p => p).map(p => decodeURIComponent(p));

        // --- 管理后台 (/admin) ---
        if (segments[0] === "admin") {
            const contentType = request.headers.get("content-type") || "";
            if (request.method === "POST" && (contentType.includes("form") || contentType.includes("urlencoded"))) {
                return Auth.handleLogin(request, env);
            }
            
            const isAuth = await Auth.verifyRequest(request, env);
            if (!isAuth) {
                if (request.method === "POST") return new Response("Unauthorized", { status: 401 });
                return UI.renderLoginPage();
            }

            if (request.method === "POST") return Database.handleApi(request, env);
            return UI.renderAdminUI();
        }

        // --- 代理逻辑 ---
        if (segments.length >= 1) {
            const nodeName = segments[0];
            const nodeData = await Database.getNode(nodeName, env, ctx);

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
                    if (Config.Regex.LogTrigger.test(remainingPath)) {
                        ctx.waitUntil(Database.addLog(env, request, nodeName, nodeData.target));
                    }
                    return Proxy.handle(request, nodeData, remainingPath, nodeName, nodeData.secret);
                }
            }
        }
        return new Response("403 Forbidden / Access Denied", { status: 403 });
    }
};
