// EMBY-PROXY-ULTIMATE V17.2 (BugFix)
// [V17.2] 紧急修复: 前端 escapeHtml 报错
// [V17.1] 修复: 列表空白 (增加KV读取容错)
// [V17] 特性: 动态代理计算 | 旧数据兼容 | 极速缓存

// ============================================================================
// 0. GLOBAL CONFIG & STATE
// ============================================================================
const GLOBALS = {
    NodeCache: new Map(),
    ConfigCache: null, 
    Regex: {
        Static: /\.(?:jpg|jpeg|gif|png|svg|ico|webp|js|css|woff2?|ttf|otf|map|webmanifest|json)$/i,
        Streaming: /\.(?:mp4|m4v|m4s|m4a|ogv|webm|mkv|mov|avi|wmv|flv|ts|m3u8|mpd)$/i
    },
    isDaytimeCN: () => {
        const h = (new Date().getUTCHours() + 8) % 24;
        return h >= 6 && h < 18;
    }
};

const Config = {
    Defaults: {
        JwtExpiry: 60 * 60 * 24 * 7,
        LoginLockDuration: 900,
        MaxLoginAttempts: 5,
        CacheTTL: 60000
    }
};

// ============================================================================
// 1. AUTH MODULE
// ============================================================================
const Auth = {
    // 辅助：获取 KV (兼容 ENI_KV 和其他常见命名)
    getKV(env) {
        return env.ENI_KV || env.KV || env.EMBY_KV || env.EMBY_PROXY;
    },

    async handleLogin(request, env) {
        const ip = request.headers.get("cf-connecting-ip") || "unknown";
        const kv = this.getKV(env);

        try {
            const formData = await request.formData();
            const password = (formData.get("password") || "").trim();
            const secret = env.JWT_SECRET || env.ADMIN_PASS;

            if (password === env.ADMIN_PASS) {
                if (kv) kv.delete(`fail:${ip}`).catch(() => { });
                const jwt = await this.generateJwt(secret, Config.Defaults.JwtExpiry);
                return new Response("Login Success", {
                    status: 302,
                    headers: {
                        "Location": "/admin",
                        "Set-Cookie": `auth_token=${jwt}; Path=/; Max-Age=${Config.Defaults.JwtExpiry}; HttpOnly; Secure; SameSite=Strict`
                    }
                });
            }

            let count = 0;
            if (kv) {
                const failKey = `fail:${ip}`;
                const prev = await kv.get(failKey);
                count = prev ? parseInt(prev) + 1 : 1;
                if (count <= Config.Defaults.MaxLoginAttempts) {
                    kv.put(failKey, count.toString(), { expirationTtl: Config.Defaults.LoginLockDuration }).catch(() => { });
                }
            }
            if (count >= Config.Defaults.MaxLoginAttempts) return UI.renderLockedPage(ip);
            return UI.renderLoginPage(`密码错误 (剩余次数: ${Config.Defaults.MaxLoginAttempts - count})`);
        } catch (e) { return UI.renderLoginPage("请求无效"); }
    },

    async verifyRequest(request, env) {
        const cookie = request.headers.get("Cookie");
        if (!cookie) return false;
        const match = cookie.match(/auth_token=([^;]+)/);
        const token = match ? match[1] : null;
        if (!token) return false;
        return await this.verifyJwt(token, env.JWT_SECRET || env.ADMIN_PASS);
    },

    async generateJwt(secret, expiresIn) {
        const header = { alg: "HS256", typ: "JWT" };
        const payload = { sub: "admin", exp: Math.floor(Date.now() / 1000) + expiresIn };
        const encHeader = this.base64UrlEncode(JSON.stringify(header));
        const encPayload = this.base64UrlEncode(JSON.stringify(payload));
        const signature = await this.sign(secret, `${encHeader}.${encPayload}`);
        return `${encHeader}.${encPayload}.${signature}`;
    },

    async verifyJwt(token, secret) {
        const parts = token.split('.');
        if (parts.length !== 3) return false;
        const [h, p, s] = parts;
        const expected = await this.sign(secret, `${h}.${p}`);
        if (s !== expected) return false;
        try {
            const payload = JSON.parse(this.base64UrlDecode(p));
            return payload.exp > Math.floor(Date.now() / 1000);
        } catch (e) { return false; }
    },

    base64UrlEncode(str) { return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
    base64UrlDecode(str) { return atob(str.replace(/-/g, '+').replace(/_/g, '/')); },

    async sign(secret, data) {
        const enc = new TextEncoder();
        const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const signature = await crypto.subtle.sign("HMAC", key, enc.encode(data));
        return this.base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
    }
};

// ============================================================================
// 2. DATABASE MODULE (Enhanced Robustness)
// ============================================================================
const Database = {
    PREFIX: "node:",
    CONFIG_KEY: "sys:theme",

    getKV(env) {
        return Auth.getKV(env);
    },

    async getNode(nodeName, env, ctx) {
        const kv = this.getKV(env);
        if (!kv) return null;

        const now = Date.now();
        const mem = GLOBALS.NodeCache.get(nodeName);
        if (mem && mem.exp > now) return mem.data;

        const cache = caches.default;
        const cacheUrl = new URL(`https://internal-config-cache/node/${nodeName}`);
        let response = await cache.match(cacheUrl);
        if (response) {
            const data = await response.json();
            GLOBALS.NodeCache.set(nodeName, { data, exp: now + Config.Defaults.CacheTTL });
            return data;
        }

        try {
            const nodeData = await kv.get(`${this.PREFIX}${nodeName}`, { type: "json" });
            if (nodeData) {
                const jsonStr = JSON.stringify(nodeData);
                const cacheResp = new Response(jsonStr, {
                    headers: { "Cache-Control": "public, max-age=60, stale-while-revalidate=600" }
                });
                ctx.waitUntil(cache.put(cacheUrl, cacheResp));
                GLOBALS.NodeCache.set(nodeName, { data: nodeData, exp: now + Config.Defaults.CacheTTL });
                return nodeData;
            }
        } catch (err) { console.error(`KV Error: ${err}`); }
        return null;
    },

    async handleApi(request, env) {
        const kv = this.getKV(env);
        if (!kv) return new Response(JSON.stringify({ error: "严重错误: 无法连接数据库(KV)。请检查Cloudflare后台变量绑定是否为 ENI_KV" }), { status: 500 });
        
        const data = await request.json();
        const cache = caches.default;

        const invalidate = async (name) => {
            GLOBALS.NodeCache.delete(name);
            await cache.delete(`https://internal-config-cache/node/${name}`);
        };

        switch (data.action) {
            case "loadConfig":
                let config = GLOBALS.ConfigCache;
                if (!config) {
                    config = await kv.get(this.CONFIG_KEY, { type: "json" }) || {};
                    GLOBALS.ConfigCache = config;
                }
                return new Response(JSON.stringify(config));
            
            case "saveConfig":
                if (data.config) {
                    if (data.config.bgImage && data.config.bgImage.startsWith('data:')) {
                        if (!data.config.bgImage.startsWith('data:image/')) {
                            return new Response(JSON.stringify({ error: "Invalid File Type" }), { status: 400 });
                        }
                    }
                    await kv.put(this.CONFIG_KEY, JSON.stringify(data.config));
                    GLOBALS.ConfigCache = data.config;
                }
                return new Response(JSON.stringify({ success: true }));

            case "save":
            case "import":
                const nodesToSave = data.action === "save" ? [data] : data.nodes;
                for (const n of nodesToSave) {
                    if (n.name && n.target) {
                        const val = {
                            secret: n.secret || n.path || "",
                            target: n.target,
                            tag: n.tag || "" 
                        };
                        await kv.put(`${this.PREFIX}${n.name}`, JSON.stringify(val));
                        await invalidate(n.name);
                    }
                }
                return new Response(JSON.stringify({ success: true }));

            case "delete":
                if (data.name) {
                    await kv.delete(`${this.PREFIX}${data.name}`);
                    await invalidate(data.name);
                }
                return new Response(JSON.stringify({ success: true }));

            case "batchDelete":
                if (Array.isArray(data.names)) {
                    for (const name of data.names) {
                        await kv.delete(`${this.PREFIX}${name}`);
                        await invalidate(name);
                    }
                }
                return new Response(JSON.stringify({ success: true }));

            case "list":
                try {
                    const list = await kv.list({ prefix: this.PREFIX });
                    const nodesList = await Promise.all(list.keys.map(async (key) => {
                        try {
                            const name = key.name.replace(this.PREFIX, "");
                            let val = GLOBALS.NodeCache.get(name)?.data;
                            if (!val) val = await kv.get(key.name, { type: "json" });
                            return val ? { name, ...val } : null;
                        } catch (e) {
                            console.error(`Error reading key ${key.name}:`, e);
                            return null;
                        }
                    }));
                    return new Response(JSON.stringify({ nodes: nodesList.filter(n => n) }));
                } catch (e) {
                    return new Response(JSON.stringify({ error: `读取列表失败: ${e.message}` }), { status: 500 });
                }

            default: return new Response("Invalid Action", { status: 400 });
        }
    }
};

// ============================================================================
// 3. PROXY MODULE
// ============================================================================
const Proxy = {
    async handle(request, node, path, name, key) {
        const targetBase = new URL(node.target);
        const finalUrl = new URL(path, targetBase);
        finalUrl.search = new URL(request.url).search;

        if (request.headers.get("Upgrade") === "websocket") {
            return this.handleWebSocket(finalUrl, request);
        }

        if (request.method === "OPTIONS") return this.renderCors();

        const isStreaming = GLOBALS.Regex.Streaming.test(path);
        const newHeaders = new Headers(request.headers);
        newHeaders.set("Host", targetBase.host);
        newHeaders.set("X-Real-IP", request.headers.get("cf-connecting-ip"));
        newHeaders.set("X-Forwarded-For", request.headers.get("cf-connecting-ip"));
        ["cf-connecting-ip", "cf-ipcountry", "cf-ray", "cf-visitor", "cf-worker"].forEach(h => newHeaders.delete(h));
        if (isStreaming) newHeaders.delete("Referer");

        const cf = isStreaming
            ? { cacheEverything: false, cacheTtl: 0 }
            : { cacheEverything: true, cacheTtlByStatus: { "200-299": 86400 } };

        try {
            const response = await fetch(finalUrl.toString(), {
                method: request.method,
                headers: newHeaders,
                body: request.body,
                redirect: "manual",
                cf
            });

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

    handleWebSocket(url, request) {
        try {
            const protocols = request.headers.get("Sec-WebSocket-Protocol") || "emby-websocket";
            const wsTarget = new URL(url);
            wsTarget.protocol = wsTarget.protocol === 'https:' ? 'wss:' : 'ws:';
            const { 0: client, 1: server } = new WebSocketPair();
            const ws = new WebSocket(wsTarget.toString(), protocols);
            server.accept();
            ws.addEventListener('message', e => { try { server.send(e.data) } catch { } });
            server.addEventListener('message', e => { try { ws.send(e.data) } catch { } });
            const close = () => {
                try { server.close() } catch { }
                try { ws.close() } catch { }
            };
            ws.addEventListener('close', close);
            server.addEventListener('close', close);
            ws.addEventListener('error', close);
            server.addEventListener('error', close);
            return new Response(null, {
                status: 101,
                webSocket: client,
                headers: { "Sec-WebSocket-Protocol": protocols }
            });
        } catch (e) {
            return new Response("WS Error", { status: 502 });
        }
    },

    rewriteLocation(headers, status, name, key, targetBase) {
        if (status < 300 || status >= 400) return;
        const location = headers.get("Location");
        if (!location) return;
        const prefix = key ? `/${name}/${key}` : `/${name}`;
        if (location.startsWith("/")) {
            headers.set("Location", `${prefix}${location}`);
        } else {
            try {
                const locUrl = new URL(location);
                if (locUrl.host === targetBase.host) {
                    headers.set("Location", `${prefix}${locUrl.pathname}${locUrl.search}`);
                }
            } catch (e) { }
        }
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
// 4. UI MODULE (V17.2 Fixed)
// ============================================================================
const UI = {
    getHead(title) {
        const isLight = GLOBALS.isDaytimeCN();
        return `<!DOCTYPE html><html class="${isLight ? 'light' : ''}"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>:root{--bg:#111;--p:rgba(34,34,34,var(--bg-op,1));--b:rgba(51,51,51,var(--bg-op,1));--t:#eee;--ts:#888;--a:#22c55e;--ah:#16a34a;--e:#ef4444;--blue:#3b82f6;--blur:0px;--mask:rgba(0,0,0,0);--shadow:none;--radius:8px}html.light{--bg:#f5f5f5;--p:rgba(255,255,255,var(--bg-op,1));--b:rgba(224,224,224,var(--bg-op,1));--t:#333;--ts:#666;--a:#16a34a;--ah:#15803d}html.text-dark{--t:#111 !important;--ts:#444 !important}html.text-light{--t:#fff !important;--ts:#ccc !important}body{background:var(--bg);color:var(--t);font-family:system-ui,-apple-system,sans-serif;margin:0;display:flex;flex-direction:column;min-height:100vh;text-shadow:var(--shadow)}body::before{content:'';position:fixed;top:0;left:0;width:100%;height:100%;background:var(--mask);pointer-events:none;z-index:-1}input,button,textarea,select{transition:all .3s}.panel{background:var(--p);border:1px solid var(--b);border-radius:var(--radius);backdrop-filter:blur(var(--blur));-webkit-backdrop-filter:blur(var(--blur))}.btn{cursor:pointer;border:none;border-radius:var(--radius);font-weight:700}.btn-p{background:var(--a);color:#fff}.btn-p:hover{filter:brightness(1.1)}.btn-icon{cursor:pointer;border:none;padding:5px;background:transparent;color:var(--ts)}.btn-icon:hover{color:var(--t)}.lang-btn{cursor:pointer;padding:5px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:var(--t)}.lang-btn:hover{background:var(--b)}.gh-icon{color:var(--ts);transition:color .3s}.gh-icon:hover{color:var(--t)}.tag-badge{font-size:10px;padding:2px 6px;border-radius:var(--radius);font-weight:bold;margin-left:6px;display:inline-block}.tag-blue{background:rgba(59,130,246,0.2);color:var(--blue)}.tag-sec{background:rgba(239,68,68,0.2);color:var(--e)}.scroll-area{flex:1;min-height:0;overflow-y:auto;scrollbar-width:thin}.scroll-area::-webkit-scrollbar{width:6px}.scroll-area::-webkit-scrollbar-thumb{background:var(--b);border-radius:3px}input[type=checkbox]:not(.toggle-input){accent-color:var(--a);cursor:pointer;width:16px;height:16px}tr.selected{background:rgba(var(--a-rgb, 34,197,94), 0.1)}.settings-btn{position:fixed;bottom:20px;left:20px;background:var(--p);border:1px solid var(--b);color:var(--t);border-radius:50%;width:40px;height:40px;display:flex;align-items:center;justify-content:center;cursor:pointer;box-shadow:0 2px 10px rgba(0,0,0,0.2);z-index:100}.settings-modal{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--p);border:1px solid var(--b);border-radius:var(--radius);padding:20px;width:90%;max-width:400px;z-index:101;box-shadow:0 10px 30px rgba(0,0,0,0.5);display:none;max-height:85vh;overflow-y:auto}.settings-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:100;display:none}.s-group{margin-bottom:15px}.s-label{display:block;margin-bottom:5px;font-size:12px;color:var(--ts)}input[type=range]{-webkit-appearance:none;width:100%;background:transparent}input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;height:16px;width:16px;border-radius:50%;background:var(--a);cursor:pointer;margin-top:-6px;box-shadow:0 1px 3px rgba(0,0,0,0.3)}input[type=range]::-webkit-slider-runnable-track{width:100%;height:4px;cursor:pointer;background:var(--b);border-radius:2px}select, input[type=text], input[type=password]{width:100%;padding:8px;background:rgba(255,255,255,0.05);border:1px solid var(--b);color:var(--t);border-radius:var(--radius)}hr{border:0;border-top:1px solid var(--b);margin:15px 0}.switch-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;padding:5px 0}.switch{position:relative;display:inline-block;width:36px;height:20px}.switch input{opacity:0;width:0;height:0}.slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background-color:var(--b);transition:.4s;border-radius:20px}.slider:before{position:absolute;content:"";height:14px;width:14px;left:3px;bottom:3px;background-color:#fff;transition:.4s;border-radius:50%}input:checked+.slider{background-color:var(--a)}input:checked+.slider:before{transform:translateX(16px)}.s-section{display:none;padding:12px;background:rgba(0,0,0,0.03);border-radius:var(--radius);margin-bottom:15px;border:1px solid var(--b)}.s-section.active{display:block}.color-picker-wrapper{display:flex;align-items:center;gap:10px}input[type=color]{-webkit-appearance:none;border:none;width:30px;height:30px;padding:0;overflow:hidden;border-radius:50%;cursor:pointer;background:none}input[type=color]::-webkit-color-swatch-wrapper{padding:0}input[type=color]::-webkit-color-swatch{border:1px solid var(--b);border-radius:50%}</style></head>`;
    },

    escapeHtml(unsafe) {
        if (!unsafe) return "";
        return String(unsafe).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    },

    renderSmartError(request, msg, nodeName) {
        if (request.headers.get("Accept")?.includes("text/html")) {
            return new Response(`${this.getHead("Error")}<body><div style="display:flex;justify-content:center;align-items:center;height:100vh"><div class="panel" style="padding:40px;text-align:center"><h2>连接失败</h2><p>节点: <strong>${this.escapeHtml(nodeName)}</strong></p><p style="color:var(--e);font-family:monospace;background:var(--bg);padding:10px;border-radius:4px">${this.escapeHtml(msg)}</p><button onclick="location.reload()" class="btn btn-p" style="padding:10px 24px">重试</button></div></div></body></html>`, { status: 502, headers: { "Content-Type": "text/html;charset=utf-8" } });
        }
        return new Response(JSON.stringify({ error: msg, node: nodeName }), { status: 502, headers: { "Content-Type": "application/json" } });
    },

    renderLoginPage(error = "") {
        return new Response(`${this.getHead("Login")}<body><div style="display:flex;justify-content:center;align-items:center;height:100vh"><div class="panel" style="padding:30px;width:300px"><h3>Emby Proxy Admin</h3><form method="POST"><input type="password" name="password" placeholder="Password" style="width:100%;padding:10px;margin-bottom:15px;box-sizing:border-box" required>${error ? `<div style="color:var(--e);font-size:12px;margin-bottom:10px;text-align:center">${this.escapeHtml(error)}</div>` : ''}<button class="btn btn-p" style="width:100%;padding:10px">登 录</button></form></div></div></body></html>`, { headers: { "Content-Type": "text/html" } });
    },

    renderLockedPage(ip) {
        return new Response(`${this.getHead("Locked")}<body><div style="display:flex;justify-content:center;align-items:center;height:100vh;text-align:center"><div><h1 style="color:var(--e)">IP 已锁定</h1><p>IP: ${this.escapeHtml(ip)}</p><p>尝试次数过多，请 15 分钟后再试。</p></div></div></body></html>`, { status: 429, headers: { "Content-Type": "text/html" } });
    },

    renderAdminUI() {
        const icons = {
            eye: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`,
            eyeOff: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`,
            trash: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>`,
            copy: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`,
            lock: `<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`,
            gear: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>`
        };

        const html = `
${this.getHead("Admin")}
<body style="padding:20px;max-width:1100px;margin:0 auto;width:100%;box-sizing:border-box">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;padding-bottom:15px;border-bottom:1px solid var(--b)">
        <h2 style="margin:0">Emby Proxy <span style="font-size:12px;color:var(--ts);font-weight:normal">V17.2</span></h2>
        <div style="display:flex;align-items:center;gap:15px">
             <div id="clk" style="font-family:monospace;font-size:12px;color:var(--ts)"></div>
             <div class="lang-btn" onclick="App.toggleLang()" title="Switch Language">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1 4-10z"></path></svg>
             </div>
        </div>
    </div>
    
    <div style="display:grid;grid-template-columns:1fr 2.5fr;gap:20px;flex:1;min-height:0" class="grid-box">
        <style>@media(max-width:768px){.grid-box{grid-template-columns:1fr !important}}</style>
        
        <div class="panel" style="padding:20px;height:fit-content">
            <h3 style="margin-top:0" id="t-new">New Node</h3>
            
            <div style="margin-bottom:10px">
                <label style="display:block;font-size:12px;color:var(--ts);margin-bottom:4px" id="l-name">Name</label>
                <input id="inName" style="width:100%">
            </div>
            
            <div style="margin-bottom:10px">
                <label style="display:block;font-size:12px;color:var(--ts);margin-bottom:4px" id="l-tag">Tag</label>
                <input id="inTag" style="width:100%">
            </div>
            
            <div style="margin-bottom:10px">
                <label style="display:block;font-size:12px;color:var(--ts);margin-bottom:4px" id="l-target">Target</label>
                <input id="inTarget" style="width:100%">
            </div>
            
            <div style="margin-bottom:15px">
                <label style="display:block;font-size:12px;color:var(--ts);margin-bottom:4px" id="l-sec">Secret Path</label>
                <input id="inSec" style="width:100%">
            </div>

            <button class="btn btn-p" onclick="App.save()" style="width:100%;padding:8px" id="t-deploy">Deploy</button>
        </div>

        <div class="panel" style="padding:20px;display:flex;flex-direction:column;min-height:0">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:10px">
                <div style="display:flex;align-items:center;gap:10px;flex:1">
                    <h3 style="margin:0;white-space:nowrap" id="t-nodes">Nodes</h3>
                    <input id="inSearch" oninput="App.filter(this.value)" placeholder="Search Name or Tag..." style="padding:5px 10px;background:var(--bg);border:1px solid var(--b);color:var(--t);border-radius:15px;font-size:12px;width:100%;max-width:200px">
                </div>
                <div style="display:flex;align-items:center;gap:5px">
                    <button onclick="App.toggleAllTargets()" class="btn btn-icon" id="btn-eye-all" title="Toggle All Targets">${icons.eye}</button>
                    <div style="width:1px;height:20px;background:var(--b);margin:0 5px"></div>
                    <button onclick="App.export()" class="btn" style="background:var(--b);color:var(--t);padding:4px 8px;font-size:12px" id="t-export">Export</button>
                    <button onclick="document.getElementById('fIn').click()" class="btn" style="background:var(--b);color:var(--t);padding:4px 8px;font-size:12px" id="t-import">Import</button>
                    <input type="file" id="fIn" hidden accept=".json" onchange="App.import(this)">
                </div>
            </div>

            <div id="batch-bar" style="display:none;align-items:center;gap:10px;background:var(--bg);padding:8px;border-radius:4px;margin-bottom:10px;border:1px dashed var(--b)">
                <span style="font-size:12px;color:var(--ts)" id="t-selected">Selected: 0</span>
                <button onclick="App.batchDelete()" class="btn" style="color:var(--e);font-size:12px;padding:2px 8px;border:1px solid var(--e);background:transparent" id="t-batchDel">Delete Selected</button>
                <button onclick="App.batchTag()" class="btn" style="color:var(--blue);font-size:12px;padding:2px 8px;border:1px solid var(--blue);background:transparent" id="t-batchTag">Set Tag</button>
            </div>

            <div class="scroll-area">
                <table style="width:100%;border-collapse:collapse;font-size:13px">
                    <thead style="position:sticky;top:0;background:var(--p);z-index:10;box-shadow:0 1px 0 var(--b)">
                        <tr>
                            <th style="text-align:left;padding:10px;border-bottom:1px solid var(--b);width:30px">
                                <input type="checkbox" onchange="App.toggleSelectAll(this)">
                            </th>
                            <th style="text-align:left;padding:10px;border-bottom:1px solid var(--b)" id="th-name">Name</th>
                            <th style="text-align:left;padding:10px;border-bottom:1px solid var(--b)" id="th-target">Target</th>
                            <th style="text-align:left;padding:10px;border-bottom:1px solid var(--b)" id="th-proxy">Proxy</th>
                            <th style="text-align:right;padding:10px;border-bottom:1px solid var(--b)" id="th-action">Action</th>
                        </tr>
                    </thead>
                    <tbody id="list"></tbody>
                </table>
            </div>
        </div>
    </div>
    
    <div class="settings-btn" onclick="App.toggleSettings()">${icons.gear}</div>
    <div class="settings-overlay" onclick="App.toggleSettings()"></div>
    <div class="settings-modal">
        <h3 style="margin-top:0">Personalization / 个性化</h3>
        
        <div class="s-group">
            <label class="s-label">Theme Preset / 预设主题</label>
            <select id="s-preset" onchange="App.applyPreset(this.value)">
                <option value="custom">Custom / 自定义</option>
                <option value="white">Minimal White / 极简白</option>
                <option value="black">Pure Black / 纯粹黑</option>
                <option value="ocean">Ocean Blue / 海洋蓝</option>
                <option value="purple">Neon Purple / 霓虹紫</option>
                <option value="orange">Sunset Gold / 落日金</option>
            </select>
        </div>
        
        <div class="switch-row">
            <span class="s-label" style="margin:0">Background Image / 背景图片 <span style="font-weight:normal;color:var(--e)">(Required for Blur)</span></span>
            <label class="switch"><input type="checkbox" id="sw-bg" onchange="App.toggleSection('bg')"><span class="slider"></span></label>
        </div>
        <div id="sec-bg" class="s-section">
            <input id="s-bg-url" placeholder="Image URL (https://...)" style="margin-bottom:5px" oninput="App.previewStyle()">
            <div style="display:flex;gap:10px">
                 <input type="file" id="s-bg-file" accept="image/*" style="font-size:12px;color:var(--ts);flex:1">
                 <button onclick="App.clearBackground()" class="btn" style="background:#ef4444;color:#fff;padding:4px 8px;font-size:12px;border-radius:4px">Clear</button>
            </div>
        </div>

        <div class="switch-row">
            <span class="s-label" style="margin:0">UI Style / 界面风格</span>
            <label class="switch"><input type="checkbox" id="sw-ui" onchange="App.toggleSection('ui')"><span class="slider"></span></label>
        </div>
        <div id="sec-ui" class="s-section">
            <div class="s-group color-picker-wrapper">
                <label class="s-label" style="margin:0;flex:1">Accent Color / 主题色</label>
                <input type="color" id="s-accent" value="#22c55e" oninput="App.previewStyle()">
            </div>
            <div class="s-group" style="margin-bottom:0">
                <label class="s-label">Border Radius / 圆角: <span id="s-radius-val">8px</span></label>
                <input type="range" id="s-radius" min="0" max="20" step="1" value="8" oninput="App.previewStyle()">
            </div>
        </div>

        <div class="switch-row">
            <span class="s-label" style="margin:0">Glass Effect / 毛玻璃特效</span>
            <label class="switch"><input type="checkbox" id="sw-glass" onchange="App.toggleSection('glass')"><span class="slider"></span></label>
        </div>
        <div id="sec-glass" class="s-section">
            <div class="s-group">
                <label class="s-label">Opacity / 透明度: <span id="s-opacity-val">0.9</span></label>
                <input type="range" id="s-opacity" min="0.1" max="1" step="0.05" value="0.9" oninput="App.previewStyle()">
            </div>
            <div class="s-group" style="margin-bottom:0">
                <label class="s-label">Blur Radius / 模糊程度: <span id="s-blur-val">0px</span></label>
                <input type="range" id="s-blur" min="0" max="20" step="1" value="0" oninput="App.previewStyle()">
            </div>
        </div>
        
        <div class="switch-row">
            <span class="s-label" style="margin:0">Background Mask / 背景遮罩</span>
            <label class="switch"><input type="checkbox" id="sw-mask" onchange="App.toggleSection('mask')"><span class="slider"></span></label>
        </div>
        <div id="sec-mask" class="s-section">
            <div class="s-group" style="margin-bottom:0">
                <label class="s-label">Darken or Lighten: <span id="s-mask-val">0</span></label>
                <input type="range" id="s-mask" min="-0.8" max="0.8" step="0.1" value="0" oninput="App.previewStyle()">
                <div style="font-size:10px;color:var(--ts);display:flex;justify-content:space-between"><span>Black</span><span>None</span><span>White</span></div>
            </div>
        </div>

        <div class="switch-row">
            <span class="s-label" style="margin:0">Theme & Custom CSS / 主题与样式</span>
            <label class="switch"><input type="checkbox" id="sw-text" onchange="App.toggleSection('text')"><span class="slider"></span></label>
        </div>
        <div id="sec-text" class="s-section">
            <div class="s-group">
                <label class="s-label">Theme Mode / 主题模式</label>
                <select id="s-theme-mode" onchange="App.previewStyle()">
                    <option value="auto">Auto</option>
                    <option value="light">Light / 浅色</option>
                    <option value="dark">Dark / 深色</option>
                </select>
            </div>
            <div class="s-group" style="margin-bottom:0">
                <label class="s-label">Custom CSS</label>
                <textarea id="s-css" placeholder="body { ... }" rows="3" style="width:100%;padding:8px;font-family:monospace;margin-top:5px" oninput="App.previewStyle()"></textarea>
            </div>
        </div>

        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:20px;border-top:1px solid var(--b);padding-top:15px">
            <button onclick="App.resetAppearance()" class="btn" style="background:transparent;color:var(--ts);font-size:12px;border:1px dashed var(--ts)">Default / 恢复</button>
            <button onclick="App.saveSettings()" class="btn btn-p" style="padding:8px 24px">Save</button>
        </div>
    </div>

    <div style="margin-top:20px;padding:20px;text-align:center;border-top:1px solid var(--b)">
        <a href="https://github.com/axuitomo/CF-EMBY-PROXY-UI" target="_blank" title="GitHub Repository" style="display:inline-block">
            <svg class="gh-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
        </a>
    </div>

    <script>
        const $=(s)=>document.querySelector(s);
        const API={req:async(d)=>{const r=await fetch('/admin',{method:'POST',body:JSON.stringify(d)});if(r.status===401)location.reload();return r.json()}};
        const Icons = {
            eye: '${icons.eye}', eyeOff: '${icons.eyeOff}', trash: '${icons.trash}', copy: '${icons.copy}', lock: '${icons.lock}'
        };

        const PRESETS = {
            white: { color: '#000000', bg: '', radius: 8, mode: 'light' },
            black: { color: '#ffffff', bg: '', radius: 8, mode: 'dark' },
            ocean: { color: '#06b6d4', bg: 'https://images.unsplash.com/photo-1507525428034-b723cf961d3e?auto=format&fit=crop&w=1920&q=80', radius: 12, mode: 'light' },
            purple: { color: '#d946ef', bg: 'https://images.unsplash.com/photo-1563089145-599997674d42?auto=format&fit=crop&w=1920&q=80', radius: 4, mode: 'dark' },
            orange: { color: '#f59e0b', bg: 'https://images.unsplash.com/photo-1470252649378-9c29740c9fa8?auto=format&fit=crop&w=1920&q=80', radius: 20, mode: 'dark' }
        };

        const TEXTS = {
            'en': {
                new: "New Node", namePh: "e.g. HK", targetPh: "http://1.2.3.4:8096",
                tagPh: "e.g. VIP", secPh: "Optional", deploy: "Deploy", nodes: "Nodes",
                export: "Export", import: "Import", noNodes: "No nodes", copy: "Copied!", copied: "Copied!", del: "Del",
                search: "Search Name or Tag...", batchDel: "Delete Selected", batchTag: "Set Tag", selected: "Selected: ",
                thName: "Name", thTarget: "Target", thProxy: "Proxy", thAction: "Action", inputTag: "Enter Tag Name:",
                lName: "Name", lTag: "Tag", lTarget: "Target Address", lSec: "Secret Path"
            },
            'zh-Hans': {
                new: "新建节点", namePh: "例如 HK", targetPh: "http://1.2.3.4:8096",
                tagPh: "例如 VIP", secPh: "可选", deploy: "部署", nodes: "节点列表",
                export: "导出配置", import: "导入配置", noNodes: "暂无节点", copy: "已复制!", copied: "已复制!", del: "删除",
                search: "搜索名称或标签...", batchDel: "批量删除", batchTag: "批量设置标签", selected: "已选: ",
                thName: "名称", thTarget: "目标", thProxy: "代理地址", thAction: "操作", inputTag: "输入标签名称:",
                lName: "名称", lTag: "标签", lTarget: "目标地址", lSec: "私密路径"
            },
            'zh-Hant': {
                new: "新建節點", namePh: "例如 HK", targetPh: "http://1.2.3.4:8096",
                tagPh: "例如 VIP", secPh: "可選", deploy: "部署", nodes: "節點列表",
                export: "導出配置", import: "導入配置", noNodes: "暫無節點", copy: "已複製!", copied: "已複製!", del: "刪除",
                search: "搜索名稱或標籤...", batchDel: "批量刪除", batchTag: "批量設置標籤", selected: "已選: ",
                thName: "名稱", thTarget: "目標", thProxy: "代理地址", thAction: "操作", inputTag: "輸入標籤名稱:",
                lName: "名稱", lTag: "標籤", lTarget: "目標地址", lSec: "私密路徑"
            }
        };

        const App={
            nodes:[],
            config: {},
            lang: 'en',
            showAllTargets: false,
            selected: new Set(),
            filterText: '',
            visibleMap: new Set(), 

            async init(){
                const nav = navigator.language.toLowerCase();
                if (nav.includes('tw') || nav.includes('hk')) this.lang = 'zh-Hant';
                else if (nav.includes('zh')) this.lang = 'zh-Hans';
                else this.lang = 'en';

                this.updateTexts();
                
                const cfg = await API.req({action:'loadConfig'});
                if(cfg) {
                    this.config = cfg;
                    this.applyConfig(this.config);
                }

                await this.refresh();
                setInterval(()=>$('#clk').innerText=new Date().toLocaleTimeString('zh-CN',{timeZone:'Asia/Shanghai'}),1000);
            },
            
            toggleSettings() {
                const d = $('.settings-modal').style.display;
                const show = d === 'block' ? 'none' : 'block';
                $('.settings-modal').style.display = show;
                $('.settings-overlay').style.display = show;
                
                if(show === 'block') {
                    const c = this.config;
                    
                    const hasBg = !!(c.bgUrl || c.bgImage);
                    const hasGlass = (c.panelOpacity !== undefined && c.panelOpacity < 1) || (c.panelBlur !== undefined && c.panelBlur > 0);
                    const hasMask = (c.bgMask !== undefined && c.bgMask !== 0);
                    const hasText = !!(c.customCss || (c.themeMode && c.themeMode !== 'auto'));
                    const hasUi = !!(c.accentColor || c.borderRadius !== undefined);

                    $('#sw-bg').checked = hasBg;
                    $('#sw-glass').checked = hasGlass;
                    $('#sw-mask').checked = hasMask;
                    $('#sw-text').checked = hasText;
                    $('#sw-ui').checked = hasUi;

                    $('#s-bg-url').value = c.bgUrl || '';
                    $('#s-css').value = c.customCss || '';
                    
                    $('#s-opacity').value = c.panelOpacity !== undefined ? c.panelOpacity : 0.9;
                    $('#s-opacity-val').innerText = $('#s-opacity').value;
                    
                    $('#s-blur').value = c.panelBlur !== undefined ? c.panelBlur : 0;
                    $('#s-blur-val').innerText = $('#s-blur').value + 'px';
                    
                    $('#s-mask').value = c.bgMask !== undefined ? c.bgMask : 0;
                    $('#s-mask-val').innerText = $('#s-mask').value;

                    $('#s-theme-mode').value = c.themeMode || 'auto';
                    
                    $('#s-accent').value = c.accentColor || '#22c55e';
                    $('#s-radius').value = c.borderRadius !== undefined ? c.borderRadius : 8;
                    $('#s-radius-val').innerText = $('#s-radius').value + 'px';

                    this.toggleSection('bg', true);
                    this.toggleSection('glass', true);
                    this.toggleSection('mask', true);
                    this.toggleSection('text', true);
                    this.toggleSection('ui', true);
                }
            },

            toggleSection(id, noPreview) {
                const checked = $('#sw-' + id).checked;
                const el = $('#sec-' + id);
                if(checked) {
                    el.classList.add('active');
                    if(id === 'glass' && !noPreview) {
                        if($('#s-opacity').value == 1) $('#s-opacity').value = 0.8; 
                        if($('#s-blur').value == 0) $('#s-blur').value = 10;
                    }
                } else {
                    el.classList.remove('active');
                }
                if(!noPreview) this.previewStyle();
            },

            applyPreset(name) {
                if (name === 'custom') return;
                const p = PRESETS[name];
                if (!p) return;

                $('#sw-ui').checked = true;
                this.toggleSection('ui', true);
                $('#s-accent').value = p.color;
                $('#s-radius').value = p.radius;
                $('#s-radius-val').innerText = p.radius + 'px';

                if (p.mode) {
                     $('#sw-text').checked = true;
                     this.toggleSection('text', true);
                     $('#s-theme-mode').value = p.mode;
                }

                if (p.bg) {
                    $('#sw-bg').checked = true;
                    this.toggleSection('bg', true);
                    $('#s-bg-url').value = p.bg;
                    $('#s-bg-file').value = '';
                } else {
                    $('#sw-bg').checked = false;
                    this.toggleSection('bg', true);
                }

                this.previewStyle();
            },

            previewStyle() {
                const useBg = $('#sw-bg').checked;
                const useGlass = $('#sw-glass').checked;
                const useMask = $('#sw-mask').checked;
                const useText = $('#sw-text').checked;
                const useUi = $('#sw-ui').checked;

                const tempConfig = {
                    bgUrl: useBg ? $('#s-bg-url').value : null,
                    bgImage: useBg ? (this.config.bgImage || null) : null, 
                    panelOpacity: useGlass ? $('#s-opacity').value : 1,
                    panelBlur: useGlass ? $('#s-blur').value : 0,
                    bgMask: useMask ? $('#s-mask').value : 0,
                    customCss: useText ? $('#s-css').value : null,
                    themeMode: useText ? $('#s-theme-mode').value : 'auto',
                    accentColor: useUi ? $('#s-accent').value : '#22c55e',
                    borderRadius: useUi ? $('#s-radius').value : 8
                };
                
                $('#s-opacity-val').innerText = tempConfig.panelOpacity;
                $('#s-blur-val').innerText = tempConfig.panelBlur + 'px';
                $('#s-mask-val').innerText = tempConfig.bgMask;
                $('#s-radius-val').innerText = tempConfig.borderRadius + 'px';
                
                this.applyConfig(tempConfig);
            },

            applyConfig(c) {
                let css = '';
                if (c.bgUrl || c.bgImage) {
                     let bg = c.bgImage || c.bgUrl;
                     css += \`body { background: url('\${bg}') no-repeat center center fixed; background-size: cover; }\`;
                } else {
                    css += \`body { background: var(--bg); }\`;
                }
                
                const op = c.panelOpacity !== undefined ? c.panelOpacity : 1; 
                const bl = c.panelBlur !== undefined ? c.panelBlur : 0;
                const rad = c.borderRadius !== undefined ? c.borderRadius : 8;
                const acc = c.accentColor || '#22c55e';
                
                let maskVal = c.bgMask !== undefined ? parseFloat(c.bgMask) : 0;
                let maskColor = '0,0,0';
                if(maskVal > 0) maskColor = '255,255,255';
                let maskAlpha = Math.abs(maskVal);
                
                document.documentElement.style.setProperty('--bg-op', op);
                document.documentElement.style.setProperty('--blur', bl + 'px');
                document.documentElement.style.setProperty('--mask', \`rgba(\${maskColor}, \${maskAlpha})\`);
                document.documentElement.style.setProperty('--radius', rad + 'px');
                document.documentElement.style.setProperty('--a', acc);
                
                const hex = acc.replace('#','');
                if(hex.length === 6) {
                    const r = parseInt(hex.substring(0,2), 16);
                    const g = parseInt(hex.substring(2,4), 16);
                    const b = parseInt(hex.substring(4,6), 16);
                    document.documentElement.style.setProperty('--a-rgb', \`\${r},\${g},\${b}\`);
                }

                const mode = c.themeMode || 'auto';
                if (mode === 'light') {
                    document.documentElement.classList.add('light');
                } else if (mode === 'dark') {
                    document.documentElement.classList.remove('light');
                } else {
                    const h = (new Date().getUTCHours() + 8) % 24;
                    if(h >= 6 && h < 18) document.documentElement.classList.add('light');
                    else document.documentElement.classList.remove('light');
                }

                if (c.customCss) css += c.customCss;
                
                let style = $('#custom-style');
                if (!style) {
                    style = document.createElement('style');
                    style.id = 'custom-style';
                    document.head.appendChild(style);
                }
                style.innerHTML = css;
            },

            async clearBackground() {
                if(!confirm("Clear Background Image?")) return;
                this.config.bgImage = null;
                this.config.bgUrl = null;
                $('#s-bg-url').value = '';
                $('#s-bg-file').value = '';
                this.previewStyle();
            },

            async resetAppearance() {
                if(!confirm("Reset all appearance settings?")) return;
                const newConfig = { 
                    bgUrl: null, bgImage: null, customCss: null,
                    panelOpacity: 1, panelBlur: 0, bgMask: 0,
                    themeMode: 'auto', accentColor: '#22c55e', borderRadius: 8
                };
                await API.req({ action: 'saveConfig', config: newConfig });
                location.reload();
            },

            async saveSettings() {
                const useBg = $('#sw-bg').checked;
                const useGlass = $('#sw-glass').checked;
                const useMask = $('#sw-mask').checked;
                const useText = $('#sw-text').checked;
                const useUi = $('#sw-ui').checked;

                const bgUrl = $('#s-bg-url').value;
                const file = $('#s-bg-file').files[0];
                let bgImage = this.config.bgImage;

                if (useBg && file) {
                    if (!file.type.startsWith('image/')) return alert('Images only');
                    if (file.size > 2 * 1024 * 1024) return alert('Max size 2MB');
                    bgImage = await new Promise(r => {
                        const reader = new FileReader();
                        reader.onload = e => r(e.target.result);
                        reader.readAsDataURL(file);
                    });
                } else if (!useBg) {
                    bgImage = null;
                }

                const newConfig = { 
                    bgUrl: useBg ? bgUrl : null, 
                    bgImage: useBg ? bgImage : null, 
                    panelOpacity: useGlass ? $('#s-opacity').value : 1, 
                    panelBlur: useGlass ? $('#s-blur').value : 0,
                    bgMask: useMask ? $('#s-mask').value : 0,
                    themeMode: useText ? $('#s-theme-mode').value : 'auto',
                    customCss: useText ? $('#s-css').value : null,
                    accentColor: useUi ? $('#s-accent').value : '#22c55e',
                    borderRadius: useUi ? $('#s-radius').value : 8
                };
                
                await API.req({ action: 'saveConfig', config: newConfig });
                this.config = newConfig;
                this.applyConfig(this.config);
                this.toggleSettings();
            },

            toggleLang() {
                if (this.lang === 'en') this.lang = 'zh-Hans';
                else if (this.lang === 'zh-Hans') this.lang = 'zh-Hant';
                else this.lang = 'en';
                this.updateTexts();
                this.renderList();
            },
            
            updateTexts() {
                const t = TEXTS[this.lang];
                $('#t-new').innerText = t.new;
                $('#l-name').innerText = t.lName; $('#inName').placeholder = t.namePh;
                $('#l-target').innerText = t.lTarget; $('#inTarget').placeholder = t.targetPh;
                $('#l-tag').innerText = t.lTag; $('#inTag').placeholder = t.tagPh;
                $('#l-sec').innerText = t.lSec; $('#inSec').placeholder = t.secPh;
                
                $('#t-deploy').innerText = t.deploy;
                $('#t-nodes').innerText = t.nodes;
                $('#t-export').innerText = t.export;
                $('#t-import').innerText = t.import;
                $('#inSearch').placeholder = t.search;
                $('#t-batchDel').innerText = t.batchDel;
                $('#t-batchTag').innerText = t.batchTag;
                $('#th-name').innerText = t.thName;
                $('#th-target').innerText = t.thTarget;
                $('#th-proxy').innerText = t.thProxy;
                $('#th-action').innerText = t.thAction;
            },

            async refresh(){
                try {
                    const d=await API.req({action:'list'});
                    if(d.error) {
                        alert('错误：' + d.error);
                        return;
                    }
                    this.nodes=(d.nodes || []).map(n => ({...n, tag: n.tag || ""})); 
                    this.selected.clear();
                    this.renderList();
                } catch(e) {
                    alert('前端加载失败：' + e);
                }
            },
            
            filter(val) {
                this.filterText = val.toLowerCase();
                this.renderList();
            },

            toggleAllTargets() {
                this.showAllTargets = !this.showAllTargets;
                const btn = $('#btn-eye-all');
                btn.innerHTML = this.showAllTargets ? Icons.eyeOff : Icons.eye;
                btn.style.color = this.showAllTargets ? 'var(--a)' : 'var(--ts)';
                this.renderList();
            },

            toggleVisibility(key) {
                if (this.visibleMap.has(key)) this.visibleMap.delete(key);
                else this.visibleMap.add(key);
                this.renderList();
            },

            toggleSelect(name) {
                if (this.selected.has(name)) this.selected.delete(name);
                else this.selected.add(name);
                this.renderBatchBar();
                const row = document.getElementById('row-'+name);
                if(row) {
                    if(this.selected.has(name)) row.classList.add('selected');
                    else row.classList.remove('selected');
                }
            },

            toggleSelectAll(cb) {
                const visibleNodes = this.getFilteredNodes();
                if (cb.checked) visibleNodes.forEach(n => this.selected.add(n.name));
                else this.selected.clear();
                this.renderList();
            },

            getFilteredNodes() {
                if (!this.filterText) return this.nodes;
                return this.nodes.filter(n => 
                    n.name.toLowerCase().includes(this.filterText) || 
                    (n.tag && n.tag.toLowerCase().includes(this.filterText))
                );
            },

            renderBatchBar() {
                const bar = $('#batch-bar');
                const t = TEXTS[this.lang];
                if (this.selected.size > 0) {
                    bar.style.display = 'flex';
                    $('#t-selected').innerText = t.selected + this.selected.size;
                } else {
                    bar.style.display = 'none';
                }
            },
            
            // 修复: 在 App 对象内补充 escapeHtml 函数
            escapeHtml(unsafe) {
                if (!unsafe) return "";
                return String(unsafe).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
            },

            renderList() {
                const t = TEXTS[this.lang];
                const displayNodes = this.getFilteredNodes();
                const allSelected = displayNodes.length > 0 && displayNodes.every(n => this.selected.has(n.name));
                
                const selectAllCb = $('thead input[type=checkbox]');
                if(selectAllCb) selectAllCb.checked = allSelected;

                $('#list').innerHTML = displayNodes.map(n => {
                    const isSel = this.selected.has(n.name);
                    const safeName = this.escapeHtml(n.name); // 之前这里报错，因为 this.escapeHtml 不存在
                    const safeTag = this.escapeHtml(n.tag);
                    const safeTarget = this.escapeHtml(n.target);
                    const safeSecret = this.escapeHtml(n.secret);

                    // ========================================================
                    // 核心逻辑：动态计算 Proxy 地址（无 KV 存储）
                    // ========================================================
                    const proxyUrl = location.origin + '/' + safeName + (n.secret ? '/' + safeSecret : '');

                    // Keys for individual visibility
                    const kTarget = safeName + ':target';
                    const kProxy = safeName + ':proxy';
                    
                    const showTarget = this.showAllTargets || this.visibleMap.has(kTarget);
                    const showProxy = this.showAllTargets || this.visibleMap.has(kProxy);

                    const tagHtml = n.tag ? \`<span class="tag-badge tag-blue">\${safeTag}</span>\` : '';
                    const secHtml = n.secret ? \`<span title="Secret" style="margin-left:5px;color:var(--d97706)">\${Icons.lock}</span>\` : '';
                    
                    const targetDisplay = showTarget ? safeTarget : '••••••••••••';
                    const targetClass = showTarget ? '' : 'color:var(--ts);letter-spacing:2px';
                    
                    const proxyDisplay = showProxy ? proxyUrl : '••••••••••••';
                    const proxyClass = showProxy ? '' : 'color:var(--ts);letter-spacing:2px';

                    return \`<tr id="row-\${safeName}" class="\${isSel?'selected':''}" style="border-bottom:1px solid var(--b)">
                        <td style="padding:10px">
                            <input type="checkbox" \${isSel?'checked':''} onchange="App.toggleSelect('\${safeName}')">
                        </td>
                        <td style="padding:10px">
                            <div style="display:flex;align-items:center">
                                <b style="cursor:pointer" onclick="App.copyText('\${safeName}', this)">\${safeName}</b>
                                \${tagHtml}
                                \${secHtml}
                            </div>
                        </td>
                        <td style="padding:10px;font-family:monospace;font-size:12px;\${targetClass}">
                            <div style="display:flex;align-items:center;gap:5px">
                                <span style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:middle">\${targetDisplay}</span>
                                <button onclick="App.toggleVisibility('\${kTarget}')" class="btn-icon" style="padding:0;transform:scale(0.8)">\${showTarget ? Icons.eyeOff : Icons.eye}</button>
                            </div>
                        </td>
                        <td style="padding:10px;font-family:monospace;font-size:12px;\${proxyClass}">
                            <div style="display:flex;align-items:center;gap:5px">
                                <span style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:middle">\${proxyDisplay}</span>
                                <button onclick="App.toggleVisibility('\${kProxy}')" class="btn-icon" style="padding:0;transform:scale(0.8)">\${showProxy ? Icons.eyeOff : Icons.eye}</button>
                            </div>
                        </td>
                        <td style="padding:10px;text-align:right">
                             <button onclick="App.copyText('\${proxyUrl}', this)" class="btn-icon" title="Copy Proxy Address">\${Icons.copy}</button>
                             <button onclick="App.del('\${safeName}')" class="btn-icon" style="color:var(--e)" title="Delete">\${Icons.trash}</button>
                        </td>
                    </tr>\`;
                }).join('') || \`<tr><td colspan="5" style="padding:20px;text-align:center;color:var(--ts)">\${t.noNodes}</td></tr>\`;
                
                this.renderBatchBar();
            },

            async save(){
                const name=$('#inName').value, target=$('#inTarget').value, secret=$('#inSec').value, tag=$('#inTag').value;
                if(!name||!target) return alert('Required');
                await API.req({action:'save',name,target,secret,tag});
                $('#inName').value=''; $('#inTarget').value=''; $('#inSec').value=''; $('#inTag').value='';
                this.refresh();
            },

            async del(n){if(confirm('Delete '+n+'?')){await API.req({action:'delete',name:n});this.refresh()}},
            
            async batchDelete() {
                if(!confirm('Delete ' + this.selected.size + ' items?')) return;
                await API.req({action:'batchDelete', names: Array.from(this.selected)});
                this.refresh();
            },

            async batchTag() {
                const tag = prompt(TEXTS[this.lang].inputTag);
                if (tag === null) return;
                const updates = [];
                for(const name of this.selected) {
                    const node = this.nodes.find(n => n.name === name);
                    if(node) updates.push({...node, tag: tag});
                }
                await API.req({action:'import', nodes: updates});
                this.refresh();
            },

            async export(){
                const a=document.createElement('a');
                a.href=URL.createObjectURL(new Blob([JSON.stringify(this.nodes)],{type:'json'}));
                a.download='nodes_v17.json';
                a.click();
            },

            async import(e){
                const f=e.files[0]; if(!f) return;
                const r=new FileReader();
                r.onload=async ev=>{try{await API.req({action:'import',nodes:JSON.parse(ev.target.result)});this.refresh()}catch{alert('Err')}};
                r.readAsText(f);
            },
            
            copyText(text, btn) {
                navigator.clipboard.writeText(text);
                const original = btn.innerHTML;
                btn.style.color = 'var(--a)';
                // If it's the copy icon, don't change text, just color. If it's name text, change text.
                if(!btn.innerHTML.includes('<svg')) {
                    btn.innerText = TEXTS[this.lang].copy;
                }
                setTimeout(()=>{ 
                    btn.innerHTML = original; 
                    btn.style.color = ''; 
                }, 1000);
            }
        };
        App.init();
    </script>
</body></html>`;
        return new Response(html, { headers: { "Content-Type": "text/html" } });
    }
};

// ============================================================================
// 5. MAIN ENTRY
// ============================================================================
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const segments = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
        const root = segments[0];

        if (root === "admin") {
            const ct = request.headers.get("content-type") || "";
            if (request.method === "POST" && ct.includes("form")) return Auth.handleLogin(request, env);
            if (!(await Auth.verifyRequest(request, env))) {
                if (request.method === "POST") return new Response("Unauthorized", { status: 401 });
                return UI.renderLoginPage();
            }
            if (request.method === "POST") return Database.handleApi(request, env);
            return UI.renderAdminUI();
        }

        if (root) {
            const nodeData = await Database.getNode(root, env, ctx);
            if (nodeData) {
                const secret = nodeData.secret;
                let valid = true;
                let strip = 1;

                if (secret) {
                    if (segments[1] === secret) { strip = 2; }
                    else { valid = false; }
                }

                if (valid) {
                    const remaining = "/" + segments.slice(strip).join('/');
                    if (remaining === "/" || remaining === "") {
                        const base = secret ? `/${root}/${secret}` : `/${root}`;
                        return Response.redirect(url.origin + base + "/web/index.html", 302);
                    }
                    return Proxy.handle(request, nodeData, remaining, root, secret);
                }
            }
        }

        return new Response("Access Denied", { status: 403 });
    }
};
