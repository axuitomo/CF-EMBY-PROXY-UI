import { fileURLToPath, URL } from "node:url";

import vue from "@vitejs/plugin-vue";
import { defineConfig, loadEnv } from "vite";

function normalizeRoutePath(rawValue = "/admin") {
  const value = String(rawValue || "").trim();
  if (!value) return "/admin";
  const normalized = value.startsWith("/") ? value : `/${value}`;
  return normalized === "/" ? "/" : normalized.replace(/\/+$/, "");
}

function normalizeProxyTarget(rawValue = "") {
  const value = String(rawValue || "").trim();
  return value || "http://127.0.0.1:8787";
}

function readRequestProtocol(request) {
  const forwardedProto = String(request?.headers?.["x-forwarded-proto"] || "")
    .split(",")[0]
    .trim()
    .toLowerCase();
  if (forwardedProto === "https") return "https";
  return request?.socket?.encrypted ? "https" : "http";
}

function rewriteDevProxyLocation(locationHeader = "", target = "", request) {
  const location = String(locationHeader || "").trim();
  const requestHost = String(request?.headers?.host || "").trim();
  if (!location || !requestHost) return location;

  try {
    const targetUrl = new URL(target);
    const nextUrl = new URL(location, targetUrl);
    if (nextUrl.origin !== targetUrl.origin) return location;
    nextUrl.protocol = `${readRequestProtocol(request)}:`;
    nextUrl.host = requestHost;
    return nextUrl.toString();
  } catch {
    return location;
  }
}

function rewriteDevProxySetCookieHeaders(setCookieHeader, request) {
  if (readRequestProtocol(request) === "https" || !setCookieHeader) return setCookieHeader;
  const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
  return cookies.map((cookie) => String(cookie || "").replace(/;\s*Secure/gi, ""));
}

function createDevProxyRule(target) {
  return {
    target,
    changeOrigin: true,
    secure: false,
    ws: false,
    autoRewrite: true,
    configure(proxy) {
      proxy.on("proxyRes", (proxyRes, request) => {
        const nextLocation = rewriteDevProxyLocation(proxyRes.headers.location, target, request);
        if (nextLocation) {
          proxyRes.headers.location = nextLocation;
        }

        const nextSetCookie = rewriteDevProxySetCookieHeaders(
          proxyRes.headers["set-cookie"],
          request,
        );
        if (nextSetCookie) {
          proxyRes.headers["set-cookie"] = nextSetCookie;
        }
      });
    },
  };
}

function createDevProxy(env) {
  const adminPath = normalizeRoutePath(env.VITE_ADMIN_PATH || "/admin");
  const target = normalizeProxyTarget(env.VITE_DEV_PROXY_TARGET || env.VITE_API_BASE_URL);

  return {
    [adminPath]: createDevProxyRule(target),
    [`${adminPath}/`]: createDevProxyRule(target),
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");

  return {
    // 依赖已提升到根 node_modules：缓存默认跟着最近的 package.json 落在 frontend/node_modules，
    // 会把“仓库里不该有 frontend/node_modules”这条事实破坏掉，所以显式指到根目录。
    cacheDir: fileURLToPath(new URL("../node_modules/.vite", import.meta.url)),
    // 线上壳的 Tailwind 由 frontend/scripts/build-admin-tailwind.mjs 在构建期编译成静态 CSS
    // 并内联进 index.html；这个配置只服务 frontend/src 参考源，不再需要 @tailwindcss/vite。
    plugins: [vue()],
    resolve: {
      alias: {
        "@": fileURLToPath(new URL("./src", import.meta.url)),
      },
    },
    server: {
      fs: {
        allow: [fileURLToPath(new URL("..", import.meta.url))],
      },
      host: "0.0.0.0",
      port: 5173,
      proxy: createDevProxy(env),
    },
    preview: {
      host: "0.0.0.0",
      port: 4173,
    },
  };
});
