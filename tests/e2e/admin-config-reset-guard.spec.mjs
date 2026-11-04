import { expect, test } from "@playwright/test";
import { adminPassword } from "./support.mjs";

// 2026-11-04 事故回归：清完浏览器数据重新登录后，getAdminBootstrap 卡了 89 秒，
// 面板已经能点、runtimeConfig 还是空对象，这时候点皮肤开关会把「本机默认值」整份写回 KV，
// 全局设置（Cloudflare 联动 / TG / 日志）被重置成默认值，只有 4 个密钥靠服务端回填活下来。
// 这条用例用真实的慢 bootstrap 复现那个窗口，断言皮肤点击一次都不落库。

const BOOTSTRAP_DELAY_MS = 8_000;
const SAVED_CONFIG = {
  cfZoneId: "zone-e2e",
  tgChatId: "4242",
  logEnabled: false,
  rateLimitRpm: 20,
};

function isSaveConfigRequest(request) {
  if (request.method() !== "POST") return false;
  const body = request.postData() || "";
  return body.includes('"action":"saveConfig"');
}

test("bootstrap 未完成时点皮肤开关不会把默认值写回配置", async ({ page }) => {
  const saveBodies = [];
  page.on("request", (request) => {
    if (isSaveConfigRequest(request)) saveBodies.push(request.postData() || "");
  });

  // 面板所有「拿配置」的入口都压住：事故里 getAdminBootstrap 卡了 89 秒，
  // 期间 runtimeConfig 一直是空对象。
  const bootstrapActions = [
    '"action":"getAdminBootstrap"',
    '"action":"getSettingsBootstrap"',
    '"action":"loadConfig"',
  ];
  await page.route("**/admin", async (route) => {
    const body = route.request().postData() || "";
    if (
      route.request().method() === "POST" &&
      bootstrapActions.some((needle) => body.includes(needle))
    ) {
      await new Promise((resolve) => setTimeout(resolve, BOOTSTRAP_DELAY_MS));
    }
    await route.continue();
  });

  await page.goto("/admin");
  await page.fill("#admin-login-password", adminPassword);
  await page.click("#admin-login-submit");
  await expect(page).toHaveURL(/\/admin$/);

  // 先落一份真配置，事故里被抹掉的就是这类字段。
  const seeded = await page.request.post("/admin", {
    data: { action: "saveConfig", config: SAVED_CONFIG },
  });
  expect(seeded.status()).toBe(200);

  // 面板可点、配置还没到：进设置页点皮肤（事故那一下）。皮肤卡片在 #set-ui 里，
  // 设置页只有在点开之后才会挂载，所以这里必须真的走一次导航。
  await page.click('.nav-item[href="#settings"]');
  await expect(page.locator("#set-ui")).toBeVisible();
  const skinButton = page.locator('[data-admin-skin-option="claude"]');
  await expect(skinButton).toBeVisible();
  await skinButton.click();
  await page.waitForTimeout(1500);
  expect(saveBodies).toEqual([]);

  // 配置必须原样留在 KV 里：没有写入，就没有默认值覆盖。
  const beforeBootstrapLanded = await page.request.post("/admin", {
    data: { action: "getSettingsBootstrap", forceRefresh: true },
  });
  const pendingConfig = (await beforeBootstrapLanded.json()).config || {};
  expect(pendingConfig.cfZoneId).toBe(SAVED_CONFIG.cfZoneId);
  expect(pendingConfig.tgChatId).toBe(SAVED_CONFIG.tgChatId);

  // bootstrap 落地后闸门必须打开：同样的点击这次要真的落库，并且不能带走其它字段。
  await expect
    .poll(
      () =>
        page.evaluate(() =>
          window.App?.runtimeConfig && Object.keys(window.App.runtimeConfig).length > 5
            ? "hydrated"
            : `pending: ${Object.keys(window.App?.runtimeConfig || {}).length}`,
        ),
      { timeout: 60_000 },
    )
    .toBe("hydrated");

  await page.locator('[data-admin-skin-option="classic"]').click();
  await expect.poll(() => saveBodies.length, { timeout: 20_000 }).toBe(1);
  expect(saveBodies[0]).toContain('"adminUiSkin":"classic"');

  const afterHydratedSave = await page.request.post("/admin", {
    data: { action: "getSettingsBootstrap", forceRefresh: true },
  });
  const savedConfig = (await afterHydratedSave.json()).config || {};
  expect(savedConfig.cfZoneId).toBe(SAVED_CONFIG.cfZoneId);
  expect(savedConfig.tgChatId).toBe(SAVED_CONFIG.tgChatId);
  expect(savedConfig.logEnabled).toBe(SAVED_CONFIG.logEnabled);
});
