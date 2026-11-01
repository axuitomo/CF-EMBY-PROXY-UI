import assert from "node:assert/strict";
import { expect, test } from "@playwright/test";
import { loginAndWaitForAdminBoot } from "./support.mjs";

// 管理台是单文件交付：这里刻意只用生产 HTML 里真实存在的选择器，
// 一旦模板改名，这条冒烟会失败，而不是悄悄测了个空壳。

test("登录后能渲染看板并在视图之间切换", async ({ page }) => {
  // 只收未捕获的脚本异常：空库/未配账号时，管理台会用 console.error 报告
  // “请在账号设置中完善 Zone ID”“FTS5 未初始化”这类降级结果，那是产品行为，不是崩溃。
  const runtimeErrors = [];
  page.on("pageerror", (error) => runtimeErrors.push(String(error)));

  await loginAndWaitForAdminBoot(page);
  await expect(page.locator("#view-dashboard")).toBeVisible();
  await expect(page.locator('.nav-item[href="#nodes"]')).toBeVisible();

  for (const view of ["nodes", "logs", "dns", "settings"]) {
    await page.click(`.nav-item[href="#${view}"]`);
    await expect(page.locator(`#view-${view}`)).toBeVisible();

    // 空库的日志页会弹“请先初始化日志表”。冒烟只证明视图能渲染，提示关掉继续。
    const dismiss = page.getByRole("button", { name: "知道了" });
    if (await dismiss.isVisible()) await dismiss.click();
  }

  // 「测试 Cloudflare 令牌」必须贴着 Cloudflare API 令牌输入框，而不是跟着 TMDB 凭据面板走。
  // 这条只有真实 DOM 能验：注入顺序、密码框包裹层、Vue 重渲染三者合起来才决定它落在哪。
  await page.click('.nav-item[href="#settings"]');
  await page.evaluate(() => {
    const label = [...document.querySelectorAll("#view-settings *")].find(
      (element) => element.children.length === 0 && element.textContent.trim() === "账号设置",
    );
    label?.closest("button, a, [role=tab]")?.click();
    label?.click();
  });
  await expect(page.locator("#cfg-cf-token")).toBeVisible();
  const credentialTestPlacement = await page.evaluate(() => {
    const token = document.querySelector("#cfg-cf-token");
    const panel = token?.closest(".ui-settings-panel");
    const tmdbPanel = document.querySelector('[data-admin-tmdb-credentials="1"]');
    return {
      panelTitle: (panel?.querySelector(".ui-section-title")?.textContent || "").trim(),
      cloudflareButtonInPanel: !!panel?.querySelector('[data-credential-test="cloudflare"]'),
      tmdbButtons: [...(tmdbPanel?.querySelectorAll("[data-credential-test]") || [])].map(
        (button) => button.getAttribute("data-credential-test"),
      ),
    };
  });
  expect(credentialTestPlacement.panelTitle).toBe("Cloudflare 联动");
  expect(credentialTestPlacement.cloudflareButtonInPanel).toBe(true);
  expect(credentialTestPlacement.tmdbButtons).toEqual(["tmdb"]);

  await page.click('.nav-item[href="#dashboard"]');
  await expect(page.locator("#view-dashboard")).toBeVisible();

  expect(runtimeErrors).toEqual([]);
});

test("CDN 不可达时管理台仍能从同源 vendor 启动", async ({ page }) => {
  // 手机网络到 cdn.jsdelivr.net 不通是长期存在的真实场景：4 个首屏脚本必须由 Worker
  // 从本地摇树产物同源返回（/ADMIN_PATH/__release/<rev>/vendor/<assetKey>），
  // 一旦回退到浏览器直连 CDN，这里就会变成一张白屏。
  const runtimeErrors = [];
  page.on("pageerror", (error) => runtimeErrors.push(String(error)));
  await page.route("**cdn.jsdelivr.net/**", (route) => route.abort("failed"));

  await loginAndWaitForAdminBoot(page);
  await expect(page.locator("#view-dashboard")).toBeVisible();

  // lucide 摇树子集：图标必须真的替换成 svg，而不是留一堆空的 <i data-lucide>
  expect(await page.locator("svg.lucide").count()).toBeGreaterThan(5);

  // chart.js 摇树子集：画布上必须有实际像素（坐标轴/网格），否则说明注册项或颜色被摇掉了
  const paintedPixels = await page.evaluate(() => {
    const canvas = document.querySelector("canvas");
    if (!canvas) return 0;
    const data = canvas.getContext("2d").getImageData(0, 0, canvas.width, canvas.height).data;
    let painted = 0;
    for (let index = 3; index < data.length; index += 4) if (data[index] > 0) painted += 1;
    return painted;
  });
  expect(paintedPixels).toBeGreaterThan(1000);
  expect(runtimeErrors).toEqual([]);
});

// 优选 IP 工作台的「导出」是 <details> 里的绝对定位弹层，而它的父级工具栏用 overflow-x-auto
// 防窄屏换行。滚动容器会整块裁掉绝对定位子元素（弹层 120px，容器 38px），三个导出格式一个都点不到，
// 只有真实浏览器算得出这个几何，字符串断言看不出来。
for (const width of [1440, 1024, 390]) {
  test(`优选 IP 工作台导出菜单在 ${width}px 下可点`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await loginAndWaitForAdminBoot(page);
    // 窄屏主导航是抽屉，直接用 hash 切视图。
    await page.evaluate(() => {
      location.hash = "#dns";
    });
    await expect(page.locator("#view-dns")).toBeVisible();
    const dismiss = page.getByRole("button", { name: "知道了" });
    if (await dismiss.isVisible().catch(() => false)) await dismiss.click();
    // 工作台只在 A 模式下渲染（CNAME 模式显示历史卡片）。
    await page.evaluate(() =>
      [...document.querySelectorAll("#view-dns button")]
        .find((button) => button.textContent.trim() === "A模式")
        ?.click(),
    );
    await expect(page.locator("#view-dns details > summary")).toBeVisible({ timeout: 15000 });

    await page.locator("#view-dns details").scrollIntoViewIfNeeded();
    await page.locator("#view-dns details > summary").click();
    await page.waitForTimeout(300);

    const menu = await page.evaluate(() => {
      const surface = document.querySelector("#view-dns details > div");
      const box = surface.getBoundingClientRect();
      return {
        inViewport: box.top >= 0 && box.bottom <= innerHeight,
        right: Math.round(box.right),
        docWidth: document.documentElement.clientWidth,
        toolbarScrolls: (() => {
          const toolbar = document.querySelector("#view-dns details").parentElement;
          return toolbar.scrollWidth > toolbar.clientWidth + 1;
        })(),
        options: [...surface.querySelectorAll("button")].map((button) => {
          const rect = button.getBoundingClientRect();
          const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
          return {
            text: button.innerText.replace(/\s+/g, " ").trim(),
            visible: rect.top >= 0 && rect.bottom <= innerHeight,
            hittable: !!hit && (hit === button || button.contains(hit)),
          };
        }),
      };
    });

    expect(menu.options.map((option) => option.text)).toEqual([
      "导出 TXT .txt",
      "导出 JSON .json",
      "导出 CSV .csv",
    ]);
    for (const option of menu.options) {
      assert.equal(option.hittable, true, `${width}px: ${option.text} 被遮挡`);
      assert.equal(option.visible, true, `${width}px: ${option.text} 超出视口`);
    }
    assert.equal(menu.inViewport, true);
    assert.ok(
      menu.right <= menu.docWidth,
      `${width}px: 弹层右侧溢出 ${menu.right} > ${menu.docWidth}`,
    );
    // 弹层不能被工具栏的横向滚动裁掉：容器仍可横滚时，弹层就是不可见的。
    assert.equal(menu.toolbarScrolls, false);
  });
}
