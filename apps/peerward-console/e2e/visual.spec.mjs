import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { mkdir } from "node:fs/promises";
import path from "node:path";

const consoleUrl = process.env.PEERWARD_CONSOLE_E2E_URL ?? "http://127.0.0.1:28081";
const oidcExpected = process.env.PEERWARD_EXPECT_OIDC === "1";

async function ready(page) {
  if (oidcExpected) {
    await page.goto(`${consoleUrl}/api/v1/auth/login`);
    await expect(page).toHaveURL((url) => url.origin === consoleUrl && url.pathname === "/");
  } else {
    await page.goto(`${consoleUrl}/`);
  }
  await expect(page.locator("main[data-console-ready]")).toHaveAttribute("data-console-ready", "true");
  // Overview has no resource editor. Document preferences are applied by WASM.
  await expect(page.locator("html")).toHaveAttribute("data-theme", /system|light|dark/);
}

async function assertAccessible(page) {
  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.filter(({ impact }) => ["critical", "serious"].includes(impact)))
    .toEqual([]);
}

async function captureEvidence(page, name, options) {
  const directory = process.env.PEERWARD_EVIDENCE_SCREENSHOT_DIR;
  if (!directory) return;
  await mkdir(directory, { recursive: true });
  const { maxDiffPixelRatio: _, ...captureOptions } = options;
  await page.screenshot({ path: path.join(directory, name), ...captureOptions });
}

for (const fixture of [
  { name: "desktop-en-light", width: 1440, height: 1000, locale: "en-US", theme: "light" },
  { name: "desktop-zh-dark", width: 1440, height: 1000, locale: "zh-CN", theme: "dark" },
  { name: "mobile-en-dark", width: 390, height: 844, locale: "en-US", theme: "dark" },
  { name: "mobile-zh-light", width: 390, height: 844, locale: "zh-CN", theme: "light" },
]) {
  test(`WCAG and visual shell ${fixture.name}`, async ({ page }) => {
    await page.setViewportSize({ width: fixture.width, height: fixture.height });
    await ready(page);
    await page.locator(".account-menu > summary").click();
    await page.locator("#pw-language").selectOption(fixture.locale);
    await page.locator("#pw-theme").selectOption(fixture.theme);
    await page.locator(".account-menu > summary").click();
    await assertAccessible(page);
    const screenshot = {
      animations: "disabled",
      caret: "hide",
      fullPage: true,
      mask: [
        page.locator(".pw-error small"),
        page.locator("section[data-browser-ready] p[role='status']"),
      ],
      maxDiffPixelRatio: 0.001,
    };
    await expect(page).toHaveScreenshot(`${fixture.name}.png`, screenshot);
    await captureEvidence(page, `${fixture.name}.png`, screenshot);
  });
}
