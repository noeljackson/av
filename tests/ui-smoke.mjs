import { chromium } from "playwright";

const baseUrl = process.env.AV_UI_URL;
if (!baseUrl) throw new Error("AV_UI_URL is required");
const expectManaged = process.env.AV_UI_EXPECT_MANAGED === "1";
const expectedProfile = process.env.AV_UI_EXPECT_PROFILE || "container-smoke";

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
const lockedScreen = page.locator("#locked-screen");
const dashboard = page.locator("#dashboard");
const browserErrors = [];
const navigationEvents = [];
page.on("pageerror", (error) => browserErrors.push(error.message));
page.on("console", (message) => {
  if (message.type() === "error") browserErrors.push(message.text());
});
page.on("response", (response) => {
  if (response.url().startsWith(baseUrl)) {
    navigationEvents.push(`response ${response.status()} ${response.url()}`);
  }
});
page.on("requestfailed", (request) => {
  if (request.url().startsWith(baseUrl)) {
    navigationEvents.push(`failed ${request.failure()?.errorText ?? "unknown"} ${request.url()}`);
  }
});

try {
  try {
    await page.goto(baseUrl, { waitUntil: "commit", timeout: 10_000 });
  } catch (error) {
    throw new Error(`${error.message}; ${navigationEvents.join("; ")}`);
  }
  await page.getByRole("heading", { name: "authentication required" }).waitFor();
  if (!(await lockedScreen.isVisible()) || (await dashboard.isVisible())) {
    throw new Error("locked UI did not render as the only visible screen");
  }
  if (await page.getByRole("heading", { name: expectedProfile }).count()) {
    throw new Error("locked UI leaked a configured profile");
  }

  await page.locator("#username").fill("operator");
  await page.locator("#password").fill("password");
  await page.getByRole("button", { name: "sign in" }).click();
  await dashboard.waitFor();
  if (!(await dashboard.isVisible()) || (await lockedScreen.isVisible())) {
    throw new Error("authenticated UI did not hide the locked screen");
  }
  await page.getByText("runtime matrix").waitFor();
  await page.getByRole("heading", { name: expectedProfile }).waitFor();
  const ownerPanel = page.getByRole("region", { name: "Managed control plane" });
  if (expectManaged) {
    await ownerPanel.waitFor();
    await ownerPanel.getByRole("heading", { name: "basic users" }).waitFor();
    const basicUserForm = ownerPanel.locator("form.owner-form").first();
    await basicUserForm.locator('input[name="username"]').fill("browser-ui");
    await basicUserForm.locator('input[name="password"]').fill("browser-ui-password");
    await basicUserForm.getByRole("button", { name: "add or rotate" }).click();
    await ownerPanel.getByText("browser-ui", { exact: true }).waitFor();
    const grantForm = ownerPanel.locator("form.owner-form").nth(1);
    await grantForm.locator('input[name="subject"]').fill("basic:browser-ui");
    await grantForm.locator('select[name="profile"]').selectOption("ungranted-integration");
    await grantForm.getByRole("button", { name: "grant profile" }).click();
    await ownerPanel.getByText("basic:browser-ui", { exact: true }).waitFor();
  } else if (await ownerPanel.count()) {
    throw new Error("static UI exposed a managed owner panel");
  }
  if (await page.locator("#password").inputValue()) {
    throw new Error("password input was not cleared after authentication");
  }

  await page.getByRole("button", { name: "disconnect" }).click();
  await lockedScreen.waitFor();
  if (!(await lockedScreen.isVisible()) || (await dashboard.isVisible())) {
    throw new Error("logout did not restore the locked screen exclusively");
  }
  if (await page.getByRole("heading", { name: expectedProfile }).isVisible()) {
    throw new Error("logout left an authorized profile visible");
  }
  if (browserErrors.length) throw new Error(browserErrors.join("; "));
  console.log("ui_browser_smoke=ok");
} finally {
  await browser.close();
}
