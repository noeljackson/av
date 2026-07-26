import { chromium } from "playwright";

const baseUrl = process.env.AV_UI_URL;
if (!baseUrl) throw new Error("AV_UI_URL is required");

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
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
  if (await page.getByRole("heading", { name: "container-smoke" }).count()) {
    throw new Error("locked UI leaked a configured profile");
  }

  await page.locator("#username").fill("operator");
  await page.locator("#password").fill("password");
  await page.getByRole("button", { name: "sign in" }).click();
  await page.locator("#dashboard:not([hidden])").waitFor();
  await page.getByText("runtime matrix").waitFor();
  await page.getByRole("heading", { name: "container-smoke" }).waitFor();
  if (await page.getByText("managed control plane").count()) {
    throw new Error("static UI exposed a managed owner panel");
  }
  if (await page.locator("#password").inputValue()) {
    throw new Error("password input was not cleared after authentication");
  }

  await page.getByRole("button", { name: "disconnect" }).click();
  await page.locator("#locked-screen:not([hidden])").waitFor();
  if (await page.getByRole("heading", { name: "container-smoke" }).isVisible()) {
    throw new Error("logout left an authorized profile visible");
  }
  if (browserErrors.length) throw new Error(browserErrors.join("; "));
  console.log("ui_browser_smoke=ok");
} finally {
  await browser.close();
}
