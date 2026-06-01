/**
 * Web Crawler / Spider — Puppeteer-powered (Dynamic SPA Support)
 *
 * Uses a headless Chromium browser to fully render pages (React / Vue / Angular)
 * before extracting links. Falls back gracefully on per-page errors.
 *
 * Interface is identical to the original static crawler so the rest of the
 * pipeline (scanner.ts, routes.ts, frontend) requires zero changes.
 */

import puppeteer, { Browser, BrowserContext, Page } from "puppeteer";
import { execSync } from "child_process";
import { URL } from "url";

/** Locate the system Chromium executable (NixOS / standard Linux). */
function findChromiumExecutable(): string | undefined {
  const candidates = [
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
  ];
  for (const bin of candidates) {
    try {
      const path = execSync(`which ${bin} 2>/dev/null`, { encoding: "utf8" }).trim();
      if (path) return path;
    } catch {}
  }
  return undefined; // Fall back to puppeteer's bundled Chrome
}

// ── Public types ─────────────────────────────────────────────────────────────

export interface FormInfo {
  action: string;
  method: string;
  inputs: string[];
}

export interface CrawlResult {
  urls: string[];
  urlsWithParams: string[];
  forms: FormInfo[];
  jsFiles: string[];
  pagesVisited: number;
  errors: string[];
}

export interface CrawlOptions {
  maxPages?: number;
  maxDepth?: number;
  timeoutMs?: number;
  /** Max concurrent browser tabs (default: 2 — conservative for container memory) */
  concurrency?: number;
}

// ── Internal types ────────────────────────────────────────────────────────────

interface PageData {
  hrefs: string[];
  forms: Array<{ action: string; method: string; inputs: string[] }>;
  scripts: string[];
  finalUrl: string;
}

// ── Page pool ─────────────────────────────────────────────────────────────────

interface PoolEntry {
  page: Page;
  ctx: BrowserContext;
}

class PagePool {
  private available: PoolEntry[] = [];
  private waitQueue: Array<(e: PoolEntry) => void> = [];

  seed(entries: PoolEntry[]): void {
    this.available = [...entries];
  }

  checkout(): Promise<PoolEntry> {
    if (this.available.length > 0) {
      return Promise.resolve(this.available.pop()!);
    }
    return new Promise<PoolEntry>((resolve) => {
      this.waitQueue.push(resolve);
    });
  }

  checkin(entry: PoolEntry): void {
    if (this.waitQueue.length > 0) {
      this.waitQueue.shift()!(entry);
    } else {
      this.available.push(entry);
    }
  }
}

// ── URL helpers ───────────────────────────────────────────────────────────────

function normalise(url: URL): string {
  const u = new URL(url.href);
  u.hostname = u.hostname.toLowerCase();
  if (u.pathname.length > 1 && u.pathname.endsWith("/")) {
    u.pathname = u.pathname.slice(0, -1);
  }
  u.hash = "";
  return u.href;
}

function resolveInternal(href: string, base: URL, origin: string): string | null {
  href = href.trim();
  if (
    !href ||
    href.startsWith("#") ||
    href.startsWith("javascript:") ||
    href.startsWith("mailto:") ||
    href.startsWith("tel:") ||
    href.startsWith("data:")
  ) return null;

  try {
    const resolved = new URL(href, base.href);
    if (resolved.origin !== origin) return null;
    resolved.hash = "";
    return resolved.href;
  } catch {
    return null;
  }
}

// ── Puppeteer page setup ──────────────────────────────────────────────────────

/**
 * Create an isolated BrowserContext for each pool slot.
 * Contexts share the browser process (single Chrome) but have completely
 * isolated cookies, storage, and cache — preventing one crawl slot from
 * contaminating another (especially important on auth-gated sites).
 */
async function preparePage(browser: Browser): Promise<PoolEntry> {
  const ctx  = await browser.createBrowserContext();
  const page = await ctx.newPage();

  // Block heavy resources — we only need the rendered DOM
  await page.setRequestInterception(true);
  page.on("request", (req) => {
    const type = req.resourceType();
    if (["image", "media", "font"].includes(type)) {
      req.abort();
    } else {
      req.continue();
    }
  });

  // Suppress console noise from the target page
  page.on("console", () => {});
  page.on("pageerror", () => {});

  return { page, ctx };
}

// ── Core page fetch ───────────────────────────────────────────────────────────

async function fetchPageData(
  page: Page,
  url: string,
  timeoutMs: number,
  origin: string
): Promise<PageData> {
  // Navigate and wait for the SPA to fully render
  await page.goto(url, {
    waitUntil: "networkidle2",
    timeout: timeoutMs,
  });

  const finalUrl = page.url();

  // Extract everything from the live DOM — catches React/Vue rendered content
  const data = await page.evaluate((pageOrigin) => {
    const hrefs: string[] = [];
    const scripts: string[] = [];
    const forms: Array<{ action: string; method: string; inputs: string[] }> = [];

    // All anchor tags — includes router-rendered links
    document.querySelectorAll("a[href]").forEach((el) => {
      const href = el.getAttribute("href");
      if (href) hrefs.push(href);
    });

    // Script tags
    document.querySelectorAll("script[src]").forEach((el) => {
      const src = el.getAttribute("src");
      if (src) scripts.push(src);
    });

    // Forms — including dynamically rendered forms in SPAs
    document.querySelectorAll("form").forEach((form) => {
      const inputs: string[] = [];
      form.querySelectorAll("input, select, textarea").forEach((input) => {
        const name = input.getAttribute("name");
        const type = (input.getAttribute("type") || "text").toLowerCase();
        if (name && !["hidden", "submit", "button", "image", "reset"].includes(type)) {
          inputs.push(name);
        }
      });
      forms.push({
        action: form.getAttribute("action") || "",
        method: (form.getAttribute("method") || "GET").toUpperCase(),
        inputs,
      });
    });

    // Also scrape data-href / ng-href / :href attributes (common SPA patterns)
    document.querySelectorAll("[data-href], [ng-href]").forEach((el) => {
      const href = el.getAttribute("data-href") || el.getAttribute("ng-href");
      if (href) hrefs.push(href);
    });

    return { hrefs, scripts, forms };
  }, origin);

  return { ...data, finalUrl };
}

// ── Main crawler ──────────────────────────────────────────────────────────────

export async function crawl(targetUrl: string, options: CrawlOptions = {}): Promise<CrawlResult> {
  const {
    maxPages   = 30,
    maxDepth   = 3,
    timeoutMs  = 15_000,
    concurrency = 2, // Conservative default: each tab ~80-120MB RAM
  } = options;

  let seedUrl: URL;
  try {
    seedUrl = new URL(targetUrl);
  } catch {
    return {
      urls: [],
      urlsWithParams: [],
      forms: [],
      jsFiles: [],
      pagesVisited: 0,
      errors: [`Invalid URL: ${targetUrl}`],
    };
  }

  const origin = seedUrl.origin;
  const seed   = normalise(seedUrl);

  const visited = new Set<string>();
  const queued  = new Set<string>([seed]);
  const allUrls = new Set<string>([seed]);
  const allForms: FormInfo[] = [];
  const allJs    = new Set<string>();
  const errors: string[]     = [];

  const queue: Array<[string, number]> = [[seed, 0]];

  let browser: Browser | null = null;

  try {
    const executablePath = findChromiumExecutable();
    browser = await puppeteer.launch({
      headless: true,
      // Prefer system Chromium (NixOS has correct rpath); fall back to bundled Chrome
      ...(executablePath ? { executablePath } : {}),
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",   // use /tmp instead of /dev/shm
        "--disable-gpu",
        "--no-first-run",
        "--no-zygote",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-sync",
        "--disable-features=VizDisplayCompositor",
        "--mute-audio",
      ],
    });

    // Pre-create pool: one isolated BrowserContext per slot
    const pool     = new PagePool();
    const poolSize = Math.min(concurrency, maxPages);
    const entries: PoolEntry[] = await Promise.all(
      Array.from({ length: poolSize }, () => preparePage(browser!))
    );
    pool.seed(entries);

    // BFS loop
    while (queue.length > 0 && visited.size < maxPages) {
      const batch = queue.splice(0, poolSize).filter(([u]) => !visited.has(u));
      if (batch.length === 0) continue;

      await Promise.all(
        batch.map(async ([pageUrl, depth]) => {
          visited.add(pageUrl);
          const entry = await pool.checkout();
          const { page } = entry;

          try {
            const data = await fetchPageData(page, pageUrl, timeoutMs, origin);
            const baseUrl = new URL(data.finalUrl);

            // Process discovered hrefs
            for (const href of data.hrefs) {
              const resolved = resolveInternal(href, baseUrl, origin);
              if (!resolved) continue;
              const norm = normalise(new URL(resolved));
              allUrls.add(norm);
              if (!queued.has(norm) && depth + 1 <= maxDepth && visited.size + queue.length < maxPages * 2) {
                queued.add(norm);
                queue.push([norm, depth + 1]);
              }
            }

            // Process forms
            for (const f of data.forms) {
              const actionHref = f.action || pageUrl;
              const resolved = resolveInternal(actionHref, baseUrl, origin);
              if (resolved) {
                const norm = normalise(new URL(resolved));
                allUrls.add(norm);
                allForms.push({ action: norm, method: f.method, inputs: f.inputs });
                // Form actions with GET method are injectable targets — queue them
                if (f.method === "GET" && !queued.has(norm)) {
                  queued.add(norm);
                  queue.push([norm, depth + 1]);
                }
              }
            }

            // Process script sources
            for (const src of data.scripts) {
              try {
                allJs.add(new URL(src, baseUrl.href).href);
              } catch {}
            }
          } catch (err: any) {
            errors.push(`${pageUrl}: ${err.message ?? String(err)}`);
          } finally {
            // Navigate to blank to clear page state (context isolation is preserved)
            await page.goto("about:blank").catch(() => {});
            pool.checkin(entry);
          }
        })
      );
    }
  } catch (err: any) {
    errors.push(`Browser launch failed: ${err.message ?? String(err)}`);
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }
  }

  const urlsArray = Array.from(allUrls).sort();
  const urlsWithParams = urlsArray.filter((u) => {
    try { return new URL(u).search.length > 1; } catch { return false; }
  });

  return {
    urls: urlsArray,
    urlsWithParams,
    forms: allForms,
    jsFiles: Array.from(allJs),
    pagesVisited: visited.size,
    errors,
  };
}
