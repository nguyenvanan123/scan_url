/**
 * Web Crawler / Spider
 *
 * Performs a breadth-first crawl of the target domain, discovering:
 *   - All internal hyperlinks  (<a href>)
 *   - Form action endpoints    (<form action>)
 *   - Embedded JS file URLs    (<script src>)
 *   - URLs with query params   (priority targets for injection testing)
 *
 * Uses only Node.js built-ins (no external deps).
 * Respects maxPages and maxDepth to stay fast and targeted.
 */

import https from "https";
import http from "http";
import { URL } from "url";

export interface FormInfo {
  action: string;   // absolute URL of the form endpoint
  method: string;   // "GET" | "POST"
  inputs: string[]; // input/select/textarea name attributes
}

export interface CrawlResult {
  /** All discovered internal URLs (deduplicated, normalised) */
  urls: string[];
  /** Subset of urls that carry query parameters — priority for injection testing */
  urlsWithParams: string[];
  /** Discovered form endpoints */
  forms: FormInfo[];
  /** JS files embedded on crawled pages */
  jsFiles: string[];
  /** How many pages were actually visited */
  pagesVisited: number;
  /** Errors encountered (soft — crawl continues on error) */
  errors: string[];
}

export interface CrawlOptions {
  /** Maximum number of pages to visit (default: 30) */
  maxPages?: number;
  /** Maximum link depth from the seed URL (default: 3) */
  maxDepth?: number;
  /** Request timeout in ms per page (default: 6000) */
  timeoutMs?: number;
  /** Max concurrent fetches (default: 5) */
  concurrency?: number;
}

// ── HTML extraction helpers ──────────────────────────────────────────────────

/** Extract all attribute values for a given attr across all matching tags. */
function extractAttr(html: string, tag: string, attr: string): string[] {
  const results: string[] = [];
  // Match opening tags only, multi-line safe
  const tagRe = new RegExp(`<${tag}[^>]*>`, "gi");
  let tagMatch: RegExpExecArray | null;
  while ((tagMatch = tagRe.exec(html)) !== null) {
    const tagStr = tagMatch[0];
    // Extract attr="..." or attr='...' or attr=... (unquoted)
    const attrRe = new RegExp(`${attr}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i");
    const m = attrRe.exec(tagStr);
    if (m) {
      const val = (m[1] ?? m[2] ?? m[3] ?? "").trim();
      if (val) results.push(val);
    }
  }
  return results;
}

/** Extract <form> details including action, method, and input names. */
function extractForms(html: string): Array<{ action: string; method: string; inputs: string[] }> {
  const forms: Array<{ action: string; method: string; inputs: string[] }> = [];
  const formRe = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
  let fm: RegExpExecArray | null;
  while ((fm = formRe.exec(html)) !== null) {
    const attrs = fm[1];
    const body = fm[2];

    const actionM = /action\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs);
    const methodM = /method\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs);

    const action = (actionM?.[1] ?? actionM?.[2] ?? actionM?.[3] ?? "").trim();
    const method = (methodM?.[1] ?? methodM?.[2] ?? methodM?.[3] ?? "GET").trim().toUpperCase();

    // Extract input/select/textarea names from form body
    const inputRe = /<(?:input|select|textarea)([^>]*)>/gi;
    const inputs: string[] = [];
    let im: RegExpExecArray | null;
    while ((im = inputRe.exec(body)) !== null) {
      const nameM = /name\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(im[1]);
      const typeM = /type\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(im[1]);
      const name = (nameM?.[1] ?? nameM?.[2] ?? nameM?.[3] ?? "").trim();
      const type = (typeM?.[1] ?? typeM?.[2] ?? typeM?.[3] ?? "text").trim().toLowerCase();
      if (name && type !== "hidden" && type !== "submit" && type !== "button" && type !== "image") {
        inputs.push(name);
      }
    }

    if (action) forms.push({ action, method, inputs });
  }
  return forms;
}

// ── URL normalisation ────────────────────────────────────────────────────────

/** Resolve a potentially relative href against a base URL. Returns null if invalid/external. */
function resolveInternal(href: string, base: URL, origin: string): string | null {
  href = href.trim();

  // Skip anchors, javascript, mailto, tel, data
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

    // Only follow same origin
    if (resolved.origin !== origin) return null;

    // Drop fragment
    resolved.hash = "";

    return resolved.href;
  } catch {
    return null;
  }
}

/** Normalise a URL for deduplication (strip trailing slash on path, lowercase host). */
function normalise(url: URL): string {
  const u = new URL(url.href);
  u.hostname = u.hostname.toLowerCase();
  if (u.pathname.length > 1 && u.pathname.endsWith("/")) {
    u.pathname = u.pathname.slice(0, -1);
  }
  u.hash = "";
  return u.href;
}

// ── HTTP fetch (shared with scanner) ────────────────────────────────────────

function fetchPage(url: string, timeoutMs: number): Promise<{ body: string; contentType: string }> {
  return new Promise((resolve, reject) => {
    let parsed: URL;
    try { parsed = new URL(url); } catch (e) { return reject(e); }

    const isHttps = parsed.protocol === "https:";
    const lib = isHttps ? https : http;

    const options: https.RequestOptions = {
      method: "GET",
      host: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        Accept: "text/html,*/*;q=0.8",
      },
      rejectUnauthorized: false,
    };

    const req = lib.request(options, (res) => {
      // Follow one redirect
      if (res.statusCode && [301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        req.destroy();
        fetchPage(res.headers.location, timeoutMs).then(resolve).catch(reject);
        return;
      }

      const contentType = (res.headers["content-type"] ?? "").toLowerCase();

      // Only read HTML pages
      if (!contentType.includes("text/html") && !contentType.includes("application/xhtml")) {
        res.resume();
        return resolve({ body: "", contentType });
      }

      let body = "";
      res.on("data", (chunk) => { if (body.length < 300_000) body += chunk; });
      res.on("end", () => resolve({ body, contentType }));
    });

    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error("Timeout")); });
    req.on("error", reject);
    req.end();
  });
}

// ── Concurrency limiter ──────────────────────────────────────────────────────

async function runWithConcurrency<T>(
  tasks: Array<() => Promise<T>>,
  concurrency: number
): Promise<T[]> {
  const results: T[] = [];
  let idx = 0;

  async function worker() {
    while (idx < tasks.length) {
      const i = idx++;
      results[i] = await tasks[i]();
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, tasks.length) }, worker));
  return results;
}

// ── Main crawler ─────────────────────────────────────────────────────────────

export async function crawl(targetUrl: string, options: CrawlOptions = {}): Promise<CrawlResult> {
  const {
    maxPages   = 30,
    maxDepth   = 3,
    timeoutMs  = 6000,
    concurrency = 5,
  } = options;

  let seedUrl: URL;
  try { seedUrl = new URL(targetUrl); } catch {
    return { urls: [], urlsWithParams: [], forms: [], jsFiles: [], pagesVisited: 0, errors: [`Invalid URL: ${targetUrl}`] };
  }

  const origin = seedUrl.origin;
  const visited = new Set<string>(); // normalised URLs already fetched
  const queued  = new Set<string>(); // normalised URLs already enqueued
  const allUrls  = new Set<string>(); // all discovered internal URLs
  const allForms: FormInfo[] = [];
  const allJsFiles = new Set<string>();
  const errors: string[] = [];

  // BFS queue entries: [url, depth]
  const seed = normalise(seedUrl);
  const queue: Array<[string, number]> = [[seed, 0]];
  queued.add(seed);
  allUrls.add(seed);

  while (queue.length > 0 && visited.size < maxPages) {
    // Take up to `concurrency` items from the queue
    const batch = queue.splice(0, concurrency).filter(([u]) => !visited.has(u));
    if (batch.length === 0) continue;

    const tasks = batch.map(([pageUrl, depth]) => async (): Promise<void> => {
      visited.add(pageUrl);
      try {
        const { body } = await fetchPage(pageUrl, timeoutMs);
        if (!body) return; // non-HTML resource

        const baseUrl = new URL(pageUrl);

        // ── Extract <a href> ──────────────────────────────────────────────
        const hrefs = extractAttr(body, "a", "href");
        for (const href of hrefs) {
          const resolved = resolveInternal(href, baseUrl, origin);
          if (!resolved) continue;

          const normResolved = normalise(new URL(resolved));
          allUrls.add(normResolved);

          if (!queued.has(normResolved) && depth + 1 <= maxDepth && visited.size + queue.length < maxPages * 2) {
            queued.add(normResolved);
            queue.push([normResolved, depth + 1]);
          }
        }

        // ── Extract <form action> ─────────────────────────────────────────
        const rawForms = extractForms(body);
        for (const f of rawForms) {
          const resolvedAction = resolveInternal(f.action || pageUrl, baseUrl, origin);
          if (resolvedAction) {
            const normAction = normalise(new URL(resolvedAction));
            allUrls.add(normAction);
            allForms.push({ action: normAction, method: f.method, inputs: f.inputs });
          }
        }

        // ── Extract <script src> JS files ─────────────────────────────────
        const scripts = extractAttr(body, "script", "src");
        for (const src of scripts) {
          try {
            const resolved = new URL(src, baseUrl.href);
            allJsFiles.add(resolved.href);
          } catch {}
        }

        // ── Extract URLs from inline JS (simple pattern matching) ─────────
        const jsUrlPattern = /['"`](\/([\w/.-]+\?[^'"`\s]+))['"` ]/g;
        let jm: RegExpExecArray | null;
        while ((jm = jsUrlPattern.exec(body)) !== null) {
          try {
            const inlineUrl = new URL(jm[1], baseUrl.href);
            if (inlineUrl.origin === origin) {
              const norm = normalise(inlineUrl);
              allUrls.add(norm);
              if (!queued.has(norm)) {
                queued.add(norm);
                // Only enqueue if it has params (potential injection target)
                if (inlineUrl.searchParams.size > 0 || inlineUrl.search.length > 1) {
                  queue.push([norm, depth + 1]);
                }
              }
            }
          } catch {}
        }
      } catch (err: any) {
        errors.push(`${pageUrl}: ${err.message ?? String(err)}`);
      }
    });

    await runWithConcurrency(tasks, concurrency);
  }

  // Build final result
  const urlsArray = Array.from(allUrls).sort();
  const urlsWithParams = urlsArray.filter((u) => {
    try { return new URL(u).search.length > 1; } catch { return false; }
  });

  return {
    urls: urlsArray,
    urlsWithParams,
    forms: allForms,
    jsFiles: Array.from(allJsFiles),
    pagesVisited: visited.size,
    errors,
  };
}
