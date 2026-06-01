import https from "https";
import http from "http";
import dns from "dns/promises";
import { URL } from "url";

export interface ScanFinding {
  id: string;
  category: "dns" | "ssl" | "headers" | "server_info" | "content_discovery" | "http_methods" | "sensitive_files" | "injection";
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  status: "pass" | "fail" | "warning" | "info";
  description: string;
  detail?: string | null;
  recommendation?: string | null;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  passed: number;
}

export interface ScanResult {
  findings: ScanFinding[];
  summary: ScanSummary;
  responseTimeMs: number;
  serverInfo?: string | null;
  ipAddress?: string | null;
  sslValid?: boolean | null;
  sslExpiry?: string | null;
  scannedAt: string;
}

interface FetchResult {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  responseTimeMs: number;
  sslValid?: boolean;
  sslExpiry?: string | null;
}

function fetchUrl(targetUrl: string, method = "GET", timeout = 10000): Promise<FetchResult> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const isHttps = parsed.protocol === "https:";
    const lib = isHttps ? https : http;
    const start = Date.now();

    const options: https.RequestOptions = {
      method,
      host: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        Accept: "text/html,application/xhtml+xml,*/*",
      },
      rejectUnauthorized: false,
    };

    const req = lib.request(options, (res) => {
      let body = "";
      res.on("data", (chunk) => {
        if (body.length < 50000) body += chunk;
      });
      res.on("end", () => {
        const headers: Record<string, string | string[] | undefined> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          headers[k.toLowerCase()] = v;
        }

        let sslValid: boolean | undefined;
        let sslExpiry: string | null = null;

        if (isHttps) {
          const socket = (res.socket as any);
          try {
            const cert = socket?.getPeerCertificate?.();
            if (cert && cert.valid_to) {
              sslExpiry = cert.valid_to;
              sslValid = new Date(cert.valid_to) > new Date();
            } else {
              sslValid = true;
            }
          } catch {
            sslValid = true;
          }
        }

        resolve({
          statusCode: res.statusCode ?? 0,
          headers,
          body,
          responseTimeMs: Date.now() - start,
          sslValid,
          sslExpiry,
        });
      });
    });

    req.setTimeout(timeout, () => {
      req.destroy();
      reject(new Error("Request timed out"));
    });

    req.on("error", reject);
    req.end();
  });
}

function headerStr(val: string | string[] | undefined): string | undefined {
  if (!val) return undefined;
  if (Array.isArray(val)) return val.join(", ");
  return val;
}

function checkSecurityHeaders(headers: Record<string, string | string[] | undefined>): ScanFinding[] {
  const findings: ScanFinding[] = [];

  const hsts = headerStr(headers["strict-transport-security"]);
  if (!hsts) {
    findings.push({
      id: "missing-hsts",
      category: "headers",
      title: "Missing Strict-Transport-Security (HSTS)",
      severity: "medium",
      status: "fail",
      description: "The Strict-Transport-Security header is not set. Without HSTS, browsers may connect over HTTP, exposing users to downgrade attacks.",
      recommendation: 'Set: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    });
  } else {
    findings.push({
      id: "hsts-present",
      category: "headers",
      title: "Strict-Transport-Security (HSTS)",
      severity: "info",
      status: "pass",
      description: "HSTS header is configured.",
      detail: hsts,
    });
  }

  const xfo = headerStr(headers["x-frame-options"]);
  if (!xfo) {
    findings.push({
      id: "missing-xfo",
      category: "headers",
      title: "Missing X-Frame-Options",
      severity: "medium",
      status: "fail",
      description: "The X-Frame-Options header is missing. This may expose the site to clickjacking attacks where it is embedded in a malicious iframe.",
      recommendation: "Set: X-Frame-Options: DENY or SAMEORIGIN",
    });
  } else {
    findings.push({
      id: "xfo-present",
      category: "headers",
      title: "X-Frame-Options",
      severity: "info",
      status: "pass",
      description: "Clickjacking protection header is set.",
      detail: xfo,
    });
  }

  const csp = headerStr(headers["content-security-policy"]);
  if (!csp) {
    findings.push({
      id: "missing-csp",
      category: "headers",
      title: "Missing Content-Security-Policy",
      severity: "high",
      status: "fail",
      description: "No Content-Security-Policy header found. CSP is the primary defense against XSS (Cross-Site Scripting) attacks.",
      recommendation: "Implement a strict CSP. Start with: Content-Security-Policy: default-src 'self'",
    });
  } else {
    const unsafeInline = csp.includes("'unsafe-inline'");
    const unsafeEval = csp.includes("'unsafe-eval'");
    if (unsafeInline || unsafeEval) {
      findings.push({
        id: "weak-csp",
        category: "headers",
        title: "Weak Content-Security-Policy",
        severity: "medium",
        status: "warning",
        description: `CSP is present but uses ${[unsafeInline && "'unsafe-inline'", unsafeEval && "'unsafe-eval'"].filter(Boolean).join(" and ")}, which weakens XSS protection.`,
        detail: csp.slice(0, 200),
        recommendation: "Remove 'unsafe-inline' and 'unsafe-eval' directives and use nonces or hashes instead.",
      });
    } else {
      findings.push({
        id: "csp-present",
        category: "headers",
        title: "Content-Security-Policy",
        severity: "info",
        status: "pass",
        description: "CSP header is configured.",
        detail: csp.slice(0, 200),
      });
    }
  }

  const xcto = headerStr(headers["x-content-type-options"]);
  if (!xcto || xcto.toLowerCase() !== "nosniff") {
    findings.push({
      id: "missing-xcto",
      category: "headers",
      title: "Missing X-Content-Type-Options",
      severity: "low",
      status: "fail",
      description: "X-Content-Type-Options: nosniff is not set. Without it, browsers may MIME-sniff responses away from declared content types.",
      recommendation: "Set: X-Content-Type-Options: nosniff",
    });
  } else {
    findings.push({
      id: "xcto-present",
      category: "headers",
      title: "X-Content-Type-Options",
      severity: "info",
      status: "pass",
      description: "MIME-type sniffing protection is enabled.",
    });
  }

  const rp = headerStr(headers["referrer-policy"]);
  if (!rp) {
    findings.push({
      id: "missing-rp",
      category: "headers",
      title: "Missing Referrer-Policy",
      severity: "low",
      status: "warning",
      description: "No Referrer-Policy header set. Without it, the browser's default may leak full URLs in the Referer header to third parties.",
      recommendation: "Set: Referrer-Policy: strict-origin-when-cross-origin",
    });
  } else {
    findings.push({
      id: "rp-present",
      category: "headers",
      title: "Referrer-Policy",
      severity: "info",
      status: "pass",
      description: "Referrer-Policy is configured.",
      detail: rp,
    });
  }

  const pp = headerStr(headers["permissions-policy"]) || headerStr(headers["feature-policy"]);
  if (!pp) {
    findings.push({
      id: "missing-pp",
      category: "headers",
      title: "Missing Permissions-Policy",
      severity: "info",
      status: "info",
      description: "Permissions-Policy (formerly Feature-Policy) header is not set. This header lets you control browser feature access (camera, microphone, geolocation).",
      recommendation: "Consider setting: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    });
  } else {
    findings.push({
      id: "pp-present",
      category: "headers",
      title: "Permissions-Policy",
      severity: "info",
      status: "pass",
      description: "Permissions-Policy header is configured.",
      detail: pp.slice(0, 150),
    });
  }

  return findings;
}

function checkServerInfo(headers: Record<string, string | string[] | undefined>): ScanFinding[] {
  const findings: ScanFinding[] = [];

  const server = headerStr(headers["server"]);
  if (server) {
    const exposesVersion = /[\d.]{2,}/.test(server) || /nginx\/|apache\/|iis\/|express\//i.test(server);
    findings.push({
      id: "server-header",
      category: "server_info",
      title: exposesVersion ? "Server Version Disclosure" : "Server Header Present",
      severity: exposesVersion ? "low" : "info",
      status: exposesVersion ? "warning" : "info",
      description: exposesVersion
        ? "The Server header reveals the web server software and version. Attackers use this to identify known vulnerabilities for that version."
        : "The Server header is present but does not disclose version information.",
      detail: server,
      recommendation: exposesVersion
        ? "Configure your web server to remove or obfuscate the Server header. Remove version information."
        : undefined,
    });
  } else {
    findings.push({
      id: "server-hidden",
      category: "server_info",
      title: "Server Header Hidden",
      severity: "info",
      status: "pass",
      description: "Server header is not present, preventing software/version disclosure.",
    });
  }

  const xpow = headerStr(headers["x-powered-by"]);
  if (xpow) {
    findings.push({
      id: "x-powered-by",
      category: "server_info",
      title: "X-Powered-By Header Exposed",
      severity: "low",
      status: "warning",
      description: "The X-Powered-By header reveals the server-side technology (e.g., PHP, Express, ASP.NET), helping attackers target known vulnerabilities.",
      detail: xpow,
      recommendation: "Remove the X-Powered-By header. In Express: app.disable('x-powered-by'). In PHP: expose_php = Off",
    });
  } else {
    findings.push({
      id: "x-powered-by-hidden",
      category: "server_info",
      title: "X-Powered-By Hidden",
      severity: "info",
      status: "pass",
      description: "X-Powered-By header is not present.",
    });
  }

  const via = headerStr(headers["via"]);
  if (via) {
    findings.push({
      id: "via-header",
      category: "server_info",
      title: "Via Header Exposes Proxy Info",
      severity: "info",
      status: "info",
      description: "The Via header is present, indicating a proxy or load balancer and its version.",
      detail: via,
    });
  }

  return findings;
}

async function checkDns(hostname: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];

  try {
    const addresses = await dns.resolve4(hostname);
    findings.push({
      id: "dns-a-records",
      category: "dns",
      title: "DNS A Records",
      severity: "info",
      status: "info",
      description: `Found ${addresses.length} IPv4 address(es) for this hostname.`,
      detail: addresses.join(", "),
    });
  } catch {
    findings.push({
      id: "dns-no-a",
      category: "dns",
      title: "No DNS A Records Found",
      severity: "high",
      status: "fail",
      description: "Could not resolve IPv4 address for this hostname. The domain may not exist or DNS is misconfigured.",
    });
  }

  try {
    const mx = await dns.resolveMx(hostname);
    if (mx.length > 0) {
      findings.push({
        id: "dns-mx",
        category: "dns",
        title: "Mail Servers (MX Records)",
        severity: "info",
        status: "info",
        description: `Found ${mx.length} MX record(s). Email infrastructure is publicly discoverable.`,
        detail: mx.map((r) => `${r.exchange} (priority: ${r.priority})`).join(", "),
      });
    }
  } catch {}

  try {
    const ns = await dns.resolveNs(hostname);
    if (ns.length > 0) {
      findings.push({
        id: "dns-ns",
        category: "dns",
        title: "Nameservers (NS Records)",
        severity: "info",
        status: "info",
        description: `Domain uses ${ns.length} nameserver(s). Nameserver software/provider is publicly discoverable.`,
        detail: ns.join(", "),
      });
    }
  } catch {}

  try {
    const txt = await dns.resolveTxt(hostname);
    const hasSPF = txt.some((r) => r.join("").toLowerCase().startsWith("v=spf1"));
    const hasDMARC = txt.some((r) => r.join("").toLowerCase().includes("v=dmarc1"));
    if (hasSPF) {
      findings.push({
        id: "spf-present",
        category: "dns",
        title: "SPF Record Present",
        severity: "info",
        status: "pass",
        description: "An SPF (Sender Policy Framework) record exists, helping prevent email spoofing.",
        detail: txt.find((r) => r.join("").toLowerCase().startsWith("v=spf1"))?.join(""),
      });
    } else {
      findings.push({
        id: "spf-missing",
        category: "dns",
        title: "Missing SPF Record",
        severity: "medium",
        status: "warning",
        description: "No SPF record found. Without SPF, malicious actors can send email impersonating your domain.",
        recommendation: "Add a TXT record: v=spf1 include:your-mail-provider.com ~all",
      });
    }

    if (!hasDMARC) {
      findings.push({
        id: "dmarc-missing",
        category: "dns",
        title: "Missing DMARC Record",
        severity: "medium",
        status: "warning",
        description: "No DMARC policy found. DMARC protects against email spoofing by specifying what to do with unauthenticated emails.",
        recommendation: "Add a TXT record on _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
      });
    } else {
      findings.push({
        id: "dmarc-present",
        category: "dns",
        title: "DMARC Policy Present",
        severity: "info",
        status: "pass",
        description: "DMARC policy is configured, protecting against email spoofing.",
      });
    }
  } catch {}

  return findings;
}

async function checkSsl(url: string, fetchResult: FetchResult): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const parsed = new URL(url);

  if (parsed.protocol === "http:") {
    findings.push({
      id: "no-https",
      category: "ssl",
      title: "Site Not Using HTTPS",
      severity: "critical",
      status: "fail",
      description: "The target URL uses plain HTTP, meaning all data is transmitted unencrypted. Credentials, session cookies, and personal data are exposed.",
      recommendation: "Migrate to HTTPS. Obtain a free TLS certificate from Let's Encrypt.",
    });
    return findings;
  }

  if (fetchResult.sslValid !== undefined) {
    if (fetchResult.sslValid) {
      findings.push({
        id: "ssl-valid",
        category: "ssl",
        title: "Valid SSL/TLS Certificate",
        severity: "info",
        status: "pass",
        description: "The SSL/TLS certificate is valid and not expired.",
        detail: fetchResult.sslExpiry ? `Expires: ${fetchResult.sslExpiry}` : undefined,
      });

      if (fetchResult.sslExpiry) {
        const expiry = new Date(fetchResult.sslExpiry);
        const daysLeft = Math.floor((expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
        if (daysLeft < 30) {
          findings.push({
            id: "ssl-expiry-soon",
            category: "ssl",
            title: "SSL Certificate Expiring Soon",
            severity: daysLeft < 7 ? "critical" : "high",
            status: "warning",
            description: `SSL certificate expires in ${daysLeft} day(s). If it expires, browsers will show security warnings and block access.`,
            detail: `Expiry: ${fetchResult.sslExpiry}`,
            recommendation: "Renew the certificate immediately. Consider enabling auto-renewal.",
          });
        }
      }
    } else {
      findings.push({
        id: "ssl-invalid",
        category: "ssl",
        title: "Invalid or Expired SSL Certificate",
        severity: "critical",
        status: "fail",
        description: "The SSL certificate is invalid or expired. Browsers will block access and users will see security warnings.",
        detail: fetchResult.sslExpiry ? `Certificate expiry: ${fetchResult.sslExpiry}` : undefined,
        recommendation: "Renew your SSL certificate immediately.",
      });
    }
  }

  return findings;
}

async function checkContentDiscovery(baseUrl: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const parsed = new URL(baseUrl);
  const base = `${parsed.protocol}//${parsed.host}`;

  const paths = [
    { path: "/robots.txt", name: "robots.txt" },
    { path: "/sitemap.xml", name: "sitemap.xml" },
    { path: "/.well-known/security.txt", name: "security.txt" },
  ];

  for (const { path, name } of paths) {
    try {
      const result = await fetchUrl(base + path, "GET", 5000);
      if (result.statusCode === 200) {
        if (name === "robots.txt") {
          const disallowed = (result.body.match(/Disallow:.+/g) || []).map((l) => l.replace("Disallow:", "").trim()).filter(Boolean);
          findings.push({
            id: "robots-txt",
            category: "content_discovery",
            title: "robots.txt Found",
            severity: "info",
            status: "info",
            description: `robots.txt is accessible and lists ${disallowed.length} disallowed path(s). This file reveals directory structure to search engines and attackers.`,
            detail: disallowed.length ? `Disallowed paths: ${disallowed.slice(0, 5).join(", ")}` : undefined,
          });
        } else if (name === "sitemap.xml") {
          findings.push({
            id: "sitemap-xml",
            category: "content_discovery",
            title: "sitemap.xml Found",
            severity: "info",
            status: "info",
            description: "sitemap.xml is publicly accessible, exposing the full URL structure of the website.",
          });
        } else if (name === "security.txt") {
          findings.push({
            id: "security-txt",
            category: "content_discovery",
            title: "security.txt Present",
            severity: "info",
            status: "pass",
            description: "A security.txt file is present, providing contact information for security researchers to report vulnerabilities.",
          });
        }
      } else if (name === "security.txt") {
        findings.push({
          id: "security-txt-missing",
          category: "content_discovery",
          title: "No security.txt Found",
          severity: "info",
          status: "info",
          description: "No security.txt file found. This optional file (RFC 9116) provides a standard way for security researchers to report vulnerabilities.",
          recommendation: "Create /.well-known/security.txt with contact and policy information.",
        });
      }
    } catch {}
  }

  return findings;
}

async function checkHttpMethods(baseUrl: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];

  const dangerousMethods = ["TRACE", "OPTIONS"];

  for (const method of dangerousMethods) {
    try {
      const result = await fetchUrl(baseUrl, method, 5000);
      if (method === "TRACE" && result.statusCode === 200) {
        findings.push({
          id: "trace-enabled",
          category: "http_methods",
          title: "HTTP TRACE Method Enabled",
          severity: "medium",
          status: "fail",
          description: "The TRACE method is enabled. It can be used in Cross-Site Tracing (XST) attacks to steal cookies, bypassing HttpOnly protection.",
          recommendation: "Disable the TRACE method on your web server.",
        });
      } else if (method === "OPTIONS") {
        const allow = headerStr(result.headers["allow"]) || headerStr(result.headers["public"]);
        if (allow) {
          const allowedMethods = allow.toUpperCase();
          const hasDelete = allowedMethods.includes("DELETE");
          const hasPut = allowedMethods.includes("PUT");
          findings.push({
            id: "options-methods",
            category: "http_methods",
            title: "HTTP Methods via OPTIONS",
            severity: hasDelete || hasPut ? "low" : "info",
            status: hasDelete || hasPut ? "warning" : "info",
            description: `Server advertises the following HTTP methods: ${allow}`,
            detail: allow,
            recommendation: hasDelete || hasPut
              ? "Verify that DELETE and PUT methods are intentionally exposed and protected by authentication."
              : undefined,
          });
        }
      }
    } catch {}
  }

  if (!findings.some((f) => f.id === "trace-enabled")) {
    findings.push({
      id: "trace-disabled",
      category: "http_methods",
      title: "HTTP TRACE Method Disabled",
      severity: "info",
      status: "pass",
      description: "TRACE method is not enabled, preventing Cross-Site Tracing attacks.",
    });
  }

  return findings;
}

// ── Sensitive Files ──────────────────────────────────────────────────────────

const SENSITIVE_PATHS: Array<{ path: string; label: string; severity: ScanFinding["severity"]; why: string }> = [
  { path: "/.git/HEAD",         label: ".git/HEAD",       severity: "critical", why: "Git repository metadata is publicly accessible, potentially exposing source code history, credentials, and internal logic." },
  { path: "/.git/config",       label: ".git/config",     severity: "critical", why: "Git config can reveal remote URLs, author details, and repository structure." },
  { path: "/.env",              label: ".env",            severity: "critical", why: "Environment file may contain database credentials, API keys, and other secrets in plain text." },
  { path: "/.env.local",        label: ".env.local",      severity: "critical", why: "Local environment override file may contain secrets not intended for production." },
  { path: "/.env.production",   label: ".env.production", severity: "critical", why: "Production environment file may expose database credentials and API keys." },
  { path: "/wp-config.php",     label: "wp-config.php",   severity: "critical", why: "WordPress configuration file contains database host, name, username, and password." },
  { path: "/.htpasswd",         label: ".htpasswd",       severity: "high",     why: "Exposes hashed credentials for HTTP Basic Authentication — attackers can attempt offline dictionary attacks." },
  { path: "/.htaccess",         label: ".htaccess",       severity: "medium",   why: "Reveals server configuration rules such as rewrites, redirects, access restrictions, and custom error pages." },
  { path: "/web.config",        label: "web.config",      severity: "high",     why: "IIS configuration file can contain connection strings, authentication settings, and custom error details." },
  { path: "/phpinfo.php",       label: "phpinfo.php",     severity: "high",     why: "PHP info page exposes server configuration, loaded modules, environment variables, and PHP version." },
  { path: "/server-status",     label: "server-status",   severity: "medium",   why: "Apache server-status page discloses active requests, clients, and server uptime." },
  { path: "/server-info",       label: "server-info",     severity: "medium",   why: "Apache server-info page reveals installed modules and configuration directives." },
  { path: "/config.php",        label: "config.php",      severity: "high",     why: "Application config file may expose database credentials and internal settings." },
  { path: "/config.yml",        label: "config.yml",      severity: "high",     why: "YAML config file may contain secrets, database credentials, or service API keys." },
  { path: "/config.json",       label: "config.json",     severity: "medium",   why: "JSON configuration file may reveal application settings and internal structure." },
  { path: "/backup.sql",        label: "backup.sql",      severity: "critical", why: "A database dump file is directly accessible — contains all table structure and data." },
  { path: "/dump.sql",          label: "dump.sql",        severity: "critical", why: "A database dump file is directly accessible — contains all table structure and data." },
  { path: "/database.sql",      label: "database.sql",    severity: "critical", why: "A database export file is directly accessible." },
  { path: "/.DS_Store",         label: ".DS_Store",       severity: "low",      why: "macOS metadata file reveals directory structure and file names on the server." },
  { path: "/crossdomain.xml",   label: "crossdomain.xml", severity: "low",      why: "Flash cross-domain policy file — if misconfigured (allow-access-from domain='*'), allows any Flash app to read responses." },
  { path: "/elmah.axd",         label: "elmah.axd",       severity: "high",     why: "ASP.NET error log viewer is publicly accessible, exposing stack traces, server paths, and potential credentials." },
  { path: "/trace.axd",         label: "trace.axd",       severity: "medium",   why: "ASP.NET trace viewer exposes request/response details and internal data flows." },
];

async function checkSensitiveFiles(baseUrl: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const parsed = new URL(baseUrl);
  const base = `${parsed.protocol}//${parsed.host}`;

  const results = await Promise.allSettled(
    SENSITIVE_PATHS.map(async ({ path, label, severity, why }) => {
      try {
        const res = await fetchUrl(base + path, "GET", 5000);
        if (res.statusCode === 200 || res.statusCode === 206) {
          const snippet = res.body.slice(0, 300).trim();
          return { label, severity, why, path, snippet, found: true };
        }
      } catch {}
      return { found: false };
    })
  );

  let foundCount = 0;
  for (const r of results) {
    if (r.status === "fulfilled" && r.value.found) {
      const { label, severity, why, path, snippet } = r.value as any;
      foundCount++;
      findings.push({
        id: `sensitive-${label.replace(/[^a-z0-9]/gi, "-")}`,
        category: "sensitive_files",
        title: `Sensitive File Exposed: ${label}`,
        severity,
        status: "fail",
        description: why,
        detail: snippet ? `Path: ${path}\nPreview: ${snippet}` : `Path: ${path}`,
        recommendation:
          severity === "critical"
            ? `Immediately block access to ${path} via your web server config. Remove any sensitive files from the web root. For .git/, add 'location /.git { deny all; }' (nginx) or 'RedirectMatch 404 /\\.git' (Apache). Rotate all credentials that may have been exposed.`
            : `Block public access to ${path} in your web server or firewall rules. Verify this file is not required to be publicly accessible.`,
      });
    }
  }

  if (foundCount === 0) {
    findings.push({
      id: "sensitive-files-none",
      category: "sensitive_files",
      title: "No Sensitive Files Exposed",
      severity: "info",
      status: "pass",
      description: `Checked ${SENSITIVE_PATHS.length} common sensitive paths — none returned HTTP 200.`,
    });
  }

  return findings;
}

// ── SQL Injection ─────────────────────────────────────────────────────────────

const SQL_PAYLOADS = ["'", '"', "' OR '1'='1", `" OR "1"="1`, "1 AND 1=2", "' OR 1=1--", "';--"];

const SQL_ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i,
  /MySQL.*SQL syntax/i,
  /Warning.*mysql_/i,
  /valid MySQL result/i,
  /MySqlClient\./i,
  /PostgreSQL.*ERROR/i,
  /ERROR.*PostgreSQL/i,
  /org\.postgresql\.util\.PSQLException/i,
  /ORA-\d{4,}/i,
  /Oracle error/i,
  /SQLite.*error/i,
  /sqlite3\.OperationalError/i,
  /\[Microsoft\]\[ODBC SQL Server Driver\]/i,
  /\[SQL Server\]/i,
  /Unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /com\.microsoft\.sqlserver\.jdbc/i,
  /Syntax error.*in query/i,
  /SQLSTATE\[\w+\]/i,
  /PDOException/i,
  /Query failed:/i,
];

async function checkSqlInjection(targetUrl: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const parsed = new URL(targetUrl);
  const params = Array.from(parsed.searchParams.keys());

  if (params.length === 0) {
    findings.push({
      id: "sqli-no-params",
      category: "injection",
      title: "SQL Injection — No Query Parameters Found",
      severity: "info",
      status: "info",
      description: "The target URL has no query parameters to test for SQL injection. To test form inputs or API endpoints, provide a URL with query parameters (e.g. https://example.com/search?q=test).",
    });
    return findings;
  }

  const vulnerableParams: string[] = [];
  const evidenceMap: Record<string, string> = {};

  for (const param of params) {
    for (const payload of SQL_PAYLOADS) {
      try {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(param, payload);
        const res = await fetchUrl(testUrl.toString(), "GET", 6000);
        const body = res.body;

        for (const pattern of SQL_ERROR_PATTERNS) {
          const match = pattern.exec(body);
          if (match) {
            if (!vulnerableParams.includes(param)) {
              vulnerableParams.push(param);
              const start = Math.max(0, match.index - 40);
              evidenceMap[param] = `Payload: ${payload}\nError snippet: ...${body.slice(start, start + 200)}...`;
            }
            break;
          }
        }
      } catch {}
      if (vulnerableParams.includes(param)) break;
    }
  }

  if (vulnerableParams.length > 0) {
    findings.push({
      id: "sqli-reflected-error",
      category: "injection",
      title: "SQL Injection — Error-Based Reflected SQLi Detected",
      severity: "critical",
      status: "fail",
      description: `The server returned database error messages in response to SQL injection payloads in parameter(s): ${vulnerableParams.join(", ")}. This confirms the input is being passed to a SQL query without proper sanitisation. An attacker can extract, modify, or delete database content, and potentially achieve remote code execution.`,
      detail: Object.entries(evidenceMap).map(([p, e]) => `Parameter: ${p}\n${e}`).join("\n\n"),
      recommendation: "1. Use parameterised queries (prepared statements) — never concatenate user input into SQL strings.\n2. Use an ORM with built-in escaping.\n3. Enforce least-privilege database accounts (read-only where possible).\n4. Disable detailed database error messages in production — log errors server-side only.\n5. Apply WAF rules to block common SQLi patterns.",
    });
  } else {
    findings.push({
      id: "sqli-not-detected",
      category: "injection",
      title: "SQL Injection — No Error-Based SQLi Detected",
      severity: "info",
      status: "pass",
      description: `Tested ${params.length} parameter(s) with ${SQL_PAYLOADS.length} payloads each. No SQL error patterns were detected in responses. Note: this tests only error-based SQLi — blind/time-based SQLi requires deeper testing.`,
      detail: `Parameters tested: ${params.join(", ")}`,
    });
  }

  return findings;
}

// ── XSS (Reflected) ───────────────────────────────────────────────────────────

const XSS_PAYLOADS = [
  "<script>alert(1)</script>",
  `"><script>alert(1)</script>`,
  `'><script>alert(1)</script>`,
  `"><img src=x onerror=alert(1)>`,
  `<svg onload=alert(1)>`,
  `javascript:alert(1)`,
];

// Patterns that indicate the payload was reflected unescaped in HTML
const XSS_REFLECT_PATTERNS = [
  /<script>alert\(1\)<\/script>/i,
  /"><script>alert\(1\)<\/script>/i,
  /'><script>alert\(1\)<\/script>/i,
  /"><img src=x onerror=alert\(1\)>/i,
  /<svg onload=alert\(1\)>/i,
  /javascript:alert\(1\)/i,
];

async function checkXss(targetUrl: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const parsed = new URL(targetUrl);
  const params = Array.from(parsed.searchParams.keys());

  if (params.length === 0) {
    findings.push({
      id: "xss-no-params",
      category: "injection",
      title: "Reflected XSS — No Query Parameters Found",
      severity: "info",
      status: "info",
      description: "The target URL has no query parameters to test for reflected XSS. Provide a URL with query parameters (e.g. https://example.com/search?q=test) to enable this check.",
    });
    return findings;
  }

  const vulnerableParams: string[] = [];
  const evidenceMap: Record<string, string> = {};

  for (const param of params) {
    for (let i = 0; i < XSS_PAYLOADS.length; i++) {
      const payload = XSS_PAYLOADS[i];
      const pattern = XSS_REFLECT_PATTERNS[i];
      try {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(param, payload);
        const res = await fetchUrl(testUrl.toString(), "GET", 6000);

        const contentType = headerStr(res.headers["content-type"]) ?? "";
        if (!contentType.includes("html")) continue;

        if (pattern.test(res.body)) {
          if (!vulnerableParams.includes(param)) {
            vulnerableParams.push(param);
            const match = pattern.exec(res.body)!;
            const start = Math.max(0, match.index - 60);
            evidenceMap[param] = `Payload: ${payload}\nReflected in response:\n...${res.body.slice(start, start + 250)}...`;
          }
          break;
        }
      } catch {}
      if (vulnerableParams.includes(param)) break;
    }
  }

  if (vulnerableParams.length > 0) {
    findings.push({
      id: "xss-reflected",
      category: "injection",
      title: "Reflected XSS — Payload Reflected Unescaped in HTML",
      severity: "high",
      status: "fail",
      description: `XSS payloads were reflected verbatim in the HTML response for parameter(s): ${vulnerableParams.join(", ")}. An attacker can craft a malicious URL that, when visited by a victim, executes arbitrary JavaScript in the victim's browser — enabling cookie theft, session hijacking, and phishing.`,
      detail: Object.entries(evidenceMap).map(([p, e]) => `Parameter: ${p}\n${e}`).join("\n\n"),
      recommendation: "1. HTML-encode all user-supplied values before rendering in HTML (e.g. replace < with &lt;, > with &gt;, \" with &quot;).\n2. Use a context-aware template engine that auto-escapes output (React JSX, Jinja2 autoescape, etc.).\n3. Set a strict Content-Security-Policy header to block inline script execution.\n4. Set X-XSS-Protection: 1; mode=block (legacy browsers).\n5. Validate and whitelist input server-side — reject or sanitise unexpected characters.",
    });
  } else {
    findings.push({
      id: "xss-not-reflected",
      category: "injection",
      title: "Reflected XSS — No Unescaped Reflection Detected",
      severity: "info",
      status: "pass",
      description: `Tested ${params.length} parameter(s) with ${XSS_PAYLOADS.length} XSS payloads each. No payload was reflected unescaped in the HTML response. Note: this covers reflected XSS only — stored and DOM-based XSS require separate testing.`,
      detail: `Parameters tested: ${params.join(", ")}`,
    });
  }

  return findings;
}

export async function runScan(targetUrl: string): Promise<ScanResult> {
  const parsed = new URL(targetUrl);
  const hostname = parsed.hostname;

  let mainFetch: FetchResult;
  try {
    mainFetch = await fetchUrl(targetUrl, "GET", 12000);
  } catch (err: any) {
    throw new Error(`Failed to connect to ${targetUrl}: ${err.message}`);
  }

  let ipAddress: string | null = null;
  try {
    const addrs = await dns.resolve4(hostname);
    ipAddress = addrs[0] ?? null;
  } catch {}

  const [dnsFindings, sslFindings, contentFindings, httpMethodFindings, sensitiveFileFindings, sqliFindings, xssFindings] = await Promise.all([
    checkDns(hostname),
    checkSsl(targetUrl, mainFetch),
    checkContentDiscovery(targetUrl),
    checkHttpMethods(targetUrl),
    checkSensitiveFiles(targetUrl),
    checkSqlInjection(targetUrl),
    checkXss(targetUrl),
  ]);

  const headerFindings = checkSecurityHeaders(mainFetch.headers);
  const serverFindings = checkServerInfo(mainFetch.headers);

  const allFindings = [
    ...dnsFindings,
    ...sslFindings,
    ...headerFindings,
    ...serverFindings,
    ...contentFindings,
    ...httpMethodFindings,
    ...sensitiveFileFindings,
    ...sqliFindings,
    ...xssFindings,
  ];

  const summary: ScanSummary = {
    total: allFindings.length,
    critical: allFindings.filter((f) => f.severity === "critical" && f.status !== "pass").length,
    high: allFindings.filter((f) => f.severity === "high" && f.status !== "pass").length,
    medium: allFindings.filter((f) => f.severity === "medium" && f.status !== "pass").length,
    low: allFindings.filter((f) => f.severity === "low" && f.status !== "pass").length,
    info: allFindings.filter((f) => f.severity === "info").length,
    passed: allFindings.filter((f) => f.status === "pass").length,
  };

  return {
    findings: allFindings,
    summary,
    responseTimeMs: mainFetch.responseTimeMs,
    serverInfo: headerStr(mainFetch.headers["server"]) ?? null,
    ipAddress,
    sslValid: mainFetch.sslValid ?? null,
    sslExpiry: mainFetch.sslExpiry ?? null,
    scannedAt: new Date().toISOString(),
  };
}
