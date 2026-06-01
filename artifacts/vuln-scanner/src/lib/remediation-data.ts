/**
 * Client-side remediation lookup table.
 * Keys are finding IDs (or prefix roots for injection findings).
 * Values are technology-specific code snippet objects.
 *
 * This mirrors the backend REMEDIATION_MAP so that historical scans
 * (run before the structured remediations field was added) still
 * display smart tabs in the UI.
 */

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

const h = (header: string, value: string): RemediationMap => ({
  nginx:  `# In your nginx server{} block\nadd_header ${header} "${value}" always;`,
  apache: `# In httpd.conf / .htaccess (requires mod_headers)\nHeader always set ${header} "${value}"`,
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
  caddy: `# In your Caddyfile site block\nheader ${header} "${value}"`,
});

export const CLIENT_REMEDIATION_MAP: Record<string, RemediationMap> = {
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
  if (req.secure) {
    res.setHeader('Strict-Transport-Security',
      'max-age=31536000; includeSubDomains; preload');
  }
  next();
});`,
    iis: h("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload").iis!,
    caddy: h("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload").caddy!,
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
    defaultSrc:     ["'self'"],
    scriptSrc:      ["'self'"],
    styleSrc:       ["'self'", "'unsafe-inline'"],
    imgSrc:         ["'self'", "data:"],
    fontSrc:        ["'self'"],
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
    caddy: `header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';"`,
    cloudflare:
`# Cloudflare Transform Rules → Modify Response Header
# Rules → Transform Rules → Create Rule → Modify Response Header
# Action: Set  |  Name: Content-Security-Policy
# Value: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';
#
# Note: Test thoroughly — overly strict CSP policies can break your site.
# Use report-only mode first: Content-Security-Policy-Report-Only`,
  },

  "missing-x-frame-options": {
    ...h("X-Frame-Options", "SAMEORIGIN"),
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
    ...h("X-Content-Type-Options", "nosniff"),
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
    ...h("Referrer-Policy", "strict-origin-when-cross-origin"),
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
    ...h("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
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
# Simply use your domain name:
example.com {
  # Your site config here — Caddy auto-provisions TLS via Let's Encrypt
}`,
    cloudflare:
`# In Cloudflare Dashboard → SSL/TLS → Edge Certificates:
# 1. Set SSL/TLS Mode to "Full (strict)"
# 2. Enable "Always Use HTTPS" toggle
# 3. Enable "HSTS" with max-age=31536000, includeSubDomains, preload
# 4. Enable "Automatic HTTPS Rewrites"

# Via Terraform (Cloudflare provider):
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

# Or strip it in Apache (httpd.conf):
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
    caddy: `header -X-Powered-By`,
  },

  "trace-enabled": {
    nginx:
`# Deny TRACE method globally
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
    return res.status(405)
      .set('Allow', 'GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD')
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
`# Add an SPF TXT record in Cloudflare Dashboard → DNS:
Type:    TXT
Name:    @  (root domain)
Content: v=spf1 include:_spf.google.com ~all
TTL:     Auto

# Common mail provider includes:
# Google Workspace: include:_spf.google.com
# Microsoft 365:    include:spf.protection.outlook.com
# SendGrid:         include:sendgrid.net`,
    nginx:
`# SPF is a DNS record — configure at your DNS provider, not your web server.
# Example TXT record:
@ IN TXT "v=spf1 include:_spf.google.com ~all"`,
    apache:
`# SPF is a DNS record — configure at your DNS provider, not Apache.
# Example TXT record:
@ IN TXT "v=spf1 include:_spf.google.com ~all"`,
    nodejs:
`// SPF is a DNS record. Add via infrastructure-as-code (AWS Route 53 / Terraform):
resource "aws_route53_record" "spf" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "@"
  type    = "TXT"
  ttl     = 300
  records = ["v=spf1 include:_spf.google.com ~all"]
}`,
  },

  "missing-dmarc": {
    cloudflare:
`# Add a DMARC TXT record in Cloudflare Dashboard → DNS:
Type:    TXT
Name:    _dmarc
Content: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; adkim=s; aspf=s
TTL:     Auto

# Policy values: none (monitor only) → quarantine → reject (strictest)
# Start with p=none to monitor, then ramp up.`,
    nginx:
`# DMARC is a DNS record — add via your DNS provider.
# Example:
_dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"

# Policy guide:
# p=none       — monitoring only
# p=quarantine — suspect mail goes to spam
# p=reject     — fail outright (most protective)`,
    apache:
`# DMARC is a DNS record — add via your DNS provider, not Apache.
_dmarc IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; adkim=s; aspf=s"`,
    nodejs:
`// DMARC is a DNS record. Add via Terraform (Route 53):
resource "aws_route53_record" "dmarc" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "_dmarc"
  type    = "TXT"
  ttl     = 300
  records = ["v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"]
}`,
  },

  // ── Injection: SQL injection ─────────────────────────────────────────────────
  "injection-sqli": {
    nodejs:
`// NEVER interpolate user input into SQL — use parameterized queries.
import { Pool } from 'pg';
const pool = new Pool();

// ✓ Safe — parameter sent separately
const { rows } = await pool.query(
  'SELECT * FROM users WHERE id = $1 AND name = $2',
  [userId, userName]
);

// ✗ UNSAFE — do NOT do this:
// pool.query(\`SELECT * FROM users WHERE id = \${userId}\`);`,
    php:
`<?php
// Use PDO prepared statements — NEVER concat user input into SQL.
$pdo = new PDO('mysql:host=localhost;dbname=mydb', $user, $pass);
$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false); // important!

// ✓ Safe
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id AND name = :name');
$stmt->execute([':id' => $id, ':name' => $name]);
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

// ✗ UNSAFE:
// $pdo->query("SELECT * FROM users WHERE id = $id");`,
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
`// Use PreparedStatement — NEVER use Statement with string concatenation.
String sql = "SELECT * FROM users WHERE id = ? AND name = ?";
try (PreparedStatement stmt = conn.prepareStatement(sql)) {
    stmt.setInt(1, userId);
    stmt.setString(2, userName);
    ResultSet rs = stmt.executeQuery();
}

// Spring Data JPA (safest — parameterized automatically):
@Query("SELECT u FROM User u WHERE u.id = :id")
User findById(@Param("id") Long id);`,
    ruby:
`# ActiveRecord parameterizes queries automatically.
# ✓ Safe
User.where(id: user_id, name: user_name)
User.where('id = ? AND name = ?', user_id, user_name)

# ✗ UNSAFE:
# User.where("id = #{user_id}")   # string interpolation = SQL injection`,
  },

  // ── Injection: XSS ──────────────────────────────────────────────────────────
  "injection-xss": {
    nodejs:
`// Always encode output. Use a template engine with auto-escaping.

// React JSX is safe by default (JSX escapes values automatically):
const UserInput = ({ text }: { text: string }) => <div>{text}</div>; // ✓ Safe

// Avoid dangerouslySetInnerHTML unless you sanitize first:
import DOMPurify from 'dompurify';
// <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(dirty) }} />

// In Express with EJS — use <%= %> (escaped) not <%- %> (raw):
// res.render('page', { userInput });

// Set Content-Type to prevent MIME-sniffing XSS:
res.setHeader('Content-Type', 'application/json');
res.setHeader('X-Content-Type-Options', 'nosniff');`,
    php:
`<?php
// Always use htmlspecialchars() for output in HTML context.
// ✓ Safe
echo htmlspecialchars($userInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');

// With Twig template engine (auto-escapes by default):
// {{ user_input }}          — escaped (safe)
// {{ user_input | raw }}    — raw (only when you control the content)

// For rich HTML content, use HTML Purifier:
require_once '/path/to/htmlpurifier/library/HTMLPurifier.auto.php';
$config  = HTMLPurifier_Config::createDefault();
$purifier = new HTMLPurifier($config);
$clean   = $purifier->purify($dirty);`,
    python:
`# Django templates auto-escape all variables by default.
# {{ user_input }}        — auto-escaped (safe)
# {{ user_input|safe }}   — raw (only use when you control the content)

# For manual escaping:
from django.utils.html import escape, format_html
safe_output = escape(user_input)

# Jinja2 — enable autoescape:
from jinja2 import Environment
env = Environment(autoescape=True)

# For rich HTML — use bleach:
import bleach
clean = bleach.clean(user_input, tags=['b', 'i', 'u'], strip=True)`,
    java:
`// Use OWASP Java Encoder for all output encoding.
import org.owasp.encoder.Encode;

// HTML context:
out.print("<div>" + Encode.forHtml(userInput) + "</div>");

// Spring Thymeleaf (auto-escapes by default):
// th:text="\${userInput}"    — escaped (safe)
// th:utext="\${userInput}"   — raw (avoid unless pre-sanitized)`,
    ruby:
`# Rails ERB auto-escapes by default.
# <%= user_input %>       — auto-escaped (safe)
# <%== user_input %>      — raw HTML (avoid unless sanitized)

# For sanitizing HTML content:
ActionView::Base.sanitized_allowed_tags = ['b', 'i', 'strong', 'em']
sanitized = ActionController::Base.helpers.sanitize(user_input)

# Use rails-html-sanitizer for fine-grained control:
sanitizer = Rails::Html::SafeListSanitizer.new
safe = sanitizer.sanitize(user_input, tags: %w[b i ul li])`,
  },
};

// Alias stored XSS to the same table as reflected XSS
CLIENT_REMEDIATION_MAP["injection-stored-xss"] = CLIENT_REMEDIATION_MAP["injection-xss"];

/**
 * Returns structured remediations for a finding by ID and category.
 * Matches exact ID first, then falls back to prefix matching for injection findings.
 */
export function getClientRemediations(id: string, category: string): RemediationMap | null {
  if (CLIENT_REMEDIATION_MAP[id]) return CLIENT_REMEDIATION_MAP[id];
  // Injection prefix matching
  if (category === "injection") {
    if (id.includes("sqli"))        return CLIENT_REMEDIATION_MAP["injection-sqli"] ?? null;
    if (id.includes("stored"))      return CLIENT_REMEDIATION_MAP["injection-stored-xss"] ?? null;
    if (id.includes("xss"))         return CLIENT_REMEDIATION_MAP["injection-xss"] ?? null;
  }
  return null;
}
