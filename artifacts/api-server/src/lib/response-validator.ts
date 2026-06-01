/**
 * ResponseValidator — eliminates false positives before findings are reported.
 *
 * When a server returns HTTP 200 it does not necessarily mean the sensitive
 * resource is genuinely accessible. Many frameworks return a custom 404/error
 * page with status 200 ("soft 404"), or a login-wall HTML page for every path.
 *
 * Each validator function returns a ValidationResult:
 *   isReal   — true  → confirmed vulnerability (report it)
 *              false → false positive (suppress)
 *   reason   — human-readable explanation shown in the finding detail
 *   confidence — "high" | "medium" | "low"
 */

export interface ValidationResult {
  isReal: boolean;
  confidence: "high" | "medium" | "low";
  reason: string;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Returns true when the body looks like an HTML page (common soft-404 signal). */
function looksLikeHtml(body: string): boolean {
  const sample = body.slice(0, 2000).toLowerCase();
  return (
    sample.includes("<!doctype html") ||
    sample.includes("<html") ||
    (sample.includes("<head") && sample.includes("<body"))
  );
}

/** Returns true when the Content-Type header indicates HTML. */
function contentTypeIsHtml(ct: string | undefined): boolean {
  if (!ct) return false;
  return ct.toLowerCase().includes("text/html");
}

/** Count how many lines in body match a pattern (useful for KEY=VALUE density). */
function countMatches(body: string, pattern: RegExp): number {
  return (body.match(pattern) || []).length;
}

// ── Per-file-type validators ──────────────────────────────────────────────────

function validateGitHead(body: string, ct?: string): ValidationResult {
  // Real .git/HEAD always starts with "ref: refs/" or a 40-hex SHA (detached HEAD)
  const trimmed = body.trim();
  const isRealGitHead =
    /^ref:\s+refs\//.test(trimmed) || /^[0-9a-f]{40}\s*$/.test(trimmed);

  if (!isRealGitHead) {
    return {
      isReal: false,
      confidence: "high",
      reason: `Response does not match .git/HEAD format (expected "ref: refs/..." or a 40-char SHA). Likely a soft-404 page.`,
    };
  }
  return {
    isReal: true,
    confidence: "high",
    reason: `Response matches git HEAD format: "${trimmed.slice(0, 60)}"`,
  };
}

function validateGitConfig(body: string, ct?: string): ValidationResult {
  if (looksLikeHtml(body) || contentTypeIsHtml(ct)) {
    return { isReal: false, confidence: "high", reason: "Response is an HTML page — soft-404." };
  }
  const hasCore = /\[core\]/i.test(body);
  const hasRemote = /\[remote\s+"[^"]*"\]/i.test(body);
  const hasRepoVersion = /repositoryformatversion\s*=/i.test(body);
  if (hasCore || hasRemote || hasRepoVersion) {
    return { isReal: true, confidence: "high", reason: "Response contains git config directives ([core], [remote], repositoryformatversion)." };
  }
  return { isReal: false, confidence: "medium", reason: "Response does not contain expected git config sections." };
}

function validateEnvFile(body: string, ct?: string): ValidationResult {
  // Hard disqualifiers
  if (looksLikeHtml(body) || contentTypeIsHtml(ct)) {
    return { isReal: false, confidence: "high", reason: "Response is an HTML page — soft-404 or login redirect." };
  }

  // A genuine .env file must have at least 1 KEY=VALUE line where KEY is
  // all-uppercase letters/digits/underscores and VALUE is anything (including empty).
  const kvLines = countMatches(body, /^[A-Z][A-Z0-9_]+=.*/gm);
  if (kvLines === 0) {
    return {
      isReal: false,
      confidence: "high",
      reason: "No KEY=VALUE lines found. File does not match .env format.",
    };
  }

  // Extra confidence boosters: known env variable names
  const knownKeys = [
    /\bDB_HOST\b/i, /\bDB_USER\b/i, /\bDB_PASS(WORD)?\b/i, /\bDB_NAME\b/i,
    /\bAPP_(KEY|ENV|SECRET|URL)\b/i, /\bSECRET_?KEY\b/i,
    /\bAPI_?KEY\b/i, /\bJWT_?SECRET\b/i, /\bSTRIPE_/i,
    /\bAWS_(ACCESS|SECRET)\b/i, /\bMAIL_(HOST|USER|PASS)\b/i,
  ];
  const boostCount = knownKeys.filter((r) => r.test(body)).length;
  const confidence = boostCount >= 2 ? "high" : boostCount === 1 ? "medium" : "low";

  return {
    isReal: true,
    confidence,
    reason: `Found ${kvLines} KEY=VALUE line(s)${boostCount > 0 ? ` including sensitive keys (${boostCount} known patterns)` : ""}.`,
  };
}

function validateWpConfig(body: string, ct?: string): ValidationResult {
  if (looksLikeHtml(body) || contentTypeIsHtml(ct)) {
    return { isReal: false, confidence: "high", reason: "Response is an HTML page — soft-404." };
  }
  const markers = [/define\(\s*['"]DB_NAME/i, /define\(\s*['"]DB_USER/i, /\$table_prefix/i, /\$wpdb/i];
  const matched = markers.filter((r) => r.test(body)).length;
  if (matched >= 1) {
    return { isReal: true, confidence: matched >= 2 ? "high" : "medium", reason: `Found ${matched} WordPress config marker(s) (DB_NAME, DB_USER, $table_prefix, $wpdb).` };
  }
  return { isReal: false, confidence: "medium", reason: "Response does not contain WordPress config markers." };
}

function validateHtpasswd(body: string, ct?: string): ValidationResult {
  if (looksLikeHtml(body) || contentTypeIsHtml(ct)) {
    return { isReal: false, confidence: "high", reason: "Response is an HTML page." };
  }
  // htpasswd lines: username:$apr1$... or username:{SHA}...
  const hashLine = /^[^:]+:(\$apr1\$|\$2y\$|\{SHA\}|[A-Za-z0-9+/]{13})/m.test(body);
  if (hashLine) {
    return { isReal: true, confidence: "high", reason: "Response contains htpasswd credential hash lines." };
  }
  return { isReal: false, confidence: "medium", reason: "Response does not match htpasswd hash format." };
}

function validateHtaccess(body: string, ct?: string): ValidationResult {
  if (looksLikeHtml(body) || contentTypeIsHtml(ct)) {
    return { isReal: false, confidence: "high", reason: "Response is an HTML page." };
  }
  const directives = [
    /RewriteRule/i, /RewriteCond/i, /RewriteEngine/i,
    /Options\s+[-+]?(Indexes|FollowSymLinks|ExecCGI)/i,
    /AuthType\s+Basic/i, /Require\s+(all|valid-user)/i,
    /^(Allow|Deny)\s+from/im, /Header\s+(set|always)/i,
    /ErrorDocument\s+\d+/i, /RedirectMatch/i,
  ];
  const matched = directives.filter((r) => r.test(body)).length;
  if (matched >= 1) {
    return { isReal: true, confidence: matched >= 3 ? "high" : "medium", reason: `Response contains ${matched} Apache .htaccess directive(s).` };
  }
  return { isReal: false, confidence: "medium", reason: "No recognised Apache directives found." };
}

function validateWebConfig(body: string, ct?: string): ValidationResult {
  if (contentTypeIsHtml(ct) && looksLikeHtml(body)) {
    return { isReal: false, confidence: "high", reason: "Response is an HTML page." };
  }
  const markers = [
    /<configuration>/i, /<system\.web>/i, /<connectionStrings>/i,
    /<appSettings>/i, /<authentication\s+mode/i,
  ];
  const matched = markers.filter((r) => r.test(body)).length;
  if (matched >= 1) {
    return { isReal: true, confidence: matched >= 2 ? "high" : "medium", reason: `Response contains ${matched} IIS/ASP.NET web.config XML element(s).` };
  }
  return { isReal: false, confidence: "medium", reason: "Response does not contain expected web.config XML structure." };
}

function validatePhpinfo(body: string, ct?: string): ValidationResult {
  // phpinfo() always outputs a very distinctive HTML page
  const markers = [/phpinfo\(\)/i, /PHP\s+Version\s+[\d.]+/i, /php\.ini/i, /Configuration File.*php\.ini/i];
  const matched = markers.filter((r) => r.test(body)).length;
  if (matched >= 2) {
    return { isReal: true, confidence: "high", reason: `Response contains ${matched} phpinfo() marker(s).` };
  }
  if (matched === 1) {
    return { isReal: true, confidence: "medium", reason: "Response contains phpinfo() marker." };
  }
  return { isReal: false, confidence: "high", reason: "Response does not contain phpinfo() output markers." };
}

function validateServerStatus(body: string, ct?: string): ValidationResult {
  const markers = [/Apache Server Status/i, /Server uptime:/i, /requests\/sec/i, /Scoreboard Key/i];
  const matched = markers.filter((r) => r.test(body)).length;
  if (matched >= 1) {
    return { isReal: true, confidence: matched >= 2 ? "high" : "medium", reason: `Response contains ${matched} Apache server-status marker(s).` };
  }
  return { isReal: false, confidence: "high", reason: "Response does not contain Apache server-status output." };
}

function validateServerInfo(body: string, ct?: string): ValidationResult {
  const markers = [/Apache Server Information/i, /Loaded Modules/i, /Server Settings/i, /MPM Name/i];
  const matched = markers.filter((r) => r.test(body)).length;
  if (matched >= 1) {
    return { isReal: true, confidence: matched >= 2 ? "high" : "medium", reason: `Response contains ${matched} Apache server-info marker(s).` };
  }
  return { isReal: false, confidence: "high", reason: "Response does not contain Apache server-info output." };
}

function validateSqlDump(body: string, ct?: string): ValidationResult {
  if (contentTypeIsHtml(ct) && looksLikeHtml(body)) {
    return { isReal: false, confidence: "high", reason: "Response is an HTML page — soft-404." };
  }
  const markers = [
    /CREATE\s+TABLE\s+`?\w+`?/i, /INSERT\s+INTO\s+`?\w+`?/i,
    /--\s*MySQL dump/i, /--\s*PostgreSQL database dump/i,
    /DROP\s+TABLE\s+IF\s+EXISTS/i, /LOCK\s+TABLES\s+`?\w+`?/i,
  ];
  const matched = markers.filter((r) => r.test(body)).length;
  if (matched >= 2) {
    return { isReal: true, confidence: "high", reason: `Response contains ${matched} SQL dump keyword(s) (CREATE TABLE, INSERT INTO, etc.).` };
  }
  if (matched === 1) {
    return { isReal: true, confidence: "medium", reason: "Response contains a SQL dump keyword." };
  }
  return { isReal: false, confidence: "medium", reason: "Response does not resemble a SQL dump." };
}

function validateConfigPhp(body: string, ct?: string): ValidationResult {
  if (contentTypeIsHtml(ct) && looksLikeHtml(body)) {
    return { isReal: false, confidence: "high", reason: "Response is an HTML page — PHP was executed and likely returned an error/redirect." };
  }
  // If PHP executed it returns nothing (no output) or a blank page — also a false positive
  if (body.trim().length < 20) {
    return { isReal: false, confidence: "high", reason: "Empty or near-empty response — PHP file executed without output (no information disclosed)." };
  }
  const markers = [/\<\?php/i, /\$[A-Z_]+\s*=/i, /define\(/i, /require(_once)?\(/i];
  const matched = markers.filter((r) => r.test(body)).length;
  if (matched >= 1) {
    return { isReal: true, confidence: "medium", reason: `PHP config source code is exposed (${matched} PHP construct(s) found).` };
  }
  return { isReal: false, confidence: "low", reason: "Response content does not clearly indicate PHP config source code." };
}

function validateConfigYml(body: string, ct?: string): ValidationResult {
  if (looksLikeHtml(body) || contentTypeIsHtml(ct)) {
    return { isReal: false, confidence: "high", reason: "Response is an HTML page." };
  }
  // YAML key: value pattern — at least 2 lines
  const kvLines = countMatches(body, /^[a-z_][a-z0-9_]*\s*:/gim);
  if (kvLines >= 2) {
    const sensitive = /password|secret|key|token|credential|database|host|user/i.test(body);
    return {
      isReal: true,
      confidence: sensitive ? "high" : "medium",
      reason: `Response contains ${kvLines} YAML key: value line(s)${sensitive ? " including potentially sensitive keys" : ""}.`,
    };
  }
  return { isReal: false, confidence: "medium", reason: `Only ${kvLines} YAML key: value line(s) found — does not clearly indicate a config file.` };
}

function validateConfigJson(body: string, ct?: string): ValidationResult {
  if (looksLikeHtml(body)) {
    return { isReal: false, confidence: "high", reason: "Response is an HTML page." };
  }
  try {
    const obj = JSON.parse(body.trim());
    if (typeof obj === "object" && obj !== null && Object.keys(obj).length > 0) {
      const sensitive = /password|secret|key|token|credential|database|host|user/i.test(JSON.stringify(obj));
      return {
        isReal: true,
        confidence: sensitive ? "high" : "medium",
        reason: `Valid JSON object with ${Object.keys(obj).length} top-level key(s)${sensitive ? " including potentially sensitive keys" : ""}.`,
      };
    }
  } catch {}
  return { isReal: false, confidence: "medium", reason: "Response is not valid JSON or is an empty object." };
}

function validateDsStore(body: string, ct?: string): ValidationResult {
  // .DS_Store files start with a specific magic byte sequence (0x00 0x00 0x00 0x01 0x42 0x75 0x64 0x31)
  // In string form this appears as non-printable chars. Check for binary content or "Bud1" marker.
  if (body.includes("Bud1") || /\0/.test(body.slice(0, 50))) {
    return { isReal: true, confidence: "high", reason: "Response contains .DS_Store binary magic bytes (Bud1 marker)." };
  }
  if (looksLikeHtml(body)) {
    return { isReal: false, confidence: "high", reason: "Response is an HTML page." };
  }
  // Binary content without HTML is suspicious enough
  const nonPrintable = (body.slice(0, 200).match(/[\x00-\x08\x0e-\x1f\x7f-\xff]/g) || []).length;
  if (nonPrintable > 10) {
    return { isReal: true, confidence: "medium", reason: "Response contains binary content consistent with .DS_Store file." };
  }
  return { isReal: false, confidence: "low", reason: "Response does not match .DS_Store binary format." };
}

function validateCrossdomain(body: string, ct?: string): ValidationResult {
  if (/<cross-domain-policy>/i.test(body)) {
    const wildcard = /allow-access-from\s+domain=["']\*["']/i.test(body);
    return {
      isReal: true,
      confidence: "high",
      reason: wildcard
        ? "crossdomain.xml is present with wildcard allow-access-from domain='*' — full cross-origin access permitted."
        : "crossdomain.xml is present.",
    };
  }
  return { isReal: false, confidence: "high", reason: "Response does not contain <cross-domain-policy> element." };
}

function validateElmah(body: string, ct?: string): ValidationResult {
  const markers = [/ELMAH\s*-\s*Error/i, /Error\s+Log\s+for/i, /Application:/i];
  if (markers.some((r) => r.test(body))) {
    return { isReal: true, confidence: "high", reason: "ELMAH error log viewer is accessible and displaying error entries." };
  }
  return { isReal: false, confidence: "high", reason: "Response does not contain ELMAH error log content." };
}

function validateTraceAxd(body: string, ct?: string): ValidationResult {
  const markers = [/Application\s+Trace/i, /Request\s+Details/i, /Trace\s+Information/i];
  if (markers.some((r) => r.test(body))) {
    return { isReal: true, confidence: "high", reason: "ASP.NET trace viewer is accessible." };
  }
  return { isReal: false, confidence: "high", reason: "Response does not contain ASP.NET trace output." };
}

// ── SQL Injection validator ───────────────────────────────────────────────────

/**
 * Secondary validation for SQL injection findings.
 * Confirms that the matched error text is not just part of static page content
 * (e.g., a help page explaining SQL syntax) rather than a live database error.
 */
export function validateSqlInjection(
  matchedPattern: string,
  body: string,
  payload: string
): ValidationResult {
  // The error must appear close to where the payload would be reflected
  // or be a clear server-side stack trace / exception message.

  // Disqualify: error only appears in a comment or documentation block
  const errorIdx = body.toLowerCase().indexOf(matchedPattern.toLowerCase());
  if (errorIdx === -1) {
    return { isReal: false, confidence: "high", reason: "Matched error pattern not found in body at validation time." };
  }

  // Context window around the match
  const ctx = body.slice(Math.max(0, errorIdx - 200), errorIdx + 400).toLowerCase();

  // If the context contains strong stack-trace or DB error indicators, high confidence
  const stackTraceSignals = [
    /exception|stack\s*trace|traceback|at\s+\w+\.\w+\(/i,
    /fatal\s+error|parse\s+error|warning:/i,
    /line\s+\d+|file\s*:.*\.php/i,
  ];
  const isStackTrace = stackTraceSignals.some((r) => r.test(ctx));
  if (isStackTrace) {
    return { isReal: true, confidence: "high", reason: "SQL error accompanied by stack trace or server exception details." };
  }

  // If it's inside a code block / pre on a documentation page, lower confidence
  const isDocumentation = /<(code|pre|kbd|samp)/i.test(
    body.slice(Math.max(0, errorIdx - 100), errorIdx + 100)
  );
  if (isDocumentation) {
    return {
      isReal: false,
      confidence: "medium",
      reason: "SQL error keyword found inside a <code>/<pre> block — likely documentation, not a live error.",
    };
  }

  return {
    isReal: true,
    confidence: "medium",
    reason: "SQL error keyword matched in response body.",
  };
}

// ── XSS validator ─────────────────────────────────────────────────────────────

/**
 * Confirms that a reflected XSS payload is genuinely unescaped in the HTML,
 * not just present as an HTML-encoded string.
 */
export function validateXssReflection(payload: string, body: string): ValidationResult {
  // Check the payload appears literally (not encoded)
  if (!body.includes(payload)) {
    return { isReal: false, confidence: "high", reason: "Payload not found verbatim in response — may have been encoded server-side." };
  }

  // Check it is NOT in a comment or script src attribute pointing elsewhere
  const idx = body.indexOf(payload);
  const ctx = body.slice(Math.max(0, idx - 150), idx + payload.length + 150);

  // HTML-encoded version of the payload — if this is what actually appears, it's not exploitable
  const encoded = payload
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");

  if (body.includes(encoded)) {
    // Both encoded and raw versions present — raw wins (still exploitable)
    return { isReal: true, confidence: "medium", reason: "Payload found raw in response (HTML-encoded version also present but raw takes precedence)." };
  }

  // Verify it appears in a context where script execution would occur
  const inScriptBlock = /<script[^>]*>.*$/is.test(ctx);
  const inEventHandler = /on\w+\s*=\s*["']?[^"'>]*$/i.test(ctx);
  const isTag = /<[a-z]/i.test(ctx);

  if (inScriptBlock || inEventHandler || isTag) {
    return { isReal: true, confidence: "high", reason: "Payload reflected in executable HTML context (script block, event handler, or tag)." };
  }

  return { isReal: true, confidence: "medium", reason: "Payload reflected verbatim in HTML response body." };
}

// ── Main dispatcher ───────────────────────────────────────────────────────────

/**
 * Validate a sensitive file finding.
 *
 * @param path         The URL path that was probed (e.g. "/.git/HEAD")
 * @param statusCode   The HTTP status code received
 * @param contentType  The Content-Type response header value (may be undefined)
 * @param body         The response body (first ~50 KB)
 * @returns            ValidationResult
 */
export function validateSensitiveFile(
  path: string,
  statusCode: number,
  contentType: string | undefined,
  body: string
): ValidationResult {
  // Any non-200/206 should not have reached the validator, but guard anyway
  if (statusCode !== 200 && statusCode !== 206) {
    return { isReal: false, confidence: "high", reason: `HTTP ${statusCode} — not accessible.` };
  }

  // Empty body → nothing was actually exposed
  if (body.trim().length === 0) {
    return { isReal: false, confidence: "high", reason: "Response body is empty — nothing was disclosed." };
  }

  const p = path.toLowerCase();

  if (p === "/.git/head")            return validateGitHead(body, contentType);
  if (p === "/.git/config")          return validateGitConfig(body, contentType);
  if (p.startsWith("/.env"))         return validateEnvFile(body, contentType);
  if (p === "/wp-config.php")        return validateWpConfig(body, contentType);
  if (p === "/.htpasswd")            return validateHtpasswd(body, contentType);
  if (p === "/.htaccess")            return validateHtaccess(body, contentType);
  if (p === "/web.config")           return validateWebConfig(body, contentType);
  if (p === "/phpinfo.php")          return validatePhpinfo(body, contentType);
  if (p === "/server-status")        return validateServerStatus(body, contentType);
  if (p === "/server-info")          return validateServerInfo(body, contentType);
  if (p === "/config.php")           return validateConfigPhp(body, contentType);
  if (p === "/config.yml")           return validateConfigYml(body, contentType);
  if (p === "/config.json")          return validateConfigJson(body, contentType);
  if (p.endsWith(".sql"))            return validateSqlDump(body, contentType);
  if (p === "/.ds_store")            return validateDsStore(body, contentType);
  if (p === "/crossdomain.xml")      return validateCrossdomain(body, contentType);
  if (p === "/elmah.axd")            return validateElmah(body, contentType);
  if (p === "/trace.axd")            return validateTraceAxd(body, contentType);

  // Generic fallback: if it looks like HTML it's probably a soft-404
  if (looksLikeHtml(body) || contentTypeIsHtml(contentType)) {
    return {
      isReal: false,
      confidence: "medium",
      reason: "Response appears to be an HTML page (possible soft-404 or authentication redirect).",
    };
  }

  return {
    isReal: true,
    confidence: "low",
    reason: "File returned HTTP 200 with non-HTML content — manual verification recommended.",
  };
}
