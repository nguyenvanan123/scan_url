# Web Vulnerability Scanner

A personal web security scanner that lets you audit your own websites for common vulnerabilities and misconfigurations.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 8080)
- `pnpm --filter @workspace/vuln-scanner run dev` — run the frontend (port 19593)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- Frontend: React + Vite, TailwindCSS, TanStack Query, Wouter
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `lib/api-spec/openapi.yaml` — single source of truth for all API contracts
- `lib/db/src/schema/scans.ts` — database schema (scans table)
- `artifacts/api-server/src/lib/scanner.ts` — core scanning engine
- `artifacts/api-server/src/routes/scans.ts` — scan API routes
- `artifacts/api-server/src/routes/exploit.ts` — Exploit Playground backend (SSE streams, header audit, LFI probe, SQLi probe, XSS injection, session injection)
- `artifacts/vuln-scanner/src/pages/exploit-playground.tsx` — Exploit Playground frontend
- `artifacts/vuln-scanner/src/` — React frontend

## Architecture decisions

- The scan runs synchronously on the backend: the POST /scans endpoint inserts a record with `status: running`, responds with 201 immediately, then continues scanning in the background and updates the record. The frontend polls the scan detail endpoint until status = completed.
- All scanner checks use Node.js built-ins (`dns/promises`, `https`, `http`) — no external scanning libraries required, keeping the dependency footprint small and the tool safe for personal use.
- Results are stored as JSONB in PostgreSQL — flexible schema for findings without needing separate tables per check type.
- Security headers, DNS records, SSL cert info, server info leakage, content discovery (robots.txt, sitemap.xml, security.txt), and HTTP methods are all checked in parallel via `Promise.all`.
- Exploit Playground uses SSE (`text/event-stream`) for live streaming of per-payload network logs — the frontend opens an `EventSource` and each HTTP probe result is pushed as a JSON event in real time.
- All `/api/exploit/*` routes (except `/config`) are guarded by an optional `EXPLOIT_TOKEN` env var. If set, requests must pass `?token=` or `Authorization: Bearer`. Private/loopback IPs are blocked via `isPrivateHost()` to prevent SSRF.
- Puppeteer is used in the Exploit Playground for XSS token injection and session capture — pages are launched with `evaluateOnNewDocument` fingerprint masking (UA, webdriver flag, plugins, canvas noise).

## Product

### Scanner
- Paste a URL and click Scan — the tool checks DNS records, SSL certificate validity, HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), server information leakage, content discovery (robots.txt, sitemap.xml, security.txt), and HTTP methods (TRACE).
- Results are displayed grouped by category with severity badges (critical/high/medium/low/info) and pass/fail/warning status.
- Each finding includes a description and actionable remediation recommendation.
- Scan history is stored and accessible at any time.

### Exploit Playground
- **SQLi Probe** — SSE stream: fires error-based and time-based payloads + obfuscated mutations; each request logs `[HTTP status|ms] phase » payload ← finding` in real time.
- **LFI / Path Traversal Probe** — SSE stream: tests 16 traversal sequences (Unix + Windows, plain + URL-encoded + double-encoded) against a query parameter; flags any response that leaks `/etc/passwd` or similar.
- **Sensitive File Fetch** — directly fetches exposed files (`.env`, `wp-config.php`, etc.) and shows first 10 lines with sensitive values redacted.
- **Clickjacking Simulator** — overlays an invisible iframe over a decoy UI; includes a **Live Header Audit** that fetches real response headers and reports X-Frame-Options, CSP `frame-ancestors`, HSTS, and CORS misconfiguration.
- **XSS Token Injection** — launches a Puppeteer page with fingerprint masking to harvest cookies, localStorage tokens, and DOM secrets from a target URL.
- **Session Injection** — replays a captured session cookie in a headless browser and streams a C2-style log of what the injected session can access.

## Chạy local (macOS / Windows / Linux)

Để xem bot tự động hoạt động trực quan với cửa sổ trình duyệt thật, chạy dự án trên máy cục bộ:

### Bước 1 — Cài tools cần thiết

```bash
# Cài pnpm nếu chưa có
npm install -g pnpm

# macOS: cài PostgreSQL qua Homebrew
brew install postgresql@16
brew services start postgresql@16
createdb vuln_scanner

# Ubuntu/Debian
sudo apt install postgresql postgresql-contrib
sudo -u postgres createdb vuln_scanner

# Windows: tải installer tại https://www.postgresql.org/download/windows/
```

> **Không cần cài Chrome/Chromium** — Puppeteer tự đi kèm bản Chromium riêng khi chạy `pnpm install`.

### Bước 2 — Setup project

```bash
# Giải nén .zip, vào thư mục
cd vuln-scanner-project
pnpm install

# Tạo file .env ở root
DATABASE_URL=postgresql://localhost:5432/vuln_scanner
PUPPETEER_HEADLESS=false   # kích hoạt headed mode — cửa sổ trình duyệt sẽ hiện ra màn hình

# Tạo bảng DB
pnpm --filter @workspace/db run push
```

### Bước 3 — Chạy 2 terminal song song

```bash
# Terminal 1: API backend (port 8080)
pnpm --filter @workspace/api-server run dev

# Terminal 2: Frontend (port 19593)
pnpm --filter @workspace/vuln-scanner run dev
```

### Bước 4 — Mở trình duyệt

```
http://localhost:19593
```

Khi bấm **🤖 Run Automation** trong SandboxViewer, một cửa sổ **Chromium thực tế** sẽ tự bật lên — tự điều hướng đến target, tự gõ từng ký tự vào form đăng nhập với delay ngẫu nhiên như người thật, stream log realtime về C2 Terminal panel trong dashboard.

---

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

- Scans can take 10-15 seconds depending on target response time. The frontend polls `/api/scans/:id` to reflect live status.
- The scanner uses `rejectUnauthorized: false` to check SSL cert details even on expired/invalid certs — this is intentional for inspection purposes, not a security issue in the scanner itself.
- Always run `pnpm --filter @workspace/api-spec run codegen` after any changes to `lib/api-spec/openapi.yaml`, then `pnpm run typecheck:libs` to rebuild lib declarations.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
