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
- `artifacts/vuln-scanner/src/` — React frontend

## Architecture decisions

- The scan runs synchronously on the backend: the POST /scans endpoint inserts a record with `status: running`, responds with 201 immediately, then continues scanning in the background and updates the record. The frontend polls the scan detail endpoint until status = completed.
- All scanner checks use Node.js built-ins (`dns/promises`, `https`, `http`) — no external scanning libraries required, keeping the dependency footprint small and the tool safe for personal use.
- Results are stored as JSONB in PostgreSQL — flexible schema for findings without needing separate tables per check type.
- Security headers, DNS records, SSL cert info, server info leakage, content discovery (robots.txt, sitemap, security.txt), and HTTP methods are all checked in parallel via `Promise.all`.

## Product

- Paste a URL and click Scan — the tool checks DNS records, SSL certificate validity, HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), server information leakage, content discovery (robots.txt, sitemap.xml, security.txt), and HTTP methods (TRACE).
- Results are displayed grouped by category with severity badges (critical/high/medium/low/info) and pass/fail/warning status.
- Each finding includes a description and actionable remediation recommendation.
- Scan history is stored and accessible at any time.

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

- Scans can take 10-15 seconds depending on target response time. The frontend polls `/api/scans/:id` to reflect live status.
- The scanner uses `rejectUnauthorized: false` to check SSL cert details even on expired/invalid certs — this is intentional for inspection purposes, not a security issue in the scanner itself.
- Always run `pnpm --filter @workspace/api-spec run codegen` after any changes to `lib/api-spec/openapi.yaml`, then `pnpm run typecheck:libs` to rebuild lib declarations.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
