---
name: Puppeteer on NixOS (Replit)
description: How to run Puppeteer in this NixOS Replit environment — system Chromium required.
---

# Puppeteer on NixOS (Replit)

## The rule
The puppeteer-downloaded Chrome binary (`~/.cache/puppeteer/chrome/...`) cannot run on Replit's NixOS — all its required `.so` libs are missing from standard paths.

## Fix
1. Install `chromium` as a system dependency (`installSystemDependencies({ packages: ["chromium"] })`).
2. At runtime, call `execSync('which chromium')` to find the NixOS Chromium path (e.g. `/nix/store/.../bin/chromium`).
3. Pass it as `executablePath` to `puppeteer.launch()`.
4. Keep `puppeteer` (not `puppeteer-core`) in dependencies — it still provides the Node.js API; just override the executable.

**Why:** NixOS doesn't put shared libraries in `/lib` or `/usr/lib`. The bundled Chrome expects standard Linux paths. The system `chromium` nix package comes pre-patched with correct rpaths and a wrapper script.

**How to apply:** Any new code that uses `puppeteer.launch()` must pass `executablePath` from a `which chromium` lookup. See `artifacts/api-server/src/lib/crawler.ts` → `findChromiumExecutable()`.
