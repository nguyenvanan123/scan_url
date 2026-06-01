import { Router } from "express";
import { db } from "@workspace/db";
import { scansTable } from "@workspace/db";
import { eq, desc } from "drizzle-orm";
import { runScan } from "../lib/scanner";
import { scanRegistry } from "../lib/scan-events";
import type { ScanProgressEvent, ProgressCallback } from "../lib/scan-events";
import {
  CreateScanBody,
  GetScanParams,
  DeleteScanParams,
} from "@workspace/api-zod";

const router = Router();

router.get("/scans/stats", async (req, res) => {
  try {
    const allScans = await db
      .select()
      .from(scansTable)
      .orderBy(desc(scansTable.createdAt));

    const completed = allScans.filter((s) => s.status === "completed");
    const failed = allScans.filter((s) => s.status === "failed");

    let criticalFindings = 0;
    let highFindings = 0;
    let mediumFindings = 0;
    let lowFindings = 0;

    for (const scan of completed) {
      const result = scan.result as any;
      if (result?.summary) {
        criticalFindings += result.summary.critical ?? 0;
        highFindings += result.summary.high ?? 0;
        mediumFindings += result.summary.medium ?? 0;
        lowFindings += result.summary.low ?? 0;
      }
    }

    const recentScans = allScans.slice(0, 5).map((s) => ({
      ...s,
      createdAt: s.createdAt.toISOString(),
      completedAt: s.completedAt?.toISOString() ?? null,
    }));

    res.json({
      totalScans: allScans.length,
      completedScans: completed.length,
      failedScans: failed.length,
      criticalFindings,
      highFindings,
      mediumFindings,
      lowFindings,
      recentScans,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to get scan stats");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/scans", async (req, res) => {
  try {
    const scans = await db
      .select()
      .from(scansTable)
      .orderBy(desc(scansTable.createdAt));

    const mapped = scans.map((s) => ({
      ...s,
      createdAt: s.createdAt.toISOString(),
      completedAt: s.completedAt?.toISOString() ?? null,
    }));

    res.json(mapped);
  } catch (err) {
    req.log.error({ err }, "Failed to list scans");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Real-time Server-Sent Events progress stream ─────────────────────────────
router.get("/scans/:id/events", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id) || id <= 0) {
    res.status(400).json({ error: "Invalid scan ID" });
    return;
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  const sendEvent = (data: ScanProgressEvent) => {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  const emitter = scanRegistry.get(id);
  if (!emitter) {
    sendEvent({ type: "done", status: "not_running" });
    res.end();
    return;
  }

  const keepAlive = setInterval(() => {
    res.write(": ping\n\n");
  }, 20_000);

  const onEvent = (event: ScanProgressEvent) => {
    sendEvent(event);
    if (event.type === "done") {
      clearInterval(keepAlive);
      res.end();
    }
  };

  emitter.on("progress", onEvent);

  req.on("close", () => {
    clearInterval(keepAlive);
    emitter.off("progress", onEvent);
  });
});

// ── POST /scans ───────────────────────────────────────────────────────────────
router.post("/scans", async (req, res) => {
  const parseResult = CreateScanBody.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: "Invalid request body" });
    return;
  }

  const { url, crawl_enabled } = parseResult.data;

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      throw new Error("Must be http or https");
    }
  } catch {
    res.status(400).json({ error: "Invalid URL. Must start with http:// or https://" });
    return;
  }

  let [scan] = await db
    .insert(scansTable)
    .values({ url: parsedUrl.toString(), status: "running" })
    .returning();

  res.status(201).json({
    ...scan,
    createdAt: scan.createdAt.toISOString(),
    completedAt: scan.completedAt?.toISOString() ?? null,
  });

  const emitter = scanRegistry.create(scan.id);
  const onProgress: ProgressCallback = (event) => {
    emitter.emit("progress", event);
  };

  try {
    const result = await runScan(parsedUrl.toString(), crawl_enabled ?? false, onProgress);
    emitter.emit("progress", { type: "done", status: "completed" });
    await db
      .update(scansTable)
      .set({ status: "completed", result, completedAt: new Date() })
      .where(eq(scansTable.id, scan.id));
  } catch (err: any) {
    emitter.emit("progress", { type: "done", status: "failed", error: err.message ?? "Unknown error" });
    await db
      .update(scansTable)
      .set({ status: "failed", errorMessage: err.message ?? "Unknown error", completedAt: new Date() })
      .where(eq(scansTable.id, scan.id));
  } finally {
    setTimeout(() => scanRegistry.delete(scan.id), 5_000);
  }
});

router.get("/scans/:id", async (req, res) => {
  const parseResult = GetScanParams.safeParse({ id: Number(req.params.id) });
  if (!parseResult.success) {
    res.status(400).json({ error: "Invalid scan ID" });
    return;
  }

  try {
    const [scan] = await db
      .select()
      .from(scansTable)
      .where(eq(scansTable.id, parseResult.data.id))
      .limit(1);

    if (!scan) {
      res.status(404).json({ error: "Scan not found" });
      return;
    }

    res.json({
      ...scan,
      createdAt: scan.createdAt.toISOString(),
      completedAt: scan.completedAt?.toISOString() ?? null,
    });
  } catch (err) {
    req.log.error({ err }, "Failed to get scan");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/scans/:id/export", async (req, res) => {
  const id = Number(req.params.id);
  if (!id) { res.status(400).json({ error: "Invalid scan ID" }); return; }

  try {
    const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, id)).limit(1);
    if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
    if (!scan.result) { res.status(400).json({ error: "Scan has no results yet" }); return; }

    const result = scan.result as any;
    const findings: any[] = result.findings ?? [];
    const summary = result.summary ?? {};
    const scannedAt = scan.completedAt?.toISOString() ?? scan.createdAt.toISOString();

    const severityColor: Record<string, string> = {
      critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#6b7280",
    };
    const statusIcon: Record<string, string> = {
      fail: "✗", pass: "✓", warning: "⚠", info: "ℹ",
    };

    const failFindings = findings.filter((f) => f.status !== "pass");
    const passFindings = findings.filter((f) => f.status === "pass");

    const findingHtml = (f: any) => `
      <div class="finding" style="border-left:4px solid ${severityColor[f.severity] ?? "#6b7280"};margin-bottom:12px;padding:12px 16px;background:#1a1a1a;border-radius:0 6px 6px 0">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <span style="color:${severityColor[f.severity] ?? "#6b7280"};font-weight:700;font-size:11px;text-transform:uppercase;font-family:monospace;background:${severityColor[f.severity] ?? "#6b7280"}22;padding:2px 8px;border-radius:4px">${f.severity}</span>
          <span style="font-family:monospace;font-size:13px;color:#e2e8f0;font-weight:600">${f.title}</span>
          <span style="margin-left:auto;color:${f.status === "fail" ? "#ef4444" : f.status === "warning" ? "#eab308" : "#6b7280"};font-size:13px">${statusIcon[f.status] ?? ""}</span>
        </div>
        <p style="color:#94a3b8;font-size:12px;margin:4px 0;line-height:1.6">${f.description ?? ""}</p>
        ${f.detail ? `<pre style="background:#0d0d0d;color:#a0aec0;font-size:11px;padding:8px;border-radius:4px;margin-top:8px;overflow-x:auto;white-space:pre-wrap">${f.detail}</pre>` : ""}
        ${f.recommendation ? `<div style="margin-top:8px;padding:8px 10px;background:#0d2210;border:1px solid #14532d;border-radius:4px;color:#86efac;font-size:11px;font-family:monospace;white-space:pre-wrap">${f.recommendation}</div>` : ""}
      </div>`;

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report — ${scan.url}</title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0a;color:#e2e8f0;margin:0;padding:32px 24px}
  .container{max-width:900px;margin:0 auto}
  h1{font-size:22px;font-weight:700;font-family:monospace;color:#f1f5f9;margin:0 0 4px}
  .meta{font-size:12px;color:#64748b;font-family:monospace;margin-bottom:28px}
  .pills{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:28px}
  .pill{padding:4px 14px;border-radius:20px;font-size:11px;font-weight:700;font-family:monospace;border:1px solid}
  .section-title{font-size:10px;font-family:monospace;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#64748b;margin:24px 0 10px;display:flex;align-items:center;gap:8px}
  .section-title::after{content:"";flex:1;height:1px;background:#1e293b}
  .pass-item{display:flex;align-items:center;gap:10px;padding:8px 14px;background:#0f1a0f;border:1px solid #14532d;border-radius:6px;margin-bottom:6px;font-family:monospace;font-size:12px;color:#86efac}
  footer{margin-top:48px;padding-top:20px;border-top:1px solid #1e293b;font-size:11px;color:#475569;font-family:monospace;text-align:center}
</style>
</head>
<body>
<div class="container">
  <h1>🛡 Security Scan Report</h1>
  <div class="meta">${scan.url} &bull; Scanned ${new Date(scannedAt).toLocaleString()} &bull; Scan #${scan.id}</div>

  <div class="pills">
    ${summary.critical > 0 ? `<span class="pill" style="background:#ef444415;color:#ef4444;border-color:#ef444440">${summary.critical} Critical</span>` : ""}
    ${summary.high > 0     ? `<span class="pill" style="background:#f9731615;color:#f97316;border-color:#f9731640">${summary.high} High</span>` : ""}
    ${summary.medium > 0   ? `<span class="pill" style="background:#eab30815;color:#eab308;border-color:#eab30840">${summary.medium} Medium</span>` : ""}
    ${summary.low > 0      ? `<span class="pill" style="background:#22c55e15;color:#22c55e;border-color:#22c55e40">${summary.low} Low</span>` : ""}
    ${summary.passed > 0   ? `<span class="pill" style="background:#1e293b;color:#64748b;border-color:#334155">${summary.passed} Passed</span>` : ""}
  </div>

  <div class="section-title">Findings (${failFindings.length})</div>
  ${failFindings.length > 0 ? failFindings.map(findingHtml).join("") : "<p style='color:#475569;font-size:13px'>No issues found.</p>"}

  ${passFindings.length > 0 ? `
  <div class="section-title">Passed Checks (${passFindings.length})</div>
  ${passFindings.map((f) => `<div class="pass-item"><span>✓</span><span>${f.title}</span></div>`).join("")}` : ""}

  <footer>Generated by Web Vulnerability Scanner &bull; ${new Date().toUTCString()}</footer>
</div>
</body>
</html>`;

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="scan-${scan.id}-report.html"`);
    res.send(html);
  } catch (err) {
    req.log.error({ err }, "Failed to export scan");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.delete("/scans/:id", async (req, res) => {
  const parseResult = DeleteScanParams.safeParse({ id: Number(req.params.id) });
  if (!parseResult.success) {
    res.status(400).json({ error: "Invalid scan ID" });
    return;
  }

  try {
    await db.delete(scansTable).where(eq(scansTable.id, parseResult.data.id));
    res.status(204).send();
  } catch (err) {
    req.log.error({ err }, "Failed to delete scan");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
