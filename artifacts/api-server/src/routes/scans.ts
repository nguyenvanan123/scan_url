import { Router } from "express";
import { db } from "@workspace/db";
import { scansTable } from "@workspace/db";
import { eq, desc, sql } from "drizzle-orm";
import { runScan } from "../lib/scanner";
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

router.post("/scans", async (req, res) => {
  const parseResult = CreateScanBody.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: "Invalid request body" });
    return;
  }

  const { url } = parseResult.data;

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

  try {
    const result = await runScan(parsedUrl.toString());
    await db
      .update(scansTable)
      .set({ status: "completed", result, completedAt: new Date() })
      .where(eq(scansTable.id, scan.id));
  } catch (err: any) {
    await db
      .update(scansTable)
      .set({ status: "failed", errorMessage: err.message ?? "Unknown error", completedAt: new Date() })
      .where(eq(scansTable.id, scan.id));
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
