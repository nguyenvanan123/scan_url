import { Router } from "express";
import { db, schedulesTable, scansTable } from "@workspace/db";
import { eq, lte, and } from "drizzle-orm";
import { runScan } from "../lib/scanner.js";
import { logger } from "../lib/logger.js";

const router = Router();

router.get("/schedules", async (req, res) => {
  try {
    const schedules = await db.select().from(schedulesTable).orderBy(schedulesTable.createdAt);
    res.json(
      schedules.map((s) => ({
        ...s,
        lastRunAt: s.lastRunAt?.toISOString() ?? null,
        nextRunAt: s.nextRunAt.toISOString(),
        createdAt: s.createdAt.toISOString(),
      })),
    );
  } catch (err) {
    req.log.error({ err }, "Failed to list schedules");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/schedules", async (req, res) => {
  const { url, intervalHours = 24 } = req.body as { url?: string; intervalHours?: number };
  if (!url || typeof url !== "string") {
    res.status(400).json({ error: "url is required" });
    return;
  }
  try { new URL(url); } catch { res.status(400).json({ error: "Invalid URL" }); return; }

  const hours = Math.max(1, Math.min(168, Number(intervalHours) || 24));
  const nextRunAt = new Date(Date.now() + hours * 3600 * 1000);

  try {
    const [schedule] = await db
      .insert(schedulesTable)
      .values({ url, intervalHours: hours, nextRunAt })
      .returning();
    res.status(201).json({
      ...schedule,
      lastRunAt: null,
      nextRunAt: schedule.nextRunAt.toISOString(),
      createdAt: schedule.createdAt.toISOString(),
    });
  } catch (err) {
    req.log.error({ err }, "Failed to create schedule");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.delete("/schedules/:id", async (req, res) => {
  const id = Number(req.params.id);
  if (!id) { res.status(400).json({ error: "Invalid ID" }); return; }
  try {
    await db.delete(schedulesTable).where(eq(schedulesTable.id, id));
    res.status(204).send();
  } catch (err) {
    req.log.error({ err }, "Failed to delete schedule");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.patch("/schedules/:id/toggle", async (req, res) => {
  const id = Number(req.params.id);
  if (!id) { res.status(400).json({ error: "Invalid ID" }); return; }
  try {
    const [s] = await db.select().from(schedulesTable).where(eq(schedulesTable.id, id)).limit(1);
    if (!s) { res.status(404).json({ error: "Not found" }); return; }
    const [updated] = await db
      .update(schedulesTable)
      .set({ enabled: !s.enabled })
      .where(eq(schedulesTable.id, id))
      .returning();
    res.json({
      ...updated,
      lastRunAt: updated.lastRunAt?.toISOString() ?? null,
      nextRunAt: updated.nextRunAt.toISOString(),
      createdAt: updated.createdAt.toISOString(),
    });
  } catch (err) {
    req.log.error({ err }, "Failed to toggle schedule");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Background cron runner ────────────────────────────────────────────────────

export function startScheduler(): void {
  logger.info("Scheduled scan runner started — polling every 60 s");

  const tick = async () => {
    try {
      const now = new Date();
      const due = await db
        .select()
        .from(schedulesTable)
        .where(and(eq(schedulesTable.enabled, true), lte(schedulesTable.nextRunAt, now)));

      for (const schedule of due) {
        logger.info({ url: schedule.url }, "Running scheduled scan");

        const [scan] = await db
          .insert(scansTable)
          .values({ url: schedule.url, status: "running" })
          .returning();

        const nextRun = new Date(Date.now() + schedule.intervalHours * 3600 * 1000);
        await db
          .update(schedulesTable)
          .set({ lastRunAt: now, nextRunAt: nextRun })
          .where(eq(schedulesTable.id, schedule.id));

        runScan(schedule.url, false)
          .then(async (result) => {
            await db
              .update(scansTable)
              .set({ status: "completed", result: result as any, completedAt: new Date() })
              .where(eq(scansTable.id, scan.id));
            logger.info({ url: schedule.url, scanId: scan.id }, "Scheduled scan completed");
          })
          .catch(async (err: Error) => {
            await db
              .update(scansTable)
              .set({ status: "failed", errorMessage: err.message })
              .where(eq(scansTable.id, scan.id));
            logger.error({ url: schedule.url, err }, "Scheduled scan failed");
          });
      }
    } catch (err) {
      logger.error({ err }, "Scheduler tick error");
    }
  };

  setTimeout(tick, 12_000);
  setInterval(tick, 60_000);
}

export default router;
