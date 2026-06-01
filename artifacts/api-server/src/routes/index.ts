import { Router, type IRouter } from "express";
import healthRouter from "./health";
import scansRouter from "./scans";
import verifyPocRouter from "./verify-poc";
import exploitRouter from "./exploit";
import schedulesRouter, { startScheduler } from "./schedules";

const router: IRouter = Router();

router.use(healthRouter);
router.use(scansRouter);
router.use(verifyPocRouter);
router.use(exploitRouter);
router.use(schedulesRouter);

startScheduler();

export default router;
