import { Router, type IRouter } from "express";
import healthRouter from "./health";
import scansRouter from "./scans";
import verifyPocRouter from "./verify-poc";

const router: IRouter = Router();

router.use(healthRouter);
router.use(scansRouter);
router.use(verifyPocRouter);

export default router;
