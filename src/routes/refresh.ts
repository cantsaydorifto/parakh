import { refreshController } from "../controllers/authController/refreshController";
import express from "express";

const router = express.Router();

router.get("/", refreshController);

export default router;
