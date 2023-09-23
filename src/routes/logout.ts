import express from "express";
import { logoutController } from "../controllers/authController/logoutController";
const router = express.Router();

router.post("/", logoutController);

export default router;
