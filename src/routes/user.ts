import express, { type Request } from "express";

const router = express.Router();
import { loginController } from "../controllers/authController/loginController";
import { signupController } from "../controllers/authController/signupController";

router.post("/login", loginController);
router.post("/signup", signupController);

export default router;
