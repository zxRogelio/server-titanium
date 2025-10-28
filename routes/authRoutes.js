import express from "express";
import { register, login, verifyOTP } from "../controllers/authController.js";
import { loginNormal } from "../controllers/authController.js";
import { forgotPassword } from "../controllers/authController.js";
import { verifyResetOTP, resetPassword } from "../controllers/authController.js";
import { requestConfirmation, confirmAccess } from "../controllers/authController.js";
import { generateTOTP, verifyTOTP } from "../controllers/authTOTPController.js";


const router = express.Router();

router.post("/register", register);
router.post("/login-normal", loginNormal);
router.post("/login", login);
router.post("/verify-otp", verifyOTP);
router.post("/forgot-password", forgotPassword);
router.post("/verify-reset-otp", verifyResetOTP);
router.post("/reset-password", resetPassword);
router.post("/login-confirmation-request", requestConfirmation);
router.post("/confirm-access", confirmAccess);
router.post("/generate-totp", generateTOTP);
router.post("/verify-totp", verifyTOTP); 

export default router;
