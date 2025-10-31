import express from "express";
import {
  register,
  login,
  verifyOTP,
  forgotPassword,
  verifyResetOTP,
  resetPassword,
  confirmAccess,
  verifyAccount
} from "../controllers/authController.js";

import {
  generateTOTP,
  verifyTOTP
} from "../controllers/authTOTPController.js";

const router = express.Router();

// Registro y verificación
router.post("/register", register);
router.get("/verify-account", verifyAccount);

// Login
router.post("/login", login);

// OTP y confirmación
router.post("/verify-otp", verifyOTP);
router.post("/confirm-access", confirmAccess);

// TOTP
router.post("/generate-totp", generateTOTP);
router.post("/verify-totp", verifyTOTP);

// Recuperación de contraseña
router.post("/forgot-password", forgotPassword);
router.post("/verify-reset-otp", verifyResetOTP);
router.post("/reset-password", resetPassword);

export default router;
