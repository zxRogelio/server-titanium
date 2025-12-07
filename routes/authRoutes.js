import express from "express";
import {
  register,
  login,
  verifyOTP,
  forgotPassword,
  verifyResetOTP,
  resetPassword,
  confirmAccess,
  verifyAccount,
  googleAuth,
  googleCallback,
} from "../controllers/authController.js";

import {
  generateTOTP,
  verifyTOTP
} from "../controllers/authTOTPController.js";
import { loginLimiter } from "../middleware/loginLimiter.js";
import { logout } from "../controllers/authController.js";
import { checkBlacklist } from "../middleware/checkBlacklist.js";
import { resendLoginOTP } from "../controllers/authController.js";
import { validateRegister } from "../middleware/validateRegister.js";
import { verifyToken } from "../middleware/authMiddleware.js";

const router = express.Router();

// Registro y verificación
router.post("/register", validateRegister, register);
router.get("/verify-account", verifyAccount);

// Login
router.post("/login", loginLimiter, login);
//Cierre de sesion
// Logout
router.post("/logout", verifyToken, logout);

// OTP y confirmación
router.post("/verify-otp", verifyOTP);
router.post("/confirm-access", confirmAccess);

// TOTP
router.post("/generate-totp" ,verifyToken,checkBlacklist,generateTOTP);
router.post("/verify-totp", verifyTOTP);

// Recuperación de contraseña
router.post("/forgot-password",  forgotPassword);
router.post("/verify-reset-otp", verifyResetOTP);
router.post("/reset-password",  resetPassword);
router.post("/resend-login-otp", resendLoginOTP);


// OAuth con Google
router.get("/google", googleAuth);
router.get("/google/callback", googleCallback);



export default router;
