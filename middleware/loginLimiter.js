// middleware/loginLimiter.js
import rateLimit from "express-rate-limit";

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // ⏱ 15 minutos
  max: 5,                   // máximo 5 intentos por IP en ese tiempo
  message:
    "Demasiados intentos de inicio de sesión. Intenta nuevamente más tarde.",
  standardHeaders: true,
  legacyHeaders: false,
});
