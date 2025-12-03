import rateLimit from "express-rate-limit";

export const loginLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 15 minutos
  max: 5,
  message: "Demasiados intentos de inicio de sesión. Intenta nuevamente en unos minutos.",
  standardHeaders: true,
  legacyHeaders: false,
});
