import rateLimit from "express-rate-limit";

const WINDOW_MS = 15 * 60 * 1000; // 15 minutos

export const loginLimiter = rateLimit({
  windowMs: WINDOW_MS,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,

  handler: (req, res /*, next */) => {
    // ⏱️ Calcular segundos restantes hasta que se libere el límite
    let retryAfterSeconds = Math.ceil(WINDOW_MS / 1000); // valor por defecto: 900

    if (req.rateLimit?.resetTime instanceof Date) {
      const diffMs = req.rateLimit.resetTime.getTime() - Date.now();
      if (diffMs > 0) {
        retryAfterSeconds = Math.ceil(diffMs / 1000);
      }
    }

    return res.status(429).json({
      error:
        "Demasiados intentos de inicio de sesión. Intenta nuevamente más tarde.",
      retryAfterSeconds, // 👈 el front ya lo usa
    });
  },
});
