import { isTokenBlacklisted } from "./tokenBlacklist.js";

export const checkBlacklist = (req, res, next) => {
  const authHeader = req.headers.authorization || req.headers["authorization"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    // Aquí casi siempre también tienes verifyToken, pero por si acaso:
    return res.status(401).json({ error: "No autorizado" });
  }

  const token = authHeader.split(" ")[1];

  if (isTokenBlacklisted(token)) {
    return res.status(401).json({ message: "Token revocado" });
  }

  next();
};
