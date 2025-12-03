// middleware/authMiddleware.js
import jwt from "jsonwebtoken";
import { Session } from "../models/Session.js";
import { User } from "../models/User.js";

export const verifyToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Token no proporcionado" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 🔹 Guardamos el método de login de ESTA sesión
    req.loginMethod = decoded.loginMethod || "local";

    const session = await Session.findOne({
      where: {
        token,
        revoked: false,
      },
    });

    if (!session) {
      return res.status(401).json({ error: "Token revocado o inválido" });
    }

    const now = new Date();
    if (session.expiresAt < now) {
      return res.status(401).json({ error: "Sesión expirada" });
    }

    const user = await User.findByPk(decoded.id);
    if (!user) {
      return res.status(401).json({ error: "Usuario no encontrado" });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error("❌ Error al verificar token:", err);
    res.status(403).json({ error: "Token inválido" });
  }
};

// 🔸 NUEVO: middleware de autorización por rol
export const authorizeRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res
        .status(401)
        .json({ error: "Usuario no autenticado" });
    }

    if (!roles.includes(req.user.role)) {
      return res
        .status(403)
        .json({ error: "No tienes permisos para acceder a este recurso" });
    }

    next();
  };
};
