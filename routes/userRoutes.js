// routes/userRoutes.js
import express from "express";
import { verifyToken, authorizeRole } from "../middleware/authMiddleware.js";
import { updateAuthMethod } from "../controllers/userController.js";
import { User } from "../models/User.js";

const router = express.Router();

/* ================================
   📄 Obtener perfil del usuario
   ================================ */
router.get("/profile", verifyToken, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: ["id", "email", "role", "authMethod"],
    });

    if (!user) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json({
      id: user.id,
      email: user.email,
      rol: user.role,
      authMethod: user.authMethod,
    });
  } catch (err) {
    console.error("❌ Error al obtener perfil:", err);
    res.status(500).json({ error: "Error del servidor" });
  }
});

/* ================================
   🔄 Actualizar método de autenticación
   ================================ */
router.patch("/update-auth-method", verifyToken, updateAuthMethod);

/* ================================
   🧍‍♂️ Acceso básico al perfil
   ================================ */
router.get("/perfil", verifyToken, (req, res) => {
  res.json({
    message: "Acceso al perfil del usuario",
    email: req.user.email,
    role: req.user.role,
  });
});

/* ================================
   🧩 Rutas protegidas por rol
   ================================ */
router.get(
  "/admin-dashboard",
  verifyToken,
  authorizeRole("administrador"),
  (req, res) => {
    res.json({ message: "Bienvenido al panel del administrador 🛡️" });
  }
);

router.get(
  "/entrenador-panel",
  verifyToken,
  authorizeRole("entrenador"),
  (req, res) => {
    res.json({ message: "Bienvenido al panel del entrenador 🏋️" });
  }
);

router.get(
  "/cliente-area",
  verifyToken,
  authorizeRole("cliente"),
  (req, res) => {
    res.json({ message: "Área exclusiva para clientes 🧘" });
  }
);

export default router;
