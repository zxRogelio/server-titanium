// controllers/userController.js
import { User } from "../models/User.js";

export const updateAuthMethod = async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: "Usuario no autenticado" });
    }

    const { authMethod } = req.body;
    const allowedMethods = ["normal", "otp", "totp", "confirm-link"];

    if (!authMethod || !allowedMethods.includes(authMethod)) {
      return res
        .status(400)
        .json({ error: "Método de autenticación no válido" });
    }

    // 🧠 Con qué método se inició ESTA sesión:
    const loginMethod =
      req.loginMethod || (req.user.provider === "google" ? "google" : "local");

    console.log(
      "🧩 updateAuthMethod -> loginMethod:",
      loginMethod,
      "provider:",
      req.user.provider
    );

    // 🚫 Si está logueado con Google, no le dejamos cambiar
    if (loginMethod === "google") {
      return res.status(403).json({
        error:
          "No puedes cambiar el método de verificación desde una sesión iniciada con Google. " +
          "Cierra sesión e inicia con tu correo y contraseña.",
      });
    }

    // Extra safety: cuenta 100% Google sin contraseña local
    if (!req.user.password && req.user.provider === "google") {
      return res.status(403).json({
        error:
          "Esta cuenta está vinculada solo a Google. No puedes configurar métodos locales.",
      });
    }

    req.user.authMethod = authMethod;
    await req.user.save();

    return res.json({
      message: "Método de autenticación actualizado correctamente",
      authMethod,
    });
  } catch (err) {
    console.error("❌ Error en updateAuthMethod:", err);
    return res
      .status(500)
      .json({ error: "Error al actualizar el método de autenticación" });
  }
};
