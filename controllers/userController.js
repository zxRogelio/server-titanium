// controllers/userController.js
import { User } from "../models/User.js";

export const updateAuthMethod = async (req, res) => {
  const { authMethod } = req.body;
  const { id } = req.user;

  if (!["normal", "otp", "totp", "confirm-link"].includes(authMethod)) {
    return res.status(400).json({ error: "Método inválido" });
  }

  try {
    const user = await User.findByPk(id);
    user.authMethod = authMethod;
    await user.save();

    res.json({ message: "Método de autenticación actualizado" });
  } catch (err) {
    console.error("❌ Error actualizando método:", err);
    res.status(500).json({ error: "Error del servidor" });
  }
};
