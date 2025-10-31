// controllers/authTOTPController.js
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import jwt from "jsonwebtoken";
import { User } from "../models/User.js";

export const generateTOTP = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    let otpauth_url;

    // ✅ Si el usuario no tiene un secreto, generamos uno nuevo
    if (!user.totpSecret) {
      const secret = speakeasy.generateSecret({ name: `UMISUMI (${email})` });
      user.totpSecret = secret.base32;
      await user.save();
      otpauth_url = secret.otpauth_url;
    } else {
      // 🔁 Si ya tiene un secreto, usamos el mismo
      otpauth_url = speakeasy.otpauthURL({
        secret: user.totpSecret,
        label: `UMISUMI (${email})`,
        encoding: "base32",
      });
    }

    // ✅ Enviar solo la URL al frontend
    return res.json({ otpauth_url });
  } catch (err) {
    console.error("❌ Error generando TOTP:", err);
    res.status(500).json({ error: "Error generando el código QR" });
  }
};

export const verifyTOTP = async (req, res) => {
  const { email, code } = req.body;

  try {
    const user = await User.findOne({ where: { email } });
    if (!user || !user.totpSecret) {
      return res.status(404).json({ error: "Usuario o secreto no encontrado" });
    }

    const isValid = speakeasy.totp.verify({
      secret: user.totpSecret,
      encoding: "base32",
      token: code,
      window: 2, // margen de 1 código antes y 1 después
    });

    if (!isValid) return res.status(401).json({ error: "Código inválido" });

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Error verificando OTP" });
  }
};
