import speakeasy from "speakeasy";
import qrcode from "qrcode";
import { User } from "../models/User.js";
import jwt from "jsonwebtoken";

// Genera la clave secreta y QR
export const generateTOTP = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    // ✅ Si ya tiene una clave, no generamos otra
    if (!user.totpSecret) {
      const secret = speakeasy.generateSecret({
        name: `MiApp (${email})`,
      });

      user.totpSecret = secret.base32;
      await user.save();

      const qr = await qrcode.toDataURL(secret.otpauth_url);
      return res.json({ qr });
    }

    // 🔁 Volver a generar QR desde el secreto existente
    const otpauth = speakeasy.otpauthURL({
      secret: user.totpSecret,
      label: `MiApp (${email})`,
      encoding: "base32",
    });

    const qr = await qrcode.toDataURL(otpauth);
    res.json({ qr });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error generando el código QR" });
  }
};

export const verifyTOTP = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || !user.totpSecret) {
      return res.status(404).json({ error: "Usuario o secreto no encontrado" });
    }

    const isValid = speakeasy.totp.verify({
      secret: user.totpSecret,
      encoding: "base32",
      token: otp,
      window: 2, // ← tolerancia de tiempo (30s antes o después)
    });

    if (!isValid) return res.status(401).json({ error: "Código inválido" });

    // Si el código es válido, generamos token JWT normal
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Error verificando OTP" });
  }
};