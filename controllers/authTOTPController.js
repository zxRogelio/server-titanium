import speakeasy from "speakeasy";
import jwt from "jsonwebtoken";
import { User } from "../models/User.js";
import { Session } from "../models/Session.js"; // ⬅️ IMPORTANTE

export const generateTOTP = async (req, res) => {
  try {

    if (!req.user || !req.user.id) {
      return res
        .status(401)
        .json({ error: "No autorizado: usuario no definido en req.user" });
    }

    const userId = req.user.id;
    const user = await User.findByPk(userId);

    if (!user) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    let otpauth_url;

    if (!user.totpSecret) {
      const secret = speakeasy.generateSecret({
        name: `Titanium Sport Gym (${user.email})`,
      });
      user.totpSecret = secret.base32;
      await user.save();
      otpauth_url = secret.otpauth_url;
    } else {
      otpauth_url = speakeasy.otpauthURL({
        secret: user.totpSecret,
        label: `Titanium Sport Gym (${user.email})`,
        encoding: "base32",
      });
    }

    return res.json({ otpauth_url });
  } catch (err) {
    console.error("❌ Error generando TOTP:", err);
    res.status(500).json({ error: "Error generando el código QR" });
  }
};

export const verifyTOTP = async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res
        .status(400)
        .json({ error: "Correo y código son requeridos" });
    }

    const user = await User.findOne({ where: { email } });
    if (!user || !user.totpSecret) {
      return res
        .status(404)
        .json({ error: "Usuario o secreto TOTP no encontrado" });
    }

    const isValid = speakeasy.totp.verify({
      secret: user.totpSecret,
      encoding: "base32",
      token: code,
      window: 2,
    });

    if (!isValid) {
      return res.status(401).json({ error: "Código inválido" });
    }

    // 🟢 Esta sesión es local (aunque el usuario tenga provider google vinculado)
    const loginMethod = "local";

    const token = jwt.sign(
      {
        id: user.id,
        role: user.role,
        email: user.email,
        loginMethod,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // ⭐ Muy importante: crear la sesión para que /user/profile NO devuelva 401
    await Session.create({
      userId: user.id,
      token,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      ipAddress: req.ip || req.connection?.remoteAddress,
      userAgent: req.headers["user-agent"] || "Desconocido",
    });

    // ⬅️ mantenemos "token" para no romper tu LoginTOTP actual
    return res.json({
      message: "Acceso concedido por TOTP",
      token,
      user: {
        id: user.id,
        email: user.email,
        rol: user.role,
      },
    });
  } catch (err) {
    console.error("❌ Error verificando TOTP:", err);
    res.status(500).json({ error: "Error verificando TOTP" });
  }
};
