  import bcrypt from "bcrypt";
  import jwt from "jsonwebtoken";
  import { User } from "../models/User.js";
  import {
    sendOTP,
    sendConfirmationEmail,
    sendVerificationEmail,
  } from "../utils/sendEmailBrevo.js";
  import dotenv from 'dotenv';
  dotenv.config();
  /* ================================
    🟢 REGISTRO + VERIFICACIÓN CORREO
  ================================= */
  export const register = async (req, res) => {
    const { email, password, role = "cliente" } = req.body;

    try {
      // Verificar si ya existe
      const existing = await User.findOne({ where: { email } });
      if (existing) {
        return res.status(400).json({ error: "El correo ya está registrado" });
      }

      // Crear usuario nuevo
      const hashed = await bcrypt.hash(password, 10);
      const user = await User.create({
        email,
        password: hashed,
        role,
        isVerified: false,
      });

      // Generar token de verificación
      const verifyToken = jwt.sign(
        { id: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "15m" }
      );

      // Enviar correo de verificación
      await sendVerificationEmail(user.email, verifyToken);

      res.status(201).json({
        message: "Usuario registrado. Verifica tu correo antes de iniciar sesión.",
      });
    } catch (err) {
      console.error("❌ Error en registro:", err);
      res.status(400).json({ error: "Error al registrar usuario" });
    }
  };

  /* ================================
    🟡 VERIFICAR CUENTA DESDE LINK
  ================================= */
  export const verifyAccount = async (req, res) => {
    const { token } = req.query;

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      const user = await User.findByPk(decoded.id);
      if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

      if (user.isVerified) {
        return res.status(200).json({ message: "Tu cuenta ya está verificada." });
      }

      user.isVerified = true;
      await user.save();

      res.status(200).json({ message: "Cuenta verificada correctamente." });
    } catch (err) {
      console.error("❌ Error al verificar cuenta:", err.message);
      res.status(400).json({ error: "Token inválido o expirado" });
    }
  };

/* ================================
   🔐 LOGIN CON MÉTODOS ADAPTATIVOS
================================ */
export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(401).json({ error: "No existe el usuario" });

    // Verificar si el usuario confirmó su cuenta
    if (!user.isVerified) {
      return res.status(403).json({
        error: "Debes verificar tu cuenta antes de iniciar sesión.",
      });
    }

    // Validar contraseña
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Contraseña incorrecta" });

    // 🧩 Decidir flujo según método de autenticación
    switch (user.authMethod) {
      // 🔵 OTP (código por correo)
      case "otp": {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = new Date(Date.now() + 10 * 60 * 1000);
        user.otp = otp;
        user.otpExpires = expires;
        await user.save();

        await sendOTP(email, otp);
        console.log(`✅ OTP enviado a ${email}`);

        return res.status(200).json({
          message: "OTP enviado al correo",
          twoFactorRequired: true,
          method: "otp",
        });
      }

      // 🟣 Confirmación por enlace tipo “¿Eres tú?”
      case "confirm-link": {
        const token = jwt.sign(
          { id: user.id, role: user.role, email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: "10m" }
        );

        user.accessToken = token;
        user.isPendingApproval = true;
        await user.save();

        await sendConfirmationEmail(user.email, token);
        console.log(`✅ Correo de confirmación enviado a ${email}`);

        return res.status(200).json({
          message: "Correo de confirmación enviado",
          twoFactorRequired: true,
          method: "confirm-link",
        });
      }

      // 🟢 TOTP (Google Authenticator)
      case "totp": {
        console.log(`✅ TOTP requerido para ${email}`);
        return res.status(200).json({
          message: "TOTP requerido",
          twoFactorRequired: true,
          method: "totp",
        });
      }

      // 🔓 Login normal (sin 2FA)
      default: {
        const token = jwt.sign(
          { id: user.id, role: user.role, email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: "1h" }
        );

        console.log(`✅ Login normal exitoso para ${email}`);

        return res.status(200).json({
          message: "Inicio exitoso",
          accessToken: token,
          user: {
            id: user.id,
            email: user.email,
            rol: user.role,
          },
          twoFactorRequired: false,
        });
      }
    }
  } catch (err) {
    console.error("❌ Error en login:", err);
    res.status(500).json({ error: "Error al iniciar sesión" });
  }
};

  /* ================================
    🔵 VERIFICAR OTP
  ================================= */
// controllers/authController.js
export const verifyOTP = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ where: { email } });

    const now = Date.now();

    if (!user || user.otp !== otp || user.otpExpires < now) {
      return res.status(400).json({ error: "OTP inválido o expirado" });
    }

    // Limpia el OTP
    user.otp = null;
    user.otpExpires = null;
    await user.save();

    // Genera token normal
    const accessToken = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Acceso concedido",
      accessToken, // ✅ mismo nombre esperado por frontend
      user: {
        id: user.id,
        email: user.email,
        rol: user.role,
      },
    });
  } catch (err) {
    console.error("Error al verificar OTP:", err);
    res.status(500).json({ error: "Error al verificar OTP" });
  }
};


  /* ================================
    🧩 RECUPERAR CONTRASEÑA
  ================================= */
  export const forgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
      const user = await User.findOne({ where: { email } });
      if (!user) return res.status(404).json({ error: "Correo no registrado" });

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const expires = new Date(Date.now() + 10 * 60 * 1000);
      user.otp = otp;
      user.otpExpires = expires;
      await user.save();

      await sendOTP(email, otp);
      res.status(200).json({ message: "Código enviado al correo" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Error al enviar código" });
    }
  };

  /* ================================
    🧾 VERIFICAR CÓDIGO RESET
  ================================= */
  export const verifyResetOTP = async (req, res) => {
    const { email, otp } = req.body;
    try {
      const user = await User.findOne({ where: { email } });
      if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
        return res.status(400).json({ error: "Código inválido o expirado" });
      }
      res.status(200).json({ message: "Código válido" });
    } catch (err) {
      res.status(500).json({ error: "Error verificando OTP" });
    }
  };

  /* ================================
    🔄 CAMBIAR CONTRASEÑA
  ================================= */
  export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;
    try {
      const user = await User.findOne({ where: { email } });
      if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
        return res.status(400).json({ error: "OTP inválido o expirado" });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      user.otp = null;
      user.otpExpires = null;
      await user.save();

      res.status(200).json({ message: "Contraseña actualizada correctamente" });
    } catch (err) {
      console.error("Error al resetear contraseña:", err);
      res.status(500).json({ error: "Error al actualizar contraseña" });
    }
  };

export const confirmAccess = async (req, res) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findByPk(decoded.id);
    if (!user) {
      return res.status(403).json({ error: "Usuario no encontrado" });
    }

    const finalToken = jwt.sign(
      {
        id: user.id,
        role: user.role,
        email: user.email, // ✅ AGREGA EL EMAIL AQUÍ
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      message: "Acceso confirmado",
      token: finalToken,
      email: user.email,
    });
  } catch (err) {
    console.error("❌ Error al verificar token:", err.message);
    res.status(400).json({ error: "Token inválido o expirado" });
  }
};