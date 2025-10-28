    import bcrypt from "bcrypt";
    import jwt from "jsonwebtoken";
    import speakeasy from "speakeasy";
import qrcode from "qrcode";
    import { User } from "../models/User.js";
import { sendOTP, sendConfirmationEmail } from "../utils/sendEmailBrevo.js";



    // REGISTRO
  export const register = async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hashed });
    res.status(201).json({ message: "Usuario registrado" });
  } catch (err) {
    console.error("❌ Error en registro:", err);
    res.status(400).json({ error: "Error al registrar" });
  }
};

  export const loginNormal = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "No existe el usuario" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Contraseña incorrecta" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    // 🟢 Responder también con el email
    res.json({ message: "Inicio exitoso", token, email });
  } catch (err) {
    console.error("❌ Error en login:", err);
    res.status(500).json({ error: "Error en login" });
  }
};

    // LOGIN CON CORREO + CONTRASEÑA + ENVÍO DE OTP
    export const login = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ error: "No existe el usuario" });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: "Contraseña incorrecta" });

        // Generar OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 min

        user.otp = otp;
        user.otpExpires = expires;
        await user.save();

        await sendOTP(email, otp);

        res.json({ message: "OTP enviado al correo" });
    } catch (err) {
        res.status(500).json({ error: "Error al iniciar sesión" });
    }
    };

    // VERIFICAR OTP
    export const verifyOTP = async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
        return res.status(400).json({ error: "OTP inválido o expirado" });
        }

        user.otp = null;
        user.otpExpires = null;
        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ message: "Acceso concedido", token });
    } catch (err) {
        res.status(500).json({ error: "Error al verificar OTP" });
    }
    };
// RECUPERAR CONTRASEÑA – Enviar OTP por correo
export const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "Correo no registrado" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutos

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
export const verifyResetOTP = async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).json({ error: "Código inválido o expirado" });
    }

    res.status(200).json({ message: "Código válido" });
  } catch (err) {
    res.status(500).json({ error: "Error verificando OTP" });
  }
};
export const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).json({ error: "OTP inválido o expirado" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10); // 🔐 ciframos la nueva contraseña

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

export const requestConfirmation = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.log("Usuario no encontrado:", email);
      return res.status(401).json({ error: "No existe el usuario" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      console.log("Contraseña incorrecta");
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    // 🔐 Aquí todo está bien: el usuario existe y la contraseña coincide
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "10m" });

    user.accessToken = token;
    user.isPendingApproval = true;
    await user.save();

    await sendConfirmationEmail(user.email, token);

    res.status(200).json({ message: "Correo de confirmación enviado" });
  } catch (err) {
    console.error("Error en autenticación:", err);
    res.status(500).json({ error: "Error en autenticación" });
  }
};

export const confirmAccess = async (req, res) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(403).json({ error: "Usuario no encontrado" });

    const finalToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.status(200).json({
      message: "Acceso confirmado sin comparar accessToken",
      token: finalToken,
      email: user.email,
    });
  } catch (err) {
    console.error("❌ Error al verificar token:", err.message);
    res.status(400).json({ error: "Token inválido o expirado" });
  }
};


// Genera la clave secreta y QR
export const generateTOTP = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    const secret = speakeasy.generateSecret({
      name: `MiApp (${email})`,
    });

    user.totpSecret = secret.base32;
    await user.save();

    const qr = await qrcode.toDataURL(secret.otpauth_url);
    res.json({ qr });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error generando el código QR" });
  }
};
