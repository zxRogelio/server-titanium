// models/User.js
import { DataTypes } from "sequelize";
import { sequelize } from "../config/sequelize.js";

export const User = sequelize.define("User", {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
  },

  // 👇 Ahora puede ser null para usuarios OAuth (Google)
  password: {
    type: DataTypes.STRING,
    allowNull: true,
  },

  otp: DataTypes.STRING,
  otpExpires: DataTypes.DATE,

  // ✅ Verificación de cuenta
  isVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },

  isPendingApproval: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
  accessToken: {
    type: DataTypes.STRING,
    defaultValue: null,
  },
  totpSecret: {
    type: DataTypes.STRING,
    defaultValue: null,
  },

  // ✅ Método de autenticación (login normal, OTP, QR o link)
  authMethod: {
    type: DataTypes.ENUM("normal", "otp", "totp", "confirm-link"),
    defaultValue: "normal",
  },

  // ✅ Roles del sistema
  role: {
    type: DataTypes.ENUM("cliente", "entrenador", "administrador"),
    defaultValue: "cliente",
  },

  // 🔹 Nuevo: proveedor de autenticación
  provider: {
    type: DataTypes.STRING,
    allowNull: false,
    defaultValue: "local", // 'local' (email/contraseña), 'google' (OAuth)
  },

  // 🔹 Nuevo: id del usuario en el proveedor (por ejemplo, Google sub)
  providerId: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  passwordChangesCount: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
  },
  passwordChangesDate: {
    type: DataTypes.DATEONLY,
    allowNull: true,
  },
});
