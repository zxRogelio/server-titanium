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
    unique: true,
    allowNull: false,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  otp: DataTypes.STRING,
  otpExpires: DataTypes.DATE,

  // ✅ Nuevo campo: Verificación de cuenta
  isVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false, // por defecto no está verificado
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
});
