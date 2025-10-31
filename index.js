import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./routes/authRoutes.js";
import { sequelize } from "./config/sequelize.js";
import userRoutes from "./routes/userRoutes.js";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// Conectar a SQL Server y sincronizar
sequelize.authenticate()
  .then(() => {
    console.log("✅ Conectado a SQL Server");
    return sequelize.sync(); // Usa { force: true } para resetear tablas
  })
  .then(() => console.log("✅ Tablas sincronizadas"))
  .catch((err) => console.error("❌ Error al conectar DB:", err));

app.use("/api/auth", authRoutes);
app.use("/api/user", userRoutes); // ahora tienes /api/user/perfil y /api/user/admin-dashboard

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Servidor en puerto ${PORT}`));
