/*
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import helmet from "helmet";
import fs from "fs";
import https from "https";

import { secureHeaders } from "./middleware/secureHeaders.js";
import { forceHTTPS } from "./middleware/forceHTTPS.js";
import authRoutes from "./routes/authRoutes.js";
import { sequelize } from "./config/sequelize.js";
import userRoutes from "./routes/userRoutes.js";

dotenv.config();
const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(secureHeaders);

// Solo redirige a HTTPS si estás en producción
if (process.env.NODE_ENV === 'production') {
  app.use(forceHTTPS);
}

// Conexión a la base de datos
sequelize.authenticate()
  .then(() => {
    console.log("✅ Conectado a SQL Server");
    return sequelize.sync();
  })
  .then(() => console.log("✅ Tablas sincronizadas"))
  .catch((err) => console.error("❌ Error al conectar DB:", err));

app.use("/api/auth", authRoutes);
app.use("/api/user", userRoutes);

// Servidor HTTPS usando los archivos que ya tienes
const httpsOptions = {
  key: fs.readFileSync('./cert/localhost.key'),
  cert: fs.readFileSync('./cert/localhost.crt')
};

const PORT = process.env.PORT || 3001;
https.createServer(httpsOptions, app).listen(PORT, () =>
  console.log(`🚀 Backend en HTTPS: https://localhost:${PORT}`)
);

*/

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import helmet from "helmet";


import { secureHeaders } from "./middleware/secureHeaders.js";
import { forceHTTPS } from "./middleware/forceHTTPS.js";
import authRoutes from "./routes/authRoutes.js";
import { sequelize } from "./config/sequelize.js";
import userRoutes from "./routes/userRoutes.js";

dotenv.config();
const app = express();
app.use(cors());
app.use(helmet()); 
app.use(express.json());
app.use(secureHeaders);     // cabeceras de seguridad
app.use(forceHTTPS);        // redirección a HTTPS (solo en producción)
// Conectar a SQL Server y sincronizar
sequelize
  .authenticate()
  .then(() => {
    console.log("✅ Conectado a SQL Server");
    return sequelize.sync();
  })
  .then(() => console.log("✅ Tablas sincronizadas"))
  .catch((err) => console.error("❌ Error al conectar DB:", err));


app.use("/api/auth", authRoutes);
app.use("/api/user", userRoutes); // ahora tienes /api/user/perfil y /api/user/admin-dashboard


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Servidor en puerto ${PORT}`));
