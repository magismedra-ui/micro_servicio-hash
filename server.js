// archivo: server.js
import express from "express";
import bcrypt from "bcrypt";

const app = express();
app.use(express.json());

// Ruta para hashear una contraseña
app.post("/hash", async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Falta la contraseña" });

  const saltRounds = 10; // puedes ajustar entre 10 y 12
  const hash = await bcrypt.hash(password, saltRounds);

  res.json({ hash });
});

// Ruta para verificar contraseña (opcional)
app.post("/verify", async (req, res) => {
  const { password, hash } = req.body;
  if (!password || !hash) return res.status(400).json({ error: "Faltan datos" });

  const match = await bcrypt.compare(password, hash);
  res.json({ match });
});

app.listen(3000, () => console.log("Microservicio bcrypt activo en puerto 3000"));
