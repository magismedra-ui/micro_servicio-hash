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
  if (!password || !hash)
    return res.status(400).json({ error: "Faltan datos" });

  const match = await bcrypt.compare(password, hash);
  res.json({ valid: match });
});

// Ruta para verificar token
app.post("/verify-token", (req, res) => {
  const { token } = req.body;
  const secret = "GOCSPX-YDiCuYyKWfnWj8H";

  try {
    const decoded = verifyJWT(token, secret);

    res.json({
      success: true,
      message: "Token válido",
      decoded,
    });
  } catch (err) {
    res.json({
      success: false,
      message: "Token invalido",
    });
  }
});

function verifyJWT(token, secret) {
  const [headerB64, payloadB64, signatureB64] = token.split(".");
  if (!headerB64 || !payloadB64 || !signatureB64)
    throw new Error("Formato JWT inválido");

  const data = `${headerB64}.${payloadB64}`;
  const expectedSig = crypto
    .createHmac("sha256", secret)
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  if (expectedSig !== signatureB64) throw new Error("Firma JWT inválida");

  const payloadJSON = Buffer.from(payloadB64, "base64").toString("utf8");
  const payload = JSON.parse(payloadJSON);

  // Verifica expiración (si existe 'exp')
  if (payload.exp && Date.now() >= payload.exp * 1000) {
    throw new Error("Token expirado");
  }

  return payload;
}

app.listen(3000, () =>
  console.log("Microservicio bcrypt activo en puerto 3000")
);
