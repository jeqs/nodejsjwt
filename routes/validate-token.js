const jwt = require("jsonwebtoken");

// middleware to validate token (rutas protegidas)
const verifyToken = (req, res, next) => {
  const token = req.header("auth-token");
  if (!token) return res.status(401).json({ error: "Acceso denegado" });

  try {
    const verify = jwt.verify(toke, process.env.TOKEN_SECRET);
    req.user = verify;
    next();

  } catch (error) {
    return res.status(401).json({ error: "Acceso denegado" });
  }
};

module.exports = verifyToken;
