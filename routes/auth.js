const router = require("express").Router();
const bcrypt = require("bcrypt");

// Schema o Modelos
const User = require("../models/User");

// JWT
const jwt = require("jsonwebtoken");

// validation
const Joi = require("@hapi/joi");
const schemaRegister = Joi.object({
  name: Joi.string().min(6).max(255).required(),
  email: Joi.string().min(6).max(255).required().email(),
  password: Joi.string().min(6).max(1024).required(),
});

router.post("/register", async (req, res) => {
  //validaciones de usuarios
  const { error } = schemaRegister.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  const existeEmail = await User.findOne({ email: req.body.email });
  if (existeEmail) {
    return res.status(400).json({ error: true, mensaje: "Email Registrado" });
  }

  const salt = await bcrypt.genSalt(10);
  const hasPassword = await bcrypt.hash(req.body.password, salt);

  const user = new User({
    name: req.body.name,
    email: req.body.email,
    password: hasPassword,
  });

  try {
    const savedUser = await user.save();
    res.json({
      error: null,
      data: savedUser,
    });
  } catch (error) {
    res.status(400).json({ error });
  }
});

// Schema Login
const schemaLogin = Joi.object({
  email: Joi.string().min(6).max(255).required().email(),
  password: Joi.string().min(6).max(1024).required(),
});

router.post("/login", async (req, res) => {
  // validaciones
  const { error } = schemaLogin.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).json({ error: "Credenciales invalidas" });

    const validPassword = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!validPassword)
      return res.status(400).json({ error: "Credenciales invalidas" });

    // JWT
    const jwtToken = jwt.sign({
        "name": user.name,
        "id": user.id
    }, process.env.TOKEN_SECRET);

    res.header('auth-token', jwtToken).json({
        error: null,
        data: {jwtToken}
    })

    res.json({
      error: null,
      data: "exito bienvenido"
    });

    
  } catch (error) {
    res.status(400).json({ error });
  }
});

module.exports = router;
