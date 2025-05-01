const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const bodyParser = require("body-parser");
const axios = require("axios");
require("dotenv").config();

const app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

// Session setup
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Use 'true' with HTTPS
  })
);

// Rate limiter to block after 5 failed login attempts per 10 mins
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  message: "Too many login attempts. Please try again later.",
});

// Dummy user (pretend this came from a DB)
const users = [
  {
    username: "admin",
    passwordHash: bcrypt.hashSync("password123", 10), // store only hashed passwords
  },
];

// Home route
app.get("/", (req, res) => {
  if (req.session.user) {
    res.send(`Welcome, ${req.session.user.username}! <a href="/logout">Logout</a>`);
  } else {
    res.redirect("/login");
  }
});

// Login form
app.get("/login", (req, res) => {
  res.render("login", { siteKey: process.env.RECAPTCHA_SITE_KEY, error: null });
});

// Handle login POST
app.post("/login", loginLimiter, async (req, res) => {
  const { username, password, "g-recaptcha-response": captcha } = req.body;

  // Verify CAPTCHA
  if (!captcha) return res.render("login", { siteKey: process.env.RECAPTCHA_SITE_KEY, error: "Please complete the CAPTCHA." });

  try {
    const verifyURL = `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET}&response=${captcha}`;
    const captchaRes = await axios.post(verifyURL);
    if (!captchaRes.data.success) {
      return res.render("login", { siteKey: process.env.RECAPTCHA_SITE_KEY, error: "CAPTCHA verification failed." });
    }
  } catch (err) {
    return res.render("login", { siteKey: process.env.RECAPTCHA_SITE_KEY, error: "Error verifying CAPTCHA." });
  }

  // Authenticate user
  const user = users.find((u) => u.username === username);
  if (!user) return res.render("login", { siteKey: process.env.RECAPTCHA_SITE_KEY, error: "Invalid credentials." });

  const isPasswordCorrect = await bcrypt.compare(password, user.passwordHash);
  if (!isPasswordCorrect) {
    return res.render("login", { siteKey: process.env.RECAPTCHA_SITE_KEY, error: "Invalid credentials." });
  }

  // Store session
  req.session.user = { username };
  res.redirect("/");
});

// Logout route
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
