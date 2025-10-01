const express = require("express");
const bcrypt = require("bcrypt");
const User = require("../model/user");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const validator = require("validator");
const nodemailer = require("nodemailer");
const rateLimit = require('express-rate-limit');


const router = express.Router();

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per window
  message: {
    error: "Too many OTP requests from this IP, please try again later."
  },
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false,  // Disable the `X-RateLimit-*` headers
});

// GET /signup
router.get("/signup", (req, res) => {
  res.render("signup");
});

// POST /signup
router.post("/signup", otpLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({
        error: "Name is required",
      });
    }

    if (!email || !email.trim()) {
      return res.status(400).json({
        error: "Email is required",
      });
    }

    const allowedDomains = ["gmail.com", "yahoo.com", "outlook.com"];
    const emailDomain = email.split("@")[1];

    if (!validator.isEmail(email) || !allowedDomains.includes(emailDomain)) {
      return res.status(400).json({ error: "Please enter a valid email" });
    }

    if (!password || !password.trim()) {
      return res.status(400).json({
        error: "Password is required",
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
    if (existingUser.is_verified) {
        return res.status(400).json({ error: "User already exists" });
    } else {
            existingUser.name = name;
        const hashedPassword = await bcrypt.hash(password, 10);
        existingUser.password = hashedPassword;

        // Generate new OTP
        const otp = crypto.randomInt(100000, 1000000).toString();
        existingUser.otp_code = await bcrypt.hash(otp, 10);
        existingUser.otp_expires_at = new Date(Date.now() + 5 * 60 * 1000);
        
        await existingUser.save();

        // Send OTP email again
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "OTP Verification",
            html: `<h3>Your OTP</h3><p>${otp}</p>`,
        });

        return res.render("otp",  { userEmail: existingUser.email });
    }
}

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // generating otp
    const otp = crypto.randomInt(100000, 1000000).toString();
    const hashedOTP = await bcrypt.hash(otp, saltRounds);
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);

    // Create new user
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      otp_code: hashedOTP,
      otp_expires_at: otpExpiresAt,
    });

    const savedUser = await newUser.save();
    console.log("User created:", savedUser);

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "OTP Verification",
      html: `
      <h3>Your OTP</h3>
      <p><strong>OTP:</strong> ${otp}</p>
    `,
    };

    await transporter.sendMail(mailOptions);
    res.render("otp", { userEmail: savedUser.email });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Failed to create user" });
  }
});


// POST /otp
router.post("/verify-otp", otpLimiter, async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }
    if (user.is_verified) {
      return res.status(400).json({ error: "User already verified" });
    }
    console.log("User input OTP:", otp);
console.log("Stored OTP hash:", user.otp_code);
    const isValidOtp = await bcrypt.compare(otp, user.otp_code);
    if (!isValidOtp) return res.status(400).json({ error: "Invalid OTP" });
    if (user.otp_expires_at < new Date()) {
      return res.status(400).json({ error: "OTP expired" });
    }
    user.is_verified = true;
    user.otp_code = undefined;
    user.otp_expires_at = undefined;
    await user.save();
    // res.status(200).json({ message: "OTP verified successfully" });
    res.redirect("/login");
  } catch (error) {
   console.error("Error verifying OTP:", error.message, error.stack);
    res.status(500).json({ error: "Failed to verify OTP" });
  }
});

// GET /login
router.get("/login", (req, res) => {
  res.render("login");
});

// POST /login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user || !user.is_verified) {
      return res
        .status(401)
        .json({ error: "User not verified or does not exist" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("token", token, { httpOnly: true });
    res.render("home", { name: user.name, email: user.email });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Login failed" });
  }
});

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
  const token = req.cookies.token;

  if (!token) return res.redirect("/login");
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.redirect("/login");
  }
}

// GET /home
router.get("/home", isAuthenticated, (req, res) => {
  res.render("home", { name: req.user.name, email: req.user.email });
});

// GET /logout
router.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

module.exports = router;
