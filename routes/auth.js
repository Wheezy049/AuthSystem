const express = require("express");
const bcrypt = require("bcrypt");
const User = require("../model/user");

const router = express.Router();

// GET /signup
router.get('/signup', (req, res) => {
    res.render('signUp');
});

// POST /signup
router.post('/signup', async (req, res) => {
    try {
        const { name, password } = req.body;
        
        // Check if user already exists
        const existingUser = await User.findOne({ name });
        if (existingUser) {
            return res.status(400).json({ error: "User already exists" });
        }
        
        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Create new user
        const newUser = new User({
            name,
            password: hashedPassword
        });
        
        const savedUser = await newUser.save();
        console.log("User created:", savedUser);
        
        res.status(201).json({ 
            message: "User created successfully", 
            userId: savedUser._id 
        });
        
    } catch (error) {
        console.error("Error creating user:", error);
        res.status(500).json({ error: "Failed to create user" });
    }
});

// GET /login
router.get('/login', (req, res) => {
    res.render('login');
});

// POST /login
router.post('/login', async (req, res) => {
    try {
        const { name, password } = req.body;
        
        const user = await User.findOne({ name });
        if (!user) {
            return res.status(401).json({ error: "Invalid credentials" });
        }
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid credentials" });
        }
        
        // res.json({ 
        //     message: "Login successful", 
        //     userId: user._id 
        // });
        console.log("User logged in:", user);
        res.render('home', { name: user.name });
        
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: "Login failed" });
    }
});

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    // Here you would typically check if the user is authenticated
    // For simplicity, we assume the user is authenticated
    next();
}

// GET /home
// router.get('/home', isAuthenticated, (req, res) => {
//     // Render home page
//     res.render('home', { name: req.query.name || "Guest" });
// });



// GET /logout
router.get('/logout', (req, res) => {
    // Here you would typically destroy the session
    // For simplicity, we just redirect to login
    res.redirect('/login');
});


module.exports = router;