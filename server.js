require("dotenv").config();
const express = require("express");
const path = require("path");
const { connectToDatabase } = require("./config/database");
const authRoutes = require("./routes/auth");
const cookieParser = require('cookie-parser');



const PORT = process.env.PORT || 5000;
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// View engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Static files
app.use(express.static("public"));

// Routes
app.get('/', (req, res) => {
    res.redirect('/login');
});

app.use('/', authRoutes);

// Start server
async function startServer() {
    await connectToDatabase();
    
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
}

startServer().catch(console.error);