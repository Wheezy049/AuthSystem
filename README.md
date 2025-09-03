# 🔐 Node.js JWT Authentication System (View Engine)

This project is a simple and secure **authentication system** built with **Node.js**, **Express**, and **EJS** (view engine). It uses **JWT (JSON Web Token)** for stateless authentication and `cookie-parser` to manage user sessions via HTTP-only cookies.

## 🚀 Features

- ✅ User registration with hashed passwords (using `bcrypt`)
- ✅ Secure login with JWT token generation
- ✅ HTTP-only cookies for storing JWTs
- ✅ Route protection using middleware (`isAuthenticated`)
- ✅ Logout functionality
- ✅ EJS-based views (`signUp`, `login`, `home`)
- ✅ Stateless (no session storage)

## 🛠 Tech Stack

- **Node.js**
- **Express.js**
- **MongoDB** (via Mongoose)
- **EJS** (templating engine)
- **JWT** for stateless authentication
- **bcrypt** for password hashing
- **cookie-parser** for reading cookies

## 🧪 Installation

1. **Clone the repository**

```bash
git clone https://github.com/Wheezy049/AuthSystem
cd authsystem

```

## Install Dependencies
```bash
npm install
```

## Create a .env file in the root directory and add:
```bash
PORT=3000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_super_secret_key
```

## Start server
```bash
npm start
```

## 🔒 How Authentication Works

- Signup: User registers, password is hashed, and stored securely in the database.

- Login: If credentials are valid, a JWT is generated and stored in a secure HTTP-only cookie.

- Protected Routes: JWT is verified using middleware. If valid, access is granted.

- Logout: Cookie is cleared and user is redirected to the login page.

✍️ Author
Dev_faruq

