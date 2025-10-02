# 🔐 Node.js JWT Authentication System (View Engine)

This project is a simple and secure **authentication system** built with **Node.js**, **Express**, and **EJS** (view engine). It uses **JWT (JSON Web Token)** for stateless authentication and `cookie-parser` to manage user sessions via HTTP-only cookies. Additionally, it implements an **email-based OTP verification** during signup.


## 🚀 Features

- ✅ User registration with hashed passwords (using `bcrypt`)
- ✅ Email-based OTP verification for new users
- ✅ Resend OTP for unverified users
- ✅ Secure login with JWT token generation (only after OTP verification)
- ✅ HTTP-only cookies for storing JWTs
- ✅ Route protection using middleware (`isAuthenticated`)
- ✅ Logout functionality
- ✅ EJS-based views (`signUp`, `login`, `otp`, `home`)
- ✅ Stateless (no session storage)
- ✅ Rate limiting for OTP requests to prevent abuse

## 🛠 Tech Stack

- **Node.js**
- **Express.js**
- **MongoDB** (via Mongoose)
- **EJS** (templating engine)
- **JWT** for stateless authentication
- **bcrypt** for password hashing
- **cookie-parser** for reading cookies
- **nodemailer** for sending OTP emails
- **express-rate-limit** for rate limiting OTP requests

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
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_email_password
```

## Start server
```bash
npm start
```

## 🔒 How Authentication Works

- Signup: User registers, password is hashed, and an OTP is generated and sent to the user’s email. The user must verify the OTP to complete registration.

- OTP Verification: User enters OTP received via email. Only verified users can log in. Users can request a new OTP if expired.

- Resend OTP: If the OTP expires or the user didn’t receive it, they can click the Resend OTP button. A new OTP is generated, sent to the email, and the countdown timer restarts.

- Login: If credentials are valid and user is verified, a JWT is generated and stored in a secure HTTP-only cookie.

- Protected Routes: JWT is verified using middleware. If valid, access is granted.

- Logout: Cookie is cleared and user is redirected to the login page.

✍️ Author
Dev_faruq

