const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true
    },
    otp_code: {
        type: String,
    },
    otp_expires_at: {
        type: Date,
    },
    is_verified: {
        type: Boolean,
        default: false
    }
});

const User = mongoose.model("User", userSchema);

module.exports = User;