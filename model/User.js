const mongoose = require('mongoose');
// const Schema = mongoose.Schema;

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        // require: true
        default: "User"
    },
    email: {
        type: String,
        require: true
    },
    roles: {
        User: {
            type: Number,
            default: 2001
        },
        Editor: Number,
        Admin: Number
    },
    password: {
        type: String,
        required: true
    },
    isVerified: {
        type: Boolean,
        default: 'false',
        require: true
    },
    // token: {
    //     type: String,
    //     default: ''
    // },
    // refreshToken: String
});

const Usermodel = mongoose.model('User', UserSchema);
module.exports = Usermodel