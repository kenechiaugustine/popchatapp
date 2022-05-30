const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
   
    email: {
        type: String,
        required: true,
        unique: true
    },
    role: {
        type: String,
        default: 'user',
        enum: ['user', 'admin']
    },
    password: {
        type: String,
        required: true
    },
}, {
    collection: 'chat-users'
});

const User = mongoose.model('User', userSchema);

module.exports = User;