const mongoose = require('mongoose')
const passportLocalMongoose = require('passport-local-mongoose')

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true // Ensuring the username is unique
    },
    passwd: {
        type: String
    },
    Balance: {
        type: Number,
        default: 0
    },
    lastVoucherRedemption: {
        type: Date,
        default: null
    },
    ownedproducts: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'UserProducts'
    }]
})

userSchema.plugin(passportLocalMongoose, {
    session: false
})

module.exports = mongoose.model('User', userSchema)