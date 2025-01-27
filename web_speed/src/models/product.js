const mongoose = require('mongoose')

const productSchema = new mongoose.Schema({
    productId: {
        type: Number,
        required: true,
        unique: true
    },
    Name: {
        type: String,
        required: true,
        unique: true
    },
    Description: {
        type: String,
        required: true,
        default: ''
    },
    Cost: {
        type: String,
        required: true,
        default: '15 Points'
    },
    FLAG: {
        type: String
    }
})

module.exports = mongoose.model('Product', productSchema)
