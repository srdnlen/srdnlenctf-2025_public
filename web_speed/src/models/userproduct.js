const mongoose = require('mongoose')

const UserProductsSchema = new mongoose.Schema({
    transactionId: {
        type: String,
        required: true,
        unique: true // Ensure the transaction ID is unique
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product',
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now // Automatically store when the user buys the product
    },
    discountCode: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'DiscountCodes',
        default: null, // Optional field for discount codes
    },
})

module.exports = mongoose.model('UserProducts', UserProductsSchema)
