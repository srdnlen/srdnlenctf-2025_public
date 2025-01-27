const mongoose = require('mongoose')

const DiscountCodeSchema = new mongoose.Schema({
    discountCode: {
        type: String,
        default: null, // Optional field for discount codes
    },
    value: {
        type: Number,
        default: 10
    }
})

module.exports = mongoose.model('DiscountCodes', DiscountCodeSchema)
