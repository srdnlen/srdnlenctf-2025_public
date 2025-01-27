const path = require('path');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const express = require('express');
const User = require('../models/user');
const Product = require('../models/product'); 
const DiscountCodes = require('../models/discountCodes'); 
const passport = require('passport');
const { engine } = require('express-handlebars');
const { Strategy: JwtStrategy } = require('passport-jwt');
const cookieParser = require('cookie-parser');

function DB(DB_URI, dbName) {
    return new Promise((res, _) => {
        mongoose.set('strictQuery', false);
        mongoose
            .connect(DB_URI, { useNewUrlParser: true, useUnifiedTopology: true, dbName })
            .then(() => res());
    });
}

// Generate a random discount code
const generateDiscountCode = () => {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let discountCode = '';
    for (let i = 0; i < 12; i++) {
        discountCode += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return discountCode;
};



async function App() {
    const app = express();
    app.use(passport.initialize());
    app.use(cookieParser());
    app.use(bodyParser.json());

    app.engine('hbs', engine({ extname: '.hbs', defaultLayout: 'base' }));

    app.use(express.static('static'));
    app.set('view engine', 'hbs');
    app.set('views', path.join(__dirname, '../webviews'));

    app.use('/', require('./routes'));

    passport.use('user-local', User.createStrategy());
    const option = {
        secretOrKey: process.env.JWT_SECRET,
        jwtFromRequest: (req) => req?.cookies?.['jwt'],
        algorithms: ['HS256'],
    };

    

    passport.use(
        new JwtStrategy(option, (payload, next) => {
            User.findOne({ _id: payload.userId })
                .then((user) => {
                    next(null, { userId: user._id } || false);
                })
                .catch((_) => next(null, false));
        })
    );

    const products = [
        { productId: 1, Name: "Lightning McQueen Toy", Description: "Ka-chow! This toy goes as fast as Lightning himself.", Cost: "Free" },
        { productId: 2, Name: "Mater's Tow Hook", Description: "Need a tow? Mater's here to save the day (with a little dirt on the side).", Cost: "1 Point" },
        { productId: 3, Name: "Doc Hudson's Racing Tires", Description: "They're not just any tires, they're Doc Hudson's tires. Vintage!", Cost: "2 Points" },
        { 
            productId: 4, 
            Name: "Lightning McQueen's Secret Text", 
            Description: "Unlock Lightning's secret racing message! Only the fastest get to know the hidden code.", 
            Cost: "50 Points", 
            FLAG: process.env.FLAG || 'SRDNLEN{fake_flag}' 
        }
    ];
    

    for (const productData of products) {
        const existingProduct = await Product.findOne({ productId: productData.productId });
        if (!existingProduct) {
            await Product.create(productData);
            console.log(`Inserted productId: ${productData.productId}`);
        } else {
            console.log(`Product with productId: ${productData.productId} already exists.`);
        }
    }

    // Insert randomly generated Discount Codes if they don't exist
    const createDiscountCodes = async () => {
        const discountCodes = [
            { discountCode: generateDiscountCode(), value: 20 }
        ];

        for (const code of discountCodes) {
            const existingCode = await DiscountCodes.findOne({ discountCode: code.discountCode });
            if (!existingCode) {
                await DiscountCodes.create(code);
                console.log(`Inserted discount code: ${code.discountCode}`);
            } else {
                console.log(`Discount code ${code.discountCode} already exists.`);
            }
        }
    };

    // Call function to insert discount codes
    await createDiscountCodes();

    app.use('/', (req, res) => {
        res.status(404);
        if (req.accepts('html') || req.accepts('json')) {
            return res.render('notfound');
        }
    });

    return app;
}

module.exports = { DB, App };
