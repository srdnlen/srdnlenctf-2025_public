const express = require('express')
const isAuth = (req, res, next) => {passport.authenticate('jwt', { session: false, failureRedirect: '/user-login' })(req, res, next)}
const JWT = require('jsonwebtoken')
const router = express.Router()
const passport = require('passport')
const UserProducts = require('../models/userproduct'); // Assuming you have the model for UserProducts
const Product = require('../models/product'); // Assuming you have the model for Product
const User = require('../models/user'); // Assuming you have the model for User
const DiscountCodes = require('../models/discountCodes')
const { v4: uuidv4 } = require('uuid');

let sleep_time = 1.5;

router.get('/store', isAuth, async (req, res) => {
    try{
        const all = await Product.find()
        const products = []
        for(let p of all) {
            products.push({ productId: p.productId, Name: p.Name, Description: p.Description, Cost: p.Cost })
        }
        const user = await User.findById(req.user.userId);
        return res.render('store', { Authenticated: true, Balance: user.Balance, Product: products})
    } catch{
        return res.render('error', { Authenticated: true, message: 'Error during request' })
    }
})


router.get('/redeem', isAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);

        if (!user) {
            return res.render('error', { Authenticated: true, message: 'User not found' });
        }

        // Now handle the DiscountCode (Gift Card)
        let { discountCode } = req.query;  // Assuming you're passing the discount code in the query
        
        if (!discountCode) {
            return res.render('error', { Authenticated: true, message: 'Discount code is required!' });
        }

        const discount = await DiscountCodes.findOne({discountCode})

        if (!discount) {
            return res.render('error', { Authenticated: true, message: 'Invalid discount code!' });
        }

        // Check if the voucher has already been redeemed today
        const today = new Date();
        const lastRedemption = user.lastVoucherRedemption;

        if (lastRedemption) {
            const isSameDay = lastRedemption.getFullYear() === today.getFullYear() &&
                              lastRedemption.getMonth() === today.getMonth() &&
                              lastRedemption.getDate() === today.getDate();
            if (isSameDay) {
                return res.json({success: false, message: 'You have already redeemed your gift card today!' });
            }
        }

        // Apply the gift card value to the user's balance
        const { Balance } = await User.findById(req.user.userId).select('Balance');
        user.Balance = Balance + discount.value;
        // Introduce a slight delay to ensure proper logging of the transaction 
        // and prevent potential database write collisions in high-load scenarios.
        new Promise(resolve => setTimeout(resolve, sleep_time * 1000));
        user.lastVoucherRedemption = today;
        await user.save();

        return res.json({
            success: true,
            message: 'Gift card redeemed successfully! New Balance: ' + user.Balance // Send success message
        });

    } catch (error) {
        console.error('Error during gift card redemption:', error);
        return res.render('error', { Authenticated: true, message: 'Error redeeming gift card'});
    }
});

router.get('/redeemVoucher', isAuth, async (req, res) => {
    const user = await User.findById(req.user.userId);
    return res.render('redeemVoucher', { Authenticated: true, Balance: user.Balance })
});

router.get('/register-user', (req, res) => {
    return res.render('register-user')
})

router.post('/register-user', (req, res, next) => {
    let { username , password } = req.body
    if (username == null || password == null){
        return next({message: "Error"})
    }
    if(!username || !password) {
        return next({ message: 'You forgot to enter your credentials!' })
    }
    if(password.length <= 2) {
        return next({ message: 'Please choose a longer password.. :-(' })
    }

    User.register(new User({ username }), password, (err, user) => {
        if(err && err.toString().includes('registered')) {
            return next({ message: 'Username taken' })
        } else if(err) {
            return next({ message: 'Error during registration' })
        }

        const jwtoken = JWT.sign({userId: user._id}, process.env.JWT_SECRET, {algorithm: 'HS256',expiresIn: '10h'})
        res.cookie('jwt', jwtoken, { httpOnly: true })

        return res.json({success: true, message: 'Account registered.'})
    })
})

router.get('/user-login', (req, res) => {
    return res.render('user-login')
})

router.post('/user-login', (req, res, next) => {
    passport.authenticate('user-local', (_, user, err) => {
        if(err) {
            return next({ message: 'Error during login' })
        }

        const jwtoken = JWT.sign({userId: user._id}, process.env.JWT_SECRET, {algorithm: 'HS256',expiresIn: '10h'})
        res.cookie('jwt', jwtoken, { httpOnly: true })

        return res.json({
            success: true,
            message: 'Logged'
        })
    })(req, res, next)
})

router.get('/user-logout', (req, res) => {
    res.clearCookie('jwt')
    res.redirect('/')
})

function parseCost(cost) {
    if (cost.toLowerCase() === "free") {
        return 0;
    }
    const match = cost.match(/\d+/); // Extract numbers from the string
    return match ? parseInt(match[0], 10) : NaN; // Return the number or NaN if not found
}

router.post('/store', isAuth, async (req, res, next) => {
    const productId = req.body.productId;

    if (!productId) {
        return next({ message: 'productId is required.' });
    }

    try {
        // Find the product by Name
        const all = await Product.find()
        product = null
        for(let p of all) {
            if(p.productId === productId){
                product = p
            }
        }

        if (!product) {
            return next({ message: 'Product not found.' });
        }

        // Parse the product cost into a numeric value
        let productCost = parseCost(product.Cost);  

        if (isNaN(productCost)) {
            return next({ message: 'Invalid product cost format.' });
        }

        // Fetch the authenticated user
        const user = await User.findById(req.user.userId);

        if (!user) {
            return next({ message: 'User not found.' });
        }

        // Check if the user can afford the product
        if (user.Balance >= productCost) {
            // Generate a UUID v4 as a transaction ID
            const transactionId = uuidv4();
            
            // Deduct the product cost and save the user
            user.Balance -= productCost;
            await user.save();

            // Create a new UserProduct entry
            const userProduct = new UserProducts({
                transactionId: transactionId,
                user: user._id,
                productId: product._id, // Reference the product purchased
            });

            await userProduct.save(); // Save the UserProduct entry

            // Add the UserProduct reference to the user's ownedproducts array
            if (!user.ownedproducts.includes(userProduct._id)) {
                user.ownedproducts.push(userProduct._id);
                await user.save(); // Save the updated user
            }

            // Prepare the response data
            const responseData = {
                success: true,
                message: `Product correctly bought! Remaining balance: ${user.Balance}`,
                product: {
                    Name: product.Name,
                    Description: product.Description,
                },
            };
            if (product.productId === 4) {
                responseData.product.FLAG = product.FLAG || 'No flag available';
            }

            return res.json(responseData);
        } else {
            return res.json({success: false, message: 'Insufficient balance to purchase this product.' });
        }
    } catch (error) {
        console.error('Error during product payment:', error);
        return res.json({success: false, message: 'An error occurred during product payment.' });
    }
});

router.get('/', (req, res, next) => {
    passport.authenticate('jwt', async (err, r) => {
        let { userId } = r
        if (!userId) {
            return res.render('home', {
                Authenticated: false
            })
        }

        try {
            // Fetch the user and populate the ownedproducts, which are UserProducts
            const user = await User.findById(userId)
                .populate({
                    path: 'ownedproducts', // Populate the UserProducts
                    populate: {
                        path: 'productId', // Populate the product details
                        model: 'Product' // The model to fetch the product details
                    }
                })
                .exec()

            // Map the owned products with product details and transactionId
            const ownedproducts = user.ownedproducts.map((userProduct) => {
                const product = userProduct.productId; // Access the populated product details
                return {
                    Name: product.Name,           // Name of the product
                    Description: product.Description, // Description of the product
                    Cost: product.Cost,             // Cost of the product
                    FLAG: product.FLAG || null,      // Flag (only exists for certain products)
                    transactionId: userProduct.transactionId // Add transactionId here
                }
            })

            return res.render('home', {
                Authenticated: true,
                username: user.username,
                Balance: user.Balance,  // Pass balance as a variable to the template
                ownedproducts: ownedproducts // Pass the products with transactionId
            })
        } catch (err) {
            console.error('Error fetching user or products:', err)
            return next(err) // Handle any errors (e.g., database issues)
        }
    })(req, res, next)
})

router.use((err, req, res, next) => {
    res.status(err.status || 400).json({
        success: false,
        error: err.message || 'Invalid Request',
    })
})

module.exports = router