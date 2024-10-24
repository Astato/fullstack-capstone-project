const express = require("express")
const router = express.Router()
const jwt = require("jsonwebtoken")
const bcryptjs = require('bcryptjs');
const dotenv = require('dotenv');
const pino = require('pino');
const connectToDatabase = require('../models/db');
const { body, validationResult } = require('express-validator');

const logger = pino();  // Create a Pino logger instance
//Step 1 - Task 3: Create a Pino logger instance

dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;

//Step 1 - Task 4: Create JWT secret

const validateData = () => [
    body("firstName").notEmpty(),
    body("email").isEmail(),
     body("lastName").notEmpty()]

const validateLogin = () => [
    body("email").isEmail(),
    body("password").notEmpty()
]

router.post('/register', validateData(), async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.json({error:"invalid input"})
    }
    try {
        const db = await connectToDatabase()
        const collection = db.collection("users")
        const existingEmail = await collection.findOne({ email: req.body.email });
        if(existingEmail){
            return res.json({error:"Email already registered"})
        }
        const email = req.body.email
        const hash = await bcryptjs.hash(req.body.password, 10)

            const newUser = await collection.insertOne({
            email: email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        });
        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };
        const authToken = jwt.sign(payload, JWT_SECRET);
        logger.info("User registered");
        return res.json({authToken, email})
  

    } catch (error) {
        return res.status(500).json({error:"An internal error has ocurred"})
    }
});


router.post("/login", validateLogin(), async(req,res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
       return  res.json({error:"invalid input or missing data"})
    }
    try {
        const db = await connectToDatabase()
        const collection = db.collection("users")
        const user = await collection.findOne({ email: req.body.email });
        if(user){
            const compare = await bcryptjs.compare(req.body.password, user.password)
            if(!compare){
                logger.error("Password do not match")
                return res.status(404).json({error:"Wrong password"})
            } 
            const username = user.firstName
            const email = user.email;
            const payload = {
                user:{
                    id: user._id
                }
            }
            const authToken = jwt.sign(payload, JWT_SECRET)

            return res.json({authToken, username, email})
        } else{
            logger.error("Email not found")
            return res.status(404).json({error:"Email not found"})
        }
        
    } catch (error) {
        return res.status(500).json({error:'Internal server error'});
    }
})


router.put('/update', async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.error('Validation errors in update request', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const email = req.headers.email;
        if (!email) {
            logger.error('Email not found in the request headers');
            return res.status(400).json({ error: "Email not found in the request headers" });
        }
        const db = await connectToDatabase();
        const collection = db.collection("users");
        const existingUser = await collection.findOne({ email });
        if (!existingUser) {
            logger.error('User not found');
            return res.status(404).json({ error: "User not found" });
        }
        existingUser.firstName = req.body.name;
        existingUser.updatedAt = new Date();
        //Task 6: Update user credentials in DB
        const updatedUser = await collection.findOneAndUpdate(
            { email },
            { $set: existingUser },
            { returnDocument: 'after' }
        );

        if(updatedUser){
            //Task 7: Create JWT authentication with user._id as payload using secret key from .env file
            const payload = {
                user: {
                    id: updatedUser._id,
                },
            };
            const authToken = jwt.sign(payload, JWT_SECRET);
            logger.info('User updated successfully');
            res.json({ authToken });
        }
    } catch (error) {
        logger.error(error);
        return res.status(500).send("Internal Server Error");
    }
});


module.exports = router;