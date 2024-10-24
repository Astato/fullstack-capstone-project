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


router.post('/register', validateData(), async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        res.json({message:"invalid input"})
    }
    try {
        const db = await connectToDatabase()
        const collection = db.collection("users")
        const existingEmail = await collection.findOne({ email: req.body.email });
        const email = req.body.email
        const hash = bcryptjs.hash(req.body.password, 10)

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
        return res.status(500).json({message:"An internal error has ocurred"})
    }
});

module.exports = router;