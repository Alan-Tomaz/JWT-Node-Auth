require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// Config JSON response
app.use(express.json());

// Models
const User = require('./models/User');

// Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({ msg: "Welcome to my API" });
});

// Private Route
app.get("/user/:id", checkToken, async (req, res) => {
    const { id } = req.params;

    // check if user exists
    const user = await User.findById(id, '-password');

    if (!user) {
        return res.status(404).json({ msg: "User Doesn't Exists" });
    }

    return res.status(200).json({ user });
})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ msg: "Access Denied!" });
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret);

        next();
    } catch (error) {
        res.status(400).json({ msg: "Invalid Token!" });
    }
}

// Register User
app.post('/auth/register', async (req, res) => {

    const { name, email, password, confirmPassword } = req.body;

    if (!name) {
        return res.status(422).json({ msg: "The name is required" })
    }

    if (!email) {
        return res.status(422).json({ msg: "The email is required" })
    }

    if (!password) {
        return res.status(422).json({ msg: "The password is required" })
    }

    if (!confirmPassword) {
        return res.status(422).json({ msg: "The confirm password is required" })
    }

    if (password !== confirmPassword) {
        return res.status(422).json({ msg: "The passwords doesn't match" });
    }

    // check if user exists
    const userExists = await User.findOne({ email: email });

    if (userExists) {
        return res.status(422).json({ msg: "Email already exists" });
    }

    // create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {
        await user.save();

        res.status(201).json({ msg: "User created Successfully" });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ msg: "Something goes wrong!" });
    }
});

// Login User
app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;

    //validations

    if (!email) {
        return res.status(422).json({ msg: "The name is required" })
    }
    if (!password) {
        return res.status(422).json({ msg: "The password is required" })
    }

    // check if user exists
    const user = await User.findOne({ email: email });

    if (!user) {
        return res.status(404).json({ msg: "User doesn't exists" });
    }

    // check if password match
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(422).json({ msg: "Invalid Password!" });

    }

    try {
        const secret = process.env.SECRET;

        const token = jwt.sign({
            id: user._id
        }, secret);

        res.status(200).json({ msg: "Authenticated Successfully", token });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ msg: "Something goes wrong!" });
    }
})

// Credencials
const port = process.env.PORT || 3000;
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.klfjqc3.mongodb.net/?retryWrites=true&w=majority`).then(() => {
    app.listen(port, () => {
        console.log("App is Running");
    })
    console.log("Connected With Database");
}).catch((err) => console.log(err));