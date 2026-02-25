const mongoose = require('mongoose');
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('./model/User');

const JWT_SECRET = 'your_jwt_secret_key'; // Replace with env variable in production

const app = express();
app.use(cors());
app.use(express.json());

// Connect to MongoDB
 mongoose.connect('mongodb+srv://ciilanesalaad482561_db_user:ttx0RSDTs6dXdZv8@cluster0.gnx3g4f.mongodb.net/?appName=Cluster0').then(() => {
    //mongoose.connect('mongodb://localhost:27017/portifolio').then(() => {
    console.log('Connected to MongoDB');
}).catch((err) => {
    console.error('Error connecting to MongoDB:', err);
});





const messageschema = require('./model/message');

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Register Route (Temporary/Helper)
app.post('/api/register', async (req, res) => {
    try {
        console.log('Register request body:', req.body);
        let { username, password } = req.body || {};
        username = typeof username === 'string' ? username.trim() : username;
        password = typeof password === 'string' ? password : password;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Register error:', error);
        // Handle duplicate username error from MongoDB
        if (error && error.code === 11000) {
            return res.status(409).json({ error: 'Username already exists' });
        }
        // If validation error (bad input), send 400
        if (error && error.name === 'ValidationError') {
            return res.status(400).json({ error: 'Invalid input', details: error.message });
        }
        res.status(500).json({ error: 'Error registering user' });
    }
});

// Login Route
app.post('/api/login', async (req, res) => {
    try {
        console.log('Login request body:', req.body);
        const { username, password } = req.body || {};
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        // normalize input
        const lookupUsername = typeof username === 'string' ? username.trim() : username;
        const lookupPassword = password;

        const user = await User.findOne({ username: lookupUsername });
        if (!user) return res.status(404).json({ error: 'User not found' });

        console.log('Found user for login:', {
            username: user.username,
            passwordIsHashed: typeof user.password === 'string' && user.password.startsWith('$2'),
            passwordLength: user.password ? user.password.length : 0,
        });

        let validPassword = false;
        try {
            if (typeof user.password === 'string' && user.password.startsWith('$2')) {
                validPassword = await bcrypt.compare(lookupPassword, user.password);
                console.log('bcrypt.compare result:', validPassword);
            } else {
                // Possibly plaintext stored in DB
                    console.log('Stored password does not appear hashed; comparing plaintext');
                    const plaintextMatch = user.password === lookupPassword;
                    console.log('Plaintext compare result:', plaintextMatch);
                    if (plaintextMatch) {
                        validPassword = true;
                    try {
                        const newHash = await bcrypt.hash(lookupPassword, 10);
                        user.password = newHash;
                        await user.save();
                        console.log('Migrated plaintext password to bcrypt for user:', lookupUsername);
                    } catch (upErr) {
                        console.error('Error migrating plaintext password:', upErr);
                    }
                }
            }
        } catch (cmpErr) {
            console.error('Password compare error:', cmpErr);
        }

        if (!validPassword) return res.status(401).json({ error: 'Invalid password' });

        const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '6h' });
        res.json({ token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Error logging in' });
    }
});

app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, message } = req.body;
        const newMessage = new messageschema({ name, email, message });
        await newMessage.save();
        res.status(201).json({ message: 'Message saved successfully' });
    } catch (error) {
        console.error('Error saving message:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

//get API to fetch contact messages
app.get('/api/contact', authenticateToken, async (req, res) => {
    try {
        const messages = await messageschema.find();
        res.json(messages);
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Dev-only: set a user's password (hashes it). Protect with a simple secret.
app.post('/api/dev/set-password', async (req, res) => {
    try {
        const { username, password, secret } = req.body || {};
        if (secret !== 'dev-secret-key') return res.status(403).json({ error: 'Forbidden' });
        if (!username || !password) return res.status(400).json({ error: 'username and password required' });
        const user = await User.findOne({ username: username.trim() });
        if (!user) return res.status(404).json({ error: 'User not found' });
        const hashed = await bcrypt.hash(password, 10);
        user.password = hashed;
        await user.save();
        res.json({ message: 'Password updated for user' });
    } catch (err) {
        console.error('Dev set-password error:', err);
        res.status(500).json({ error: 'Error updating password' });
    }
});

app.listen(5000, () => {
    console.log('Server is running on http://localhost:5000');
});
