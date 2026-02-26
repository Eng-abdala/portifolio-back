const mongoose = require('mongoose');
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const User = require('./model/User');

// simple hard‑coded secret, no .env
const JWT_SECRET = 'your_jwt_secret_key'; // change for production if needed

const app = express();

// Parse JSON bodies from frontend
app.use(express.json());

// Custom CORS + Private Network Access handler
// no environment variable, list origins here if required
const allowedOrigins = []; // e.g. ['https://example.com']

app.use((req, res, next) => {
    const origin = req.get('origin');
    if (origin) {
        // If ALLOWED_ORIGINS is configured, only allow matching origins
        if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
            res.setHeader('Vary', 'Origin');
            res.setHeader('Access-Control-Allow-Credentials', 'true');
        }
    }

    res.setHeader('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // If browser sent a private-network preflight request header, allow it
    if (req.headers['access-control-request-private-network']) {
        res.setHeader('Access-Control-Allow-Private-Network', 'true');
    }

    // Handle preflight
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});


// Connect to MongoDB using a fixed connection string
mongoose.connect('mongodb+srv://ciilanesalaad482561_db_user:ttx0RSDTs6dXdZv8@cluster0.gnx3g4f.mongodb.net/?appName=Cluster0', {
    useNewUrlParser: true,  
    useUnifiedTopology: true
})
.then(() => {
    console.log('Connected to MongoDB');
})
.catch((error) => {
    console.error('Error connecting to MongoDB:', error);
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
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        const existing = await User.findOne({ username });
        if (existing) return res.status(409).json({ error: 'Username already exists' });
        // Store password as plaintext (development/simple mode)
        const user = new User({ username, password });
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
        // Simple plaintext comparison (no hashing)
        if (user.password !== lookupPassword) return res.status(401).json({ error: 'Invalid password' });
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
        // Set plaintext password (dev helper)
        user.password = password;
        await user.save();
        res.json({ message: 'Password updated for user' });
    } catch (err) {
        console.error('Dev set-password error:', err);
        res.status(500).json({ error: 'Error updating password' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
