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
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Error registering user' });
    }
});

// Login Route
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'User not found' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid password' });

        const token = jwt.sign({ username: user.username }, JWT_SECRET);
        res.json({ token });
    } catch (error) {
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

app.listen(5000, () => {
    console.log('Server is running on http://localhost:5000');
});