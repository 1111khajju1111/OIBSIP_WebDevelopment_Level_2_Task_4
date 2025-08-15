// =======================
//  server.js
// =======================
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();

// =======================
//  CONFIG
// =======================
const PORT = 3000;
const MONGO_URI = 'mongodb://127.0.0.1:27017/auth_demo';
const SESSION_SECRET = 'your_super_secret_key';

// =======================
//  MIDDLEWARE
// =======================
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGO_URI }),
    cookie: { maxAge: 1000 * 60 * 60 } // 1 hour
}));

// Serve static files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, 'public')));

// =======================
//  DB CONNECTION
// =======================
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ MongoDB connected'))
    .catch(err => console.error(err));

// =======================
//  USER MODEL
// =======================
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// =======================
//  ROUTES
// =======================

// Register
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) return res.status(400).json({ message: 'All fields are required' });

    const userExists = await User.findOne({ username });
    if (userExists) return res.status(400).json({ message: 'Username already taken' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.json({ message: 'Registration successful' });
});

// Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: 'Invalid username or password' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid username or password' });

    req.session.userId = user._id;
    res.json({ message: 'Login successful' });
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ message: 'Logout failed' });
        res.clearCookie('connect.sid');
        res.json({ message: 'Logged out' });
    });
});

// Protected route example
app.get('/dashboard', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ message: 'Unauthorized' });
    res.json({ message: 'Welcome to your dashboard!' });
});

// =======================
//  START SERVER
// =======================
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
