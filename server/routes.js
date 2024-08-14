const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const authMiddleware = require('./authMiddleware');

const router = express.Router();
const usersFilePath = './server/users.json';
const secretKey = 'supersecretkey';

// Helper function to read users from the JSON file
const readUsers = () => {
    const data = fs.readFileSync(usersFilePath);
    return JSON.parse(data);
};

// Helper function to write users to the JSON file
const writeUsers = (users) => {
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
};

// Sign-up route
router.post('/signup', (req, res) => {
    const { username, password, role } = req.body;
    const users = readUsers();

    if (users.find(user => user.username === username)) {
        return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = bcrypt.hashSync(password, 8);
    const newUser = { username, password: hashedPassword, role };
    users.push(newUser);
    writeUsers(users);

    res.status(201).json({ message: 'User created successfully' });
});

// Login route
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    const users = readUsers();
    const user = users.find(user => user.username === username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ username: user.username, role: user.role }, secretKey, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
});

// Protected route
router.get('/protected', authMiddleware(secretKey), (req, res) => {
    res.json({ message: `Hello, ${req.user.username}! You have access to this protected route.` });
});

module.exports = router;
