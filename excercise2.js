const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your-secret-key'; // Replace with a strong secret key
const REFRESH_SECRET_KEY = 'your-refresh-secret-key'; // Separate key for refresh tokens

app.use(bodyParser.json());

// Mock user data with roles
const users = [
    { id: 1, username: 'admin', password: 'admin123', role: 'admin' },
    { id: 2, username: 'user', password: 'user123', role: 'user' }
];

// Store refresh tokens (in a real-world scenario, use a database)
let refreshTokens = [];

// Middleware to verify JWT
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1]; // Extract token from "Bearer <token>"

        jwt.verify(token, SECRET_KEY, (err, user) => {
            if (err) {
                return res.sendStatus(403); // Forbidden if token is invalid
            }

            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401); // Unauthorized if no token is provided
    }
};

// Middleware to check if the user has the required role
const checkRole = (role) => {
    return (req, res, next) => {
        if (req.user.role === role) {
            next();
        } else {
            res.sendStatus(403); // Forbidden if the user doesn't have the required role
        }
    };
};

// Sign in route to generate access token and refresh token
app.post('/signin', (req, res) => {
    const { username, password } = req.body;

    // Find user in mock data
    const user = users.find(u => u.username === username && u.password === password);

    if (user) {
        // Generate an access token (short-lived)
        const accessToken = jwt.sign({ username: user.username, id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '15m' });

        // Generate a refresh token (long-lived)
        const refreshToken = jwt.sign({ username: user.username, id: user.id, role: user.role }, REFRESH_SECRET_KEY, { expiresIn: '7d' });

        // Store the refresh token
        refreshTokens.push(refreshToken);

        // Return both tokens
        res.json({ accessToken, refreshToken });
    } else {
        res.status(401).json({ message: 'Invalid credentials' });
    }
});

// Route to refresh the access token
app.post('/refresh', (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.sendStatus(401); // Unauthorized if no refresh token is provided
    }

    if (!refreshTokens.includes(refreshToken)) {
        return res.sendStatus(403); // Forbidden if the refresh token is invalid
    }

    // Verify the refresh token
    jwt.verify(refreshToken, REFRESH_SECRET_KEY, (err, user) => {
        if (err) {
            return res.sendStatus(403); // Forbidden if the refresh token is invalid
        }

        // Generate a new access token
        const accessToken = jwt.sign({ username: user.username, id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '15m' });

        // Return the new access token
        res.json({ accessToken });
    });
});

// Logout route to invalidate the refresh token
app.post('/logout', (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.sendStatus(400); // Bad request if no refresh token is provided
    }

    // Remove the refresh token from the list
    refreshTokens = refreshTokens.filter(token => token !== refreshToken);

    res.sendStatus(204); // No content
});

// GET /posts - Accessible to both admin and user roles
app.get('/posts', authenticateJWT, (req, res) => {
    const posts = [
        'early bird catches the worm',
        'a stitch in time saves nine',
        'the pen is mightier than the sword'
    ];

    res.json(posts);
});

// POST /posts - Accessible only to admin role
app.post('/posts', authenticateJWT, checkRole('admin'), (req, res) => {
    const { message } = req.body;

    if (message) {
        res.json({ message: 'Post added successfully' });
    } else {
        res.status(400).json({ message: 'Message is required' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});