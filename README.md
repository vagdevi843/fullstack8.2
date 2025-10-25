# fullstack8.2
// server.js
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());

// Dummy user (password: 12345)
const users = [
  {
    id: 1,
    username: 'admin',
    // Hashed password for '12345'
    password: '$2a$10$Ww1yEZaXThsE1d7R5LJbSOkm8gNgPT9T.lRSUks3lyweBlgl01Xve'
  }
];

// Secret key for signing JWTs
const JWT_SECRET = 'my_secret_key';

// 🟢 Login route — generates a JWT for valid users
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Find user in dummy list
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ message: 'User not found' });

  // Check password
  const validPass = await bcrypt.compare(password, user.password);
  if (!validPass) return res.status(400).json({ message: 'Invalid password' });

  // Create JWT token
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ message: 'Login successful', token });
});

// 🟡 Middleware — verifies the JWT token before giving access
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer <token>"

  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified; // Attach user info to request
    next();
  } catch (err) {
    res.status(403).json({ message: 'Invalid or expired token' });
  }
}

// 🔒 Protected route — only accessible with valid JWT
app.get('/dashboard', verifyToken, (req, res) => {
  res.json({ message: `Welcome, ${req.user.username}! You have access to the dashboard.` });
});

// 🌐 Public route — anyone can access
app.get('/', (req, res) => {
  res.send('Public route: Anyone can access this.');
});

// Start the server
app.listen(5000, () => console.log('✅ Server running on http://localhost:5000'));
