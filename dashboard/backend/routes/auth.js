const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { verifyToken } = require('../middleware/auth');

const router = express.Router();

// POST /api/auth/register
router.post('/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required.' });
    }

    const existing = await User.findOne({ username });
    if (existing) {
      return res.status(409).json({ error: 'Username already exists.' });
    }

    const user = new User({
      username,
      passwordHash: password, // pre-save hook will hash it
      role: role || 'user',
    });
    await user.save();

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User registered successfully.',
      token,
      user: user.toJSON(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required.' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Audit log
    await AuditLog.create({
      userId: user._id,
      username: user.username,
      action: 'LOGIN',
      details: `User logged in as ${user.role}`,
      ipAddress: req.ip,
    });

    res.json({ token, user: user.toJSON() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/auth/me
router.get('/me', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-passwordHash');
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/auth/profile — Update username or password
router.put('/profile', verifyToken, async (req, res) => {
  try {
    const { username, newPassword } = req.body;
    const user = await User.findById(req.user.id);
    
    if (!user) return res.status(404).json({ error: 'User not found.' });

    if (username && username !== user.username) {
      const existing = await User.findOne({ username });
      if (existing) return res.status(409).json({ error: 'Username already taken.' });
      user.username = username;
    }

    if (newPassword) {
      user.passwordHash = newPassword; // Pre-save hook will hash
    }

    await user.save();

    // Audit log
    await AuditLog.create({
      userId: user._id,
      username: user.username,
      action: 'UPDATE_PROFILE',
      details: `User updated ${newPassword ? 'password and ' : ''}username`,
      ipAddress: req.ip,
    });

    res.json({ message: 'Profile updated successfully.', user: user.toJSON() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
