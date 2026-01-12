require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');

const app = express();

/* =========================
   CORS — FINAL FIX
   ========================= */
app.use(cors({
  origin: [
    'https://ddeutschio.netlify.app',
    'http://127.0.0.1:5500',
    'http://localhost:5500'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

/* =========================
   MIDDLEWARE
   ========================= */
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/* =========================
   DATABASE
   ========================= */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('Mongo error:', err);
    process.exit(1);
  });

/* =========================
   MODEL
   ========================= */
const User = mongoose.model(
  'User',
  new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, default: '' },
    avatar: { type: String, default: '' },
    notes: { type: Array, default: [] }
  })
);

/* =========================
   AUTH MIDDLEWARE
   ========================= */
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: 'No token' });

  try {
    const token = header.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

/* =========================
   AUTH ROUTES
   ========================= */
app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: 'Missing fields' });

    if (await User.findOne({ email }))
      return res.status(400).json({ message: 'User exists' });

    const hashed = await bcrypt.hash(password, 10);
    await User.create({ email, password: hashed });

    res.status(201).json({ message: 'Signup success' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok)
      return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* =========================
   PROFILE ROUTES
   ========================= */
app.get('/profile', auth, async (req, res) => {
  const user = await User.findById(req.userId).select('-password');
  res.json(user);
});

app.put('/profile', auth, async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.userId,
    req.body,
    { new: true }
  ).select('-password');
  res.json(user);
});

app.put('/name', auth, async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.userId,
    { name: req.body.name },
    { new: true }
  ).select('-password');
  res.json(user);
});

app.delete('/profile', auth, async (req, res) => {
  await User.findByIdAndDelete(req.userId);
  res.json({ message: 'Account deleted' });
});

/* =========================
   FRONTEND FALLBACK
   ========================= */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

/* =========================
   START
   ========================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Server running on port ${PORT}`)
);
