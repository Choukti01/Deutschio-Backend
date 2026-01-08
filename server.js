require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

/* =========================
   CORS — FINAL (REAL FINAL)
   ========================= */
const allowedOrigins = [
  'http://127.0.0.1:5500',
  'http://localhost:5500',
  'https://ddeutschio.netlify.app'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // allow curl/postman
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('CORS blocked'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

/* =========================
   DATABASE
   ========================= */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('Mongo error:', err.message);
    process.exit(1);
  });

/* =========================
   USER MODEL
   ========================= */
const User = mongoose.model(
  'User',
  new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
  })
);

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
   HEALTH
   ========================= */
app.get('/', (_, res) => res.send('Deutschio backend OK'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running on', PORT));
