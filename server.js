require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const { Resend } = require('resend');

const app = express();

/* =========================
   RESEND
   ========================= */
const resend = new Resend(process.env.RESEND_API_KEY);

/* =========================
   CORS
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
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error(err);
    process.exit(1);
  });

/* =========================
   USER MODEL
   ========================= */
const User = mongoose.model('User', new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  emailVerified: { type: Boolean, default: false },
  verificationToken: String,
  name: { type: String, default: '' },
  avatar: { type: String, default: '' },
  notes: { type: Array, default: [] }
}));

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
   SIGNUP (EMAIL VERIFY)
   ========================= */
app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: 'Missing fields' });

    if (await User.findOne({ email }))
      return res.status(400).json({ message: 'User exists' });

    const hashed = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString('hex');

    await User.create({
      email,
      password: hashed,
      verificationToken
    });

    const verifyLink =
      `${process.env.APP_URL}/verify-email?token=${verificationToken}`;

    await resend.emails.send({
      from: 'Deutschio <onboarding@resend.dev>',
      to: email,
      subject: 'Verify your email',
      html: `
        <h2>Welcome to Deutschio 🇩🇪</h2>
        <p>Please verify your email by clicking the link below:</p>
        <a href="${verifyLink}">${verifyLink}</a>
      `
    });

    res.status(201).json({
      message: 'Signup successful. Check your email to verify your account.'
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* =========================
   VERIFY EMAIL
   ========================= */
app.get('/verify-email', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Invalid link');

  const user = await User.findOne({ verificationToken: token });
  if (!user) return res.status(400).send('Invalid or expired token');

  user.emailVerified = true;
  user.verificationToken = null;
  await user.save();

  res.send('<h2>Email verified ✅ You can now login.</h2>');
});

/* =========================
   LOGIN
   ========================= */
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: 'Invalid credentials' });

    if (!user.emailVerified)
      return res.status(403).json({ message: 'Please verify your email first' });

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
   PROFILE
   ========================= */
app.get('/profile', auth, async (req, res) => {
  const user = await User.findById(req.userId).select('-password');
  res.json(user);
});

/* =========================
   FRONTEND
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
