require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

app.use(cors());           // ✅ this is enough
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, default: '' },
  avatar: { type: String, default: '' },
  notes: [{ text: String, createdAt: Date }]
});

const User = mongoose.model('User', userSchema);

// -------- PROFILE ROUTES --------

app.put('/profile/avatar', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    await User.findByIdAndUpdate(decoded.id, { avatar: req.body.avatar });
    res.sendStatus(200);
  } catch {
    res.sendStatus(401);
  }
});

app.put('/profile/notes', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    await User.findByIdAndUpdate(decoded.id, { notes: req.body.notes });
    res.sendStatus(200);
  } catch {
    res.sendStatus(401);
  }
});

app.delete('/profile', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    await User.findByIdAndDelete(decoded.id);
    res.sendStatus(200);
  } catch {
    res.sendStatus(401);
  }
});

// -------- AUTH --------

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: 'All fields required' });

  const existing = await User.findOne({ email });
  if (existing)
    return res.status(400).json({ message: 'User already exists' });

  const hashed = await bcrypt.hash(password, 10);
  await new User({ email, password: hashed }).save();

  res.status(201).json({ message: 'User created' });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: 'All fields required' });

  const user = await User.findOne({ email });
  if (!user)
    return res.status(400).json({ message: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid)
    return res.status(400).json({ message: 'Invalid credentials' });

  const token = jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '2h' }
  );

  res.json({ token });
});

app.get('/profile', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth)
    return res.status(401).json({ message: 'No token provided' });

  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');

    if (!user)
      return res.status(404).json({ message: 'User not found' });

    res.json({
      email: user.email,
      name: user.name,
      avatar: user.avatar,
      notes: user.notes
    });
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
});

// -------- HEALTH --------

app.get('/', (req, res) => {
  res.send('Deutschio backend is running 🚀');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running on port', PORT));
