import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from './db.js';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
// CORS configuration - Frontend origin links correct ga manage chestundi

app.use(cors({
  origin: [
    'https://tender-fascination-production-e9e7.up.railway.app', 
    'https://share-a-meal-123.onrender.com', 
    'http://localhost:5173', 
    'http://localhost:3000'
  ],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

// Root test route
app.get('/', (req, res) => {
  res.send('Share-A-Meal Backend API is working perfectly live! 🌟');
});

/* ==========================================================================
   1. SIGN UP / REGISTER ROUTE
   ========================================================================== */
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Check if user already exists
    const userExist = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExist.rows.length > 0) {
      return res.status(400).json({ message: 'User already registered with this email.' });
    }

    // Password Encription
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Save user to Postgres DB
    const newUser = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, hashedPassword]
    );

    // Generate JWT Auth Token
    const token = jwt.sign({ id: newUser.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '24h' });

    res.status(201).json({
      message: 'Registration successful!',
      token,
      user: newUser.rows[0]
    });

  } catch (err) {
    console.error('Register Error:', err.message);
    res.status(500).json({ message: 'Server error during registration. Try again.' });
  }
});

/* ==========================================================================
   2. SIGN IN / LOGIN ROUTE
   ========================================================================== */
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Database checking for User
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid Email or Password.' });
    }

    const user = result.rows[0];

    // Password comparison match verify
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid Email or Password.' });
    }

    // Creating login session JWT Token
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '24h' });

    // Response exact structure mapping (Frontend can use data.user.name smoothly)
    res.status(200).json({
      message: 'Login successful!',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });

  } catch (err) {
    console.error('Login Error:', err.message);
    res.status(500).json({ message: 'Server error during sign in.' });
  }
});

// App server engine trigger listener
app.listen(PORT, () => {
  console.log(`Backend Server running on port ${PORT} 🚀`);
});
