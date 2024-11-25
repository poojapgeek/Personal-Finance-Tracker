const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt'); // Import bcrypt for password hashing
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();

// Database connection
const db = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: process.env.PASSWORD,
  database: 'finance_tracker',
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(cookieParser());

// Use JWT secret from environment variable
const JWT_SECRET = process.env.JWT_SECRET;

// Authentication Middleware
const ensureAuthenticated = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.redirect('/login');
    req.user = decoded;
    next();
  });
};
// API Endpoint for Visualization Data with Optional Month Filter
app.get('/api/visualization-data', ensureAuthenticated, async (req, res) => {
  const userId = req.user.id;
  const { month } = req.query; // Optional query parameter for filtering by month

  try {
    // Query for total income and expenses (optional filter by month)
    const incomeQuery = `
      SELECT SUM(amount) AS total_income FROM income 
      WHERE user_id = ? ${month ? "AND MONTH(date) = ?" : ""}`;
    const expenseQuery = `
      SELECT SUM(amount) AS total_expenses FROM expense 
      WHERE user_id = ? ${month ? "AND MONTH(date) = ?" : ""}`;

    const incomeParams = month ? [userId, month] : [userId];
    const expenseParams = month ? [userId, month] : [userId];

    const [incomes] = await db.query(incomeQuery, incomeParams);
    const [expenses] = await db.query(expenseQuery, expenseParams);

    const totalIncome = incomes[0].total_income || 0;
    const totalExpenses = expenses[0].total_expenses || 0;

    // Fetch monthly data for bar and line charts
    const monthlyQuery = `
      SELECT MONTH(date) AS month, 
             SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) AS total_income,
             SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) AS total_expenses
      FROM (
        SELECT date, amount, 'income' AS type FROM income WHERE user_id = ?
        UNION ALL
        SELECT date, amount, 'expense' AS type FROM expense WHERE user_id = ?
      ) AS combined
      GROUP BY MONTH(date)
      ORDER BY MONTH(date)`;

    const [monthlyData] = await db.query(monthlyQuery, [userId, userId]);

    // Send data to frontend
    res.json({ totalIncome, totalExpenses, monthlyData });
  } catch (error) {
    console.error('Error fetching visualization data:', error);
    res.status(500).json({ error: 'Failed to fetch data' });
  }
});

// Route to render the visualization page (Pie Chart)
app.get('/visualization', ensureAuthenticated, (req, res) => {
  res.render('visualization', { user: req.user });
});
// Routes
// Route for Landing Page
app.get('/', (req, res) => {
  res.render('landing'); // Render the landing page
});

// Routes for Sign Up and Login
app.get('/signup', (req, res) => res.render('signup'));
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  await db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword]);
  res.redirect('/login');
});

app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

  if (rows.length > 0) {
    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
      res.cookie('token', token, { httpOnly: true });
      return res.redirect('/tracker');
    }
  }


  res.send('Invalid credentials');
});

// Forgot Password
app.get('/reset-password', (req, res) => res.render('reset-password'));
app.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  await db.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
  res.redirect('/login');
});

app.get('/logout', (req, res) => {
  res.clearCookie('token'); // Clear the JWT cookie
  res.redirect('/'); // Redirect to login page
});

app.get('/tracker', ensureAuthenticated, async (req, res) => {
  const [user] = await db.query('SELECT * FROM users WHERE id = ?', [req.user.id]);
  res.render('tracker', { user: user[0] });
});

app.post('/add-income', ensureAuthenticated, async (req, res) => {
  const { source, amount, date } = req.body;
  await db.query('INSERT INTO income (user_id, source, amount, date) VALUES (?, ?, ?, ?)', [req.user.id, source, amount, date]);
  res.redirect('/tracker');
});

app.post('/add-expense', ensureAuthenticated, async (req, res) => {
  const { category, amount, date } = req.body;
  await db.query('INSERT INTO expense (user_id, category, amount, date) VALUES (?, ?, ?, ?)', [req.user.id, category, amount, date]);
  res.redirect('/tracker');
});
app.get('/view-records/:userId', ensureAuthenticated, async (req, res) => {
  const userId = req.params.userId;
  const [incomes] = await db.query('SELECT * FROM income WHERE user_id = ?', [userId]);
  const [expenses] = await db.query('SELECT * FROM expense WHERE user_id = ?', [userId]);
  res.render('records', { incomes, expenses });
});
// Start server
app.listen(3001, () => console.log('Server running on http://localhost:3001'));
