const express  = require('express');
const router   = express.Router();
const passport = require('passport');
const User     = require('../models/User');
const { forwardAuthenticated } = require('../middleware/auth');

// ─── GET /auth/login ──────────────────────────────────────────────────────────
router.get('/login', forwardAuthenticated, (req, res) => {
  res.render('login', { googleEnabled: isGoogleConfigured() });
});

// ─── GET /auth/signup ─────────────────────────────────────────────────────────
router.get('/signup', forwardAuthenticated, (req, res) => {
  res.render('signup', { errors: [], name: '', email: '', googleEnabled: isGoogleConfigured() });
});

// ─── POST /auth/login ─────────────────────────────────────────────────────────
router.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/auth/login',
    failureFlash: true
  })(req, res, next);
});

// ─── POST /auth/signup ────────────────────────────────────────────────────────
router.post('/signup', async (req, res) => {
  const { name, email, password, password2 } = req.body;
  const errors = [];

  if (!name || !name.trim())     errors.push({ msg: 'Please enter your name.' });
  if (!email || !email.trim())   errors.push({ msg: 'Please enter your email.' });
  if (!password)                 errors.push({ msg: 'Please enter a password.' });
  if (password !== password2)    errors.push({ msg: 'Passwords do not match.' });
  if (password && password.length < 6) errors.push({ msg: 'Password must be at least 6 characters.' });

  if (errors.length > 0) {
    return res.render('signup', { errors, name: name || '', email: email || '', googleEnabled: isGoogleConfigured() });
  }

  try {
    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res.render('signup', {
        errors: [{ msg: 'An account with that email already exists.' }],
        name, email, googleEnabled: isGoogleConfigured()
      });
    }

    const user = new User({ name: name.trim(), email: email.toLowerCase().trim(), password });
    await user.save();

    req.flash('success_msg', 'Account created successfully! Please log in.');
    res.redirect('/auth/login');
  } catch (err) {
    console.error('Signup error:', err.message);
    res.render('signup', {
      errors: [{ msg: 'Server error. Please try again.' }],
      name: name || '', email: email || '', googleEnabled: isGoogleConfigured()
    });
  }
});

// ─── Google OAuth ─────────────────────────────────────────────────────────────
router.get('/google', (req, res, next) => {
  if (!isGoogleConfigured()) {
    req.flash('error_msg', 'Google login is not configured on this server.');
    return res.redirect('/auth/login');
  }
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

router.get('/google/callback', (req, res, next) => {
  if (!isGoogleConfigured()) return res.redirect('/auth/login');
  passport.authenticate('google', {
    successRedirect: '/dashboard',
    failureRedirect: '/auth/login',
    failureFlash: true
  })(req, res, next);
});

// ─── Logout ────────────────────────────────────────────────────────────────────
router.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.flash('success_msg', 'You have been logged out successfully.');
    res.redirect('/auth/login');
  });
});

// ─── Helper ───────────────────────────────────────────────────────────────────
function isGoogleConfigured() {
  const id  = process.env.GOOGLE_CLIENT_ID;
  const sec = process.env.GOOGLE_CLIENT_SECRET;
  return !!(id && sec && !id.includes('your_google'));
}

module.exports = router;
