// routes/auth.js
const express = require('express');
const router = express.Router();
const {
  signUp,
  verifyOTP,
  loginWithPasswordAndOTP,
  verifyLoginOTP,
  initiatePasswordReset,
  verifyPasswordResetOTP,
  completePasswordReset
} = require('../controllers/authController');
const { adminMiddleware } = require('../middleware/adminMiddleware');

// Registration routes (USERS ONLY)
router.post('/signup', signUp);
router.post('/verify-otp', verifyOTP);

// Unified Login routes (BOTH USERS AND ADMINS)
router.post('/login', loginWithPasswordAndOTP);
router.post('/verify-login', verifyLoginOTP);

// Unified Password reset routes (BOTH USERS AND ADMINS)
router.post('/forgot-password', initiatePasswordReset);
router.post('/verify-reset-otp', verifyPasswordResetOTP);
router.post('/reset-password', completePasswordReset);


// Admin-only login status check
router.get('/admin/check', adminMiddleware, (req, res) => {
  res.json({
    success: true,
    message: 'Admin authenticated',
    user: req.user
  });
});

module.exports = router;