const express = require('express');
const router = express.Router();
const scholarshipsController = require('../controllers/scholarshipsController');
const { userMiddleware } = require('../middleware/userMiddleware');

// Public scholarship search (no authentication required)
router.post('/', scholarshipsController.searchScholarships);

// Get scholarship history - REQUIRES AUTHENTICATION
router.get('/scholarships_history', userMiddleware, scholarshipsController.getScholarshipHistory);

module.exports = router;