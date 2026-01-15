const express = require('express');
const router = express.Router();
const universitiesController = require('../controllers/universityController');
const { userMiddleware } = require('../middleware/userMiddleware');

// Public university search (no authentication required)
router.post('/', universitiesController.searchUniversityPrograms);

// Get university history - REQUIRES AUTHENTICATION
router.get('/university_history', userMiddleware, universitiesController.getUniversityHistory);

module.exports = router;