const express = require('express');
const router = express.Router();
const jobsController = require('../controllers/jobController');
const { userMiddleware } = require('../middleware/userMiddleware');
const { adminMiddleware } = require('../middleware/adminMiddleware');

// Public routes (no authentication required)
router.post('/', jobsController.searchJobs);

// User routes (requires user authentication)
router.get('/job_history', userMiddleware, jobsController.getJobHistory);


module.exports = router;