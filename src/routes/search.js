const express = require('express');
const router = express.Router();
const searchController = require('../controllers/searchController');

// Separate endpoints for each category
router.post('/jobs', searchController.searchJobs);
router.post('/products', searchController.searchProducts);
router.post('/universities', searchController.searchUniversityPrograms);
router.post('/scholarships', searchController.searchScholarships);

module.exports = router;