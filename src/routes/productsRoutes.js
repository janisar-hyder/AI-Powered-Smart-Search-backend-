const express = require('express');
const router = express.Router();
const productsController = require('../controllers/productController');
const { userMiddleware } = require('../middleware/userMiddleware');

// Public product search (no authentication required)
router.post('/', productsController.searchProducts);

// Get product history - REQUIRES AUTHENTICATION
router.get('/product_history', userMiddleware, productsController.getProductHistory);

// Track product visit - REQUIRES AUTHENTICATION
router.post('/track-visit', userMiddleware, productsController.trackProductVisit);

module.exports = router;