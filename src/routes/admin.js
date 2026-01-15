// routes/admin.js
const express = require('express');
const router = express.Router();
const {
  // User Management
  getAllUsers,
  getUserById,
  updateUser,
  deleteUser,
  searchUsers,
  exportUsers,
  toggleEmailVerification,
  
  // Admin Management
  getAllAdmins,
  getAdminById,
  createAdmin,
  updateAdmin,
  deleteAdmin,
  searchAdmins
} = require('../controllers/adminController');
const { adminMiddleware, superAdminMiddleware, roleMiddleware } = require('../middleware/adminMiddleware');

// ============= USER MANAGEMENT ROUTES =============
router.get('/users', adminMiddleware, getAllUsers);
router.get('/users/search', adminMiddleware, searchUsers);
router.get('/users/export', adminMiddleware, exportUsers);
router.get('/users/:id', adminMiddleware, getUserById);
router.put('/users/:id', adminMiddleware, updateUser);
router.delete('/users/:id', adminMiddleware, deleteUser);
router.patch('/users/:id/verify', adminMiddleware, toggleEmailVerification);

// ============= ADMIN MANAGEMENT ROUTES =============
router.get('/admins', superAdminMiddleware, getAllAdmins);
router.get('/admins/search', superAdminMiddleware, searchAdmins);
router.get('/admins/:id', superAdminMiddleware, getAdminById);
router.post('/admins', superAdminMiddleware, createAdmin);
router.put('/admins/:id', superAdminMiddleware, updateAdmin);
router.delete('/admins/:id', superAdminMiddleware, deleteAdmin);

// Admin dashboard (any admin can access)
router.get('/dashboard', adminMiddleware, (req, res) => {
  res.json({
    success: true,
    message: 'Admin dashboard',
    user: req.user,
    timestamp: new Date().toISOString()
  });
});

module.exports = router;