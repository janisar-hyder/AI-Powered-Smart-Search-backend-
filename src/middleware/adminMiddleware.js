const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

/**
 * Admin-only Middleware
 * Requires user to be in the admins table
 */
const adminMiddleware = async (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Access token required',
        code: 'NO_TOKEN'
      });
    }

    console.log('🔐 Verifying admin token...');
    
    // Verify token with Supabase Auth
    const { data: { user }, error } = await supabase.auth.getUser(token);
    
    if (error || !user) {
      return res.status(403).json({
        success: false,
        error: 'Invalid or expired token',
        code: 'INVALID_TOKEN'
      });
    }

    // Check if user exists in admins table
    const { data: admin, error: adminError } = await supabase
      .from('admins')
      .select('id, email, role, email_verified, first_name, last_name, full_name, created_at')
      .eq('id', user.id)
      .single();

    if (adminError || !admin) {
      console.log(`❌ User ${user.email} is not an admin`);
      return res.status(403).json({
        success: false,
        error: 'Access denied. Admin privileges required.',
        code: 'NOT_ADMIN'
      });
    }

    // Check if email is verified
    if (!admin.email_verified) {
      return res.status(403).json({
        success: false,
        error: 'Please verify your admin email to access admin features',
        code: 'EMAIL_NOT_VERIFIED'
      });
    }

    // Add admin info to request
    req.user = {
      id: admin.id,
      email: admin.email,
      role: admin.role || 'admin',
      firstName: admin.first_name,
      lastName: admin.last_name,
      fullName: admin.full_name,
      table: 'admins',
      emailVerified: admin.email_verified,
      createdAt: admin.created_at,
      authUser: user,
      isActive: true,
      permissions: admin.permissions || ['all'] // You can add permissions column to admins table
    };
    
    console.log(`👑 Admin authenticated: ${req.user.email} (${req.user.role})`);
    next();
    
  } catch (error) {
    console.error('Admin middleware error:', error);
    res.status(500).json({
      success: false,
      error: 'Authentication server error',
      code: 'AUTH_SERVER_ERROR'
    });
  }
};

/**
 * Role-based Access Control Middleware
 * @param {Array} allowedRoles - Array of allowed roles
 * @param {String} tableType - 'admins', 'users', or 'both'
 */
const roleMiddleware = (allowedRoles = [], tableType = 'both') => {
  return async (req, res, next) => {
    try {
      // Get token from Authorization header
      const authHeader = req.headers.authorization;
      const token = authHeader && authHeader.split(' ')[1];
      
      if (!token) {
        return res.status(401).json({
          success: false,
          error: 'Access token required',
          code: 'NO_TOKEN'
        });
      }

      // Verify token with Supabase Auth
      const { data: { user }, error: authError } = await supabase.auth.getUser(token);
      
      if (authError || !user) {
        return res.status(403).json({
          success: false,
          error: 'Invalid or expired token',
          code: 'INVALID_TOKEN'
        });
      }

      let userData = null;
      let table = null;

      // Check appropriate tables based on tableType
      if (tableType === 'admins' || tableType === 'both') {
        const { data: admin, error: adminError } = await supabase
          .from('admins')
          .select('*')
          .eq('id', user.id)
          .single();

        if (admin && !adminError) {
          userData = admin;
          table = 'admins';
        }
      }

      // Check users table if needed and not already found
      if (!userData && (tableType === 'users' || tableType === 'both')) {
        const { data: regularUser, error: userError } = await supabase
          .from('users')
          .select('*')
          .eq('id', user.id)
          .single();

        if (regularUser && !userError) {
          userData = regularUser;
          table = 'users';
        }
      }

      // If user not found in allowed tables
      if (!userData) {
        return res.status(403).json({
          success: false,
          error: `User not found in ${tableType} table(s)`,
          code: 'USER_NOT_FOUND'
        });
      }

      // Check if email is verified
      if (!userData.email_verified) {
        return res.status(403).json({
          success: false,
          error: 'Please verify your email',
          code: 'EMAIL_NOT_VERIFIED'
        });
      }

      // Check if user role is in allowedRoles (if specified)
      if (allowedRoles.length > 0 && !allowedRoles.includes(userData.role)) {
        return res.status(403).json({
          success: false,
          error: `Access denied. Required roles: ${allowedRoles.join(', ')}`,
          code: 'INSUFFICIENT_PERMISSIONS'
        });
      }

      // Add user info to request
      req.user = {
        id: userData.id,
        email: userData.email,
        role: userData.role,
        firstName: userData.first_name,
        lastName: userData.last_name,
        fullName: userData.full_name,
        table: table,
        emailVerified: userData.email_verified,
        createdAt: userData.created_at,
        updatedAt: userData.updated_at,
        authUser: user,
        isActive: true
      };
      
      console.log(`✅ ${table === 'admins' ? '👑 Admin' : '👤 User'} authenticated with role ${req.user.role}: ${req.user.email}`);
      next();
      
    } catch (error) {
      console.error('Role middleware error:', error);
      res.status(500).json({
        success: false,
        error: 'Authentication server error',
        code: 'AUTH_SERVER_ERROR'
      });
    }
  };
};

/**
 * Super Admin Middleware (only allows superadmin role)
 */
const superAdminMiddleware = async (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Access token required',
        code: 'NO_TOKEN'
      });
    }

    // Verify token with Supabase Auth
    const { data: { user }, error } = await supabase.auth.getUser(token);
    
    if (error || !user) {
      return res.status(403).json({
        success: false,
        error: 'Invalid or expired token',
        code: 'INVALID_TOKEN'
      });
    }

    // Check if user exists in admins table with superadmin role
    const { data: admin, error: adminError } = await supabase
      .from('admins')
      .select('*')
      .eq('id', user.id)
      .eq('role', 'superadmin')
      .single();

    if (adminError || !admin) {
      return res.status(403).json({
        success: false,
        error: 'Access denied. Superadmin privileges required.',
        code: 'NOT_SUPERADMIN'
      });
    }

    // Add super admin info to request
    req.user = {
      id: admin.id,
      email: admin.email,
      role: admin.role,
      firstName: admin.first_name,
      lastName: admin.last_name,
      fullName: admin.full_name,
      table: 'admins',
      emailVerified: admin.email_verified,
      createdAt: admin.created_at,
      isActive: true,
      permissions: ['all']
    };
    
    console.log(`👑👑 Super Admin authenticated: ${req.user.email}`);
    next();
    
  } catch (error) {
    console.error('Super admin middleware error:', error);
    res.status(500).json({
      success: false,
      error: 'Authentication server error',
      code: 'AUTH_SERVER_ERROR'
    });
  }
};

module.exports = { 
  adminMiddleware, 
  roleMiddleware, 
  superAdminMiddleware 
};