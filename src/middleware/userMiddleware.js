const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

/**
 * Unified User Middleware - For both Users and Admins
 * Verifies JWT using Supabase's built-in auth and checks appropriate table
 */
const userMiddleware = async (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Access token required. Please log in.',
        code: 'NO_TOKEN'
      });
    }

    console.log('🔐 Verifying Supabase token...');
    
    // Use Supabase to verify the token
    const { data: { user }, error } = await supabase.auth.getUser(token);
    
    if (error) {
      console.error('Supabase auth error:', error.message);
      return res.status(403).json({
        success: false,
        error: 'Invalid or expired token. Please log in again.',
        code: 'INVALID_TOKEN'
      });
    }
    
    if (!user) {
      console.error('No user found for token');
      return res.status(403).json({
        success: false,
        error: 'User not found for this token.',
        code: 'USER_NOT_FOUND'
      });
    }

    let userData = null;
    let table = null;

    // First check if user is an admin
    const { data: admin, error: adminError } = await supabase
      .from('admins')
      .select('*')
      .eq('id', user.id)
      .single();

    if (admin && !adminError) {
      userData = admin;
      table = 'admins';
    } else {
      // If not admin, check if user is a regular user
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

    // If user not found in either table
    if (!userData) {
      console.error('User not found in database tables');
      return res.status(403).json({
        success: false,
        error: 'User account not found in database. Please contact support.',
        code: 'ACCOUNT_NOT_FOUND'
      });
    }

    // Check if email is verified
    if (!userData.email_verified) {
      return res.status(403).json({
        success: false,
        error: 'Please verify your email to access this feature.',
        code: 'EMAIL_NOT_VERIFIED'
      });
    }

    // Add complete user info to request
    req.user = {
      id: userData.id,
      email: userData.email,
      role: userData.role || (table === 'admins' ? 'admin' : 'user'),
      firstName: userData.first_name,
      lastName: userData.last_name,
      fullName: userData.full_name,
      table: table,
      emailVerified: userData.email_verified,
      createdAt: userData.created_at,
      updatedAt: userData.updated_at,
      authUser: user, // Keep original auth user data
      isActive: true
    };
    
    console.log(`✅ ${table === 'admins' ? '👑 Admin' : '👤 User'} authenticated: ${req.user.email} (${req.user.role})`);
    next();
    
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({
      success: false,
      error: 'Authentication server error',
      code: 'AUTH_SERVER_ERROR'
    });
  }
};

/**
 * User-only Middleware - Only allows regular users (not admins)
 */
const userOnlyMiddleware = async (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Access token required. Please log in.',
        code: 'NO_TOKEN'
      });
    }

    // Verify token with Supabase Auth
    const { data: { user }, error } = await supabase.auth.getUser(token);
    
    if (error || !user) {
      return res.status(403).json({
        success: false,
        error: 'Invalid or expired token. Please log in again.',
        code: 'INVALID_TOKEN'
      });
    }

    // Check if user exists in users table
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('id', user.id)
      .single();

    if (userError || !userData) {
      return res.status(403).json({
        success: false,
        error: 'User account not found.',
        code: 'USER_NOT_FOUND'
      });
    }

    // Check if user is trying to access as admin
    const { data: adminCheck } = await supabase
      .from('admins')
      .select('id')
      .eq('id', user.id)
      .single();

    if (adminCheck) {
      return res.status(403).json({
        success: false,
        error: 'Admins cannot access user-only endpoints.',
        code: 'ADMIN_ACCESS_DENIED'
      });
    }

    // Check if email is verified
    if (!userData.email_verified) {
      return res.status(403).json({
        success: false,
        error: 'Please verify your email to access user features.',
        code: 'EMAIL_NOT_VERIFIED'
      });
    }

    // Add user info to request
    req.user = {
      id: userData.id,
      email: userData.email,
      role: userData.role || 'user',
      firstName: userData.first_name,
      lastName: userData.last_name,
      fullName: userData.full_name,
      table: 'users',
      emailVerified: userData.email_verified,
      createdAt: userData.created_at,
      updatedAt: userData.updated_at,
      isActive: true
    };
    
    console.log(`👤 User-only access: ${req.user.email}`);
    next();
    
  } catch (error) {
    console.error('User-only middleware error:', error);
    res.status(500).json({
      success: false,
      error: 'Authentication server error',
      code: 'AUTH_SERVER_ERROR'
    });
  }
};

module.exports = { 
  userMiddleware, 
  userOnlyMiddleware 
};