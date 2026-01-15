// controllers/adminController.js
const { supabase, supabaseDB } = require('../config/supabase');

// ============= USER MANAGEMENT ENDPOINTS =============

/**
 * @desc    Get all users (with pagination, filtering, and sorting)
 * @route   GET /api/admin/users
 * @access  Private/Admin
 */
const getAllUsers = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      search = '',
      role = '',
      sortBy = 'created_at',
      sortOrder = 'desc',
      verified = '',
      startDate = '',
      endDate = ''
    } = req.query;

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const offset = (pageNum - 1) * limitNum;

    // Build query
    let query = supabaseDB
      .from('users')
      .select('*', { count: 'exact' });

    // Apply search filter
    if (search) {
      query = query.or(`first_name.ilike.%${search}%,last_name.ilike.%${search}%,email.ilike.%${search}%,full_name.ilike.%${search}%`);
    }

    // Apply role filter
    if (role) {
      query = query.eq('role', role);
    }

    // Apply verification filter
    if (verified !== '') {
      query = query.eq('email_verified', verified === 'true');
    }

    // Apply date range filter
    if (startDate) {
      query = query.gte('created_at', startDate);
    }
    if (endDate) {
      query = query.lte('created_at', endDate);
    }

    // Apply sorting
    query = query.order(sortBy, { ascending: sortOrder === 'asc' });

    // Apply pagination
    query = query.range(offset, offset + limitNum - 1);

    // Execute query
    const { data: users, error, count } = await query;

    if (error) throw error;

    // Calculate pagination metadata
    const totalPages = Math.ceil(count / limitNum);
    const hasNextPage = pageNum < totalPages;
    const hasPrevPage = pageNum > 1;

    return res.status(200).json({
      success: true,
      message: 'Users retrieved successfully',
      data: {
        users,
        pagination: {
          total: count,
          totalPages,
          currentPage: pageNum,
          pageSize: limitNum,
          hasNextPage,
          hasPrevPage,
          nextPage: hasNextPage ? pageNum + 1 : null,
          prevPage: hasPrevPage ? pageNum - 1 : null
        },
        filters: {
          search,
          role,
          verified,
          startDate,
          endDate,
          sortBy,
          sortOrder
        }
      }
    });

  } catch (error) {
    console.error('Get all users error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to retrieve users',
      message: error.message,
      code: error.code
    });
  }
};

/**
 * @desc    Get user by ID
 * @route   GET /api/admin/users/:id
 * @access  Private/Admin
 */
const getUserById = async (req, res) => {
  try {
    const { id } = req.params;

    const { data: user, error } = await supabaseDB
      .from('users')
      .select('*')
      .eq('id', id)
      .single();

    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }
      throw error;
    }

    // Get user's recent activity if available (optional)
    try {
      const { data: recentActivity } = await supabaseDB
        .from('audit_logs')
        .select('action, created_at')
        .eq('user_id', id)
        .order('created_at', { ascending: false })
        .limit(5);
      
      return res.status(200).json({
        success: true,
        message: 'User retrieved successfully',
        data: {
          user,
          recentActivity: recentActivity || []
        }
      });
    } catch (auditError) {
      // If audit_logs table doesn't exist, just return user data
      return res.status(200).json({
        success: true,
        message: 'User retrieved successfully',
        data: {
          user,
          recentActivity: []
        }
      });
    }

  } catch (error) {
    console.error('Get user by ID error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to retrieve user',
      message: error.message,
      code: error.code
    });
  }
};

/**
 * @desc    Update user details
 * @route   PUT /api/admin/users/:id
 * @access  Private/Admin
 */
const updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    const {
      first_name,
      last_name,
      email,
      role,
      email_verified
    } = req.body;

    // Check if user exists
    const { data: existingUser, error: checkError } = await supabaseDB
      .from('users')
      .select('id, email, first_name, last_name')
      .eq('id', id)
      .single();

    if (checkError || !existingUser) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Check if email is being changed and already exists
    if (email && email !== existingUser.email) {
      const { data: emailExists } = await supabaseDB
        .from('users')
        .select('id')
        .eq('email', email)
        .neq('id', id)
        .single();

      if (emailExists) {
        return res.status(400).json({
          success: false,
          error: 'Email already in use by another user'
        });
      }
    }

    // Prepare update data
    const updateData = {
      updated_at: new Date().toISOString()
    };

    if (first_name !== undefined) updateData.first_name = first_name;
    if (last_name !== undefined) updateData.last_name = last_name;
    if (email !== undefined) updateData.email = email;
    if (role !== undefined) updateData.role = role;
    if (email_verified !== undefined) updateData.email_verified = email_verified;

    // Update full_name if first or last name changed
    if (first_name !== undefined || last_name !== undefined) {
      const finalFirstName = first_name !== undefined ? first_name : existingUser.first_name;
      const finalLastName = last_name !== undefined ? last_name : existingUser.last_name;
      updateData.full_name = `${finalFirstName} ${finalLastName}`;
    }

    // Update user in database
    const { data: updatedUser, error: updateError } = await supabaseDB
      .from('users')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (updateError) throw updateError;

    // Log the update action (optional)
    try {
      await logAdminAction(req.user.id, 'UPDATE_USER', {
        admin_id: req.user.id,
        user_id: id,
        user_email: existingUser.email,
        changes: updateData,
        previous_data: {
          first_name: existingUser.first_name,
          last_name: existingUser.last_name,
          email: existingUser.email,
          role: existingUser.role
        },
        ip_address: req.ip
      });
    } catch (logError) {
      // Continue even if logging fails
      console.log('Audit logging failed:', logError.message);
    }

    return res.status(200).json({
      success: true,
      message: 'User updated successfully',
      data: updatedUser
    });

  } catch (error) {
    console.error('Update user error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to update user',
      message: error.message,
      code: error.code
    });
  }
};

/**
 * @desc    Delete user account (HARD DELETE - permanent)
 * @route   DELETE /api/admin/users/:id
 * @access  Private/Admin
 */
const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body || {};

    // Check if user exists
    const { data: existingUser, error: checkError } = await supabaseDB
      .from('users')
      .select('id, email, first_name, last_name, role, created_at')
      .eq('id', id)
      .single();

    if (checkError || !existingUser) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Prevent deleting your own account
    if (id === req.user.id) {
      return res.status(400).json({
        success: false,
        error: 'Cannot delete your own account'
      });
    }

    // HARD DELETE (permanently remove from database)
    const { error: deleteError } = await supabaseDB
      .from('users')
      .delete()  // This permanently deletes the row
      .eq('id', id);

    if (deleteError) {
      console.error('Delete error:', deleteError);
      return res.status(500).json({
        success: false,
        error: 'Failed to delete user from database',
        message: deleteError.message,
        code: deleteError.code
      });
    }

    // Log the deletion (optional)
    try {
      await logAdminAction(req.user.id, 'DELETE_USER', {
        admin_id: req.user.id,
        user_id: id,
        user_email: existingUser.email,
        user_name: `${existingUser.first_name} ${existingUser.last_name}`,
        user_role: existingUser.role,
        reason: reason || 'No reason provided',
        ip_address: req.ip,
        hard_delete: true,
        deleted_at: new Date().toISOString()
      });
    } catch (logError) {
      // Continue even if logging fails
      console.log('Audit logging failed:', logError.message);
    }

    return res.status(200).json({
      success: true,
      message: 'User deleted successfully',
      data: {
        id,
        email: existingUser.email,
        name: `${existingUser.first_name} ${existingUser.last_name}`,
        role: existingUser.role,
        deleted_at: new Date().toISOString(),
        method: 'hard_delete'
      }
    });

  } catch (error) {
    console.error('Delete user error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to delete user',
      message: error.message,
      code: error.code
    });
  }
};

// ============= ADMIN MANAGEMENT ENDPOINTS =============

/**
 * @desc    Get all admins
 * @route   GET /api/admin/admins
 * @access  Private/SuperAdmin
 */
const getAllAdmins = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      search = '',
      role = '',
      sortBy = 'created_at',
      sortOrder = 'desc'
    } = req.query;

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const offset = (pageNum - 1) * limitNum;

    // Build query
    let query = supabaseDB
      .from('admins')
      .select('*', { count: 'exact' });

    // Apply search filter
    if (search) {
      query = query.or(`first_name.ilike.%${search}%,last_name.ilike.%${search}%,email.ilike.%${search}%,full_name.ilike.%${search}%`);
    }

    // Apply role filter
    if (role) {
      query = query.eq('role', role);
    }

    // Apply sorting
    query = query.order(sortBy, { ascending: sortOrder === 'asc' });

    // Apply pagination
    query = query.range(offset, offset + limitNum - 1);

    // Execute query
    const { data: admins, error, count } = await query;

    if (error) throw error;

    // Calculate pagination metadata
    const totalPages = Math.ceil(count / limitNum);
    const hasNextPage = pageNum < totalPages;
    const hasPrevPage = pageNum > 1;

    return res.status(200).json({
      success: true,
      message: 'Admins retrieved successfully',
      data: {
        admins,
        pagination: {
          total: count,
          totalPages,
          currentPage: pageNum,
          pageSize: limitNum,
          hasNextPage,
          hasPrevPage,
          nextPage: hasNextPage ? pageNum + 1 : null,
          prevPage: hasPrevPage ? pageNum - 1 : null
        },
        filters: {
          search,
          role,
          sortBy,
          sortOrder
        }
      }
    });

  } catch (error) {
    console.error('Get all admins error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to retrieve admins',
      message: error.message,
      code: error.code
    });
  }
};

/**
 * @desc    Get admin by ID
 * @route   GET /api/admin/admins/:id
 * @access  Private/SuperAdmin
 */
const getAdminById = async (req, res) => {
  try {
    const { id } = req.params;

    const { data: admin, error } = await supabaseDB
      .from('admins')
      .select('*')
      .eq('id', id)
      .single();

    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(404).json({
          success: false,
          error: 'Admin not found'
        });
      }
      throw error;
    }

    return res.status(200).json({
      success: true,
      message: 'Admin retrieved successfully',
      data: admin
    });

  } catch (error) {
    console.error('Get admin by ID error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to retrieve admin',
      message: error.message,
      code: error.code
    });
  }
};

/**
 * @desc    Create a new admin (only for superadmins)
 * @route   POST /api/admin/admins
 * @access  Private/SuperAdmin
 */
const createAdmin = async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      email,
      password,
      role = 'admin',
      email_verified = true
    } = req.body;

    // Validate required fields
    if (!first_name || !last_name || !email || !password) {
      return res.status(400).json({
        success: false,
        error: 'First name, last name, email, and password are required'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format'
      });
    }

    // Check if email already exists in admins table
    const { data: existingAdmin } = await supabaseDB
      .from('admins')
      .select('email')
      .eq('email', email)
      .single();

    if (existingAdmin) {
      return res.status(409).json({
        success: false,
        error: 'Admin with this email already exists'
      });
    }

    // Check if email exists in users table
    const { data: existingUser } = await supabaseDB
      .from('users')
      .select('email')
      .eq('email', email)
      .single();

    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: 'A user with this email already exists. Please use a different email.'
      });
    }

    // Create admin in Supabase Auth
    const { data: authData, error: authError } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: email_verified,
      user_metadata: {
        first_name,
        last_name,
        full_name: `${first_name} ${last_name}`,
        role: role
      }
    });

    if (authError) {
      console.error('Auth creation error:', authError);
      
      // Handle specific auth errors
      if (authError.message.includes('already registered')) {
        return res.status(409).json({
          success: false,
          error: 'This email is already registered in the authentication system'
        });
      }
      
      throw authError;
    }

    // Hash password for storage in admins table
    const bcrypt = require('bcrypt');
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create admin in admins table
    const { data: newAdmin, error: adminError } = await supabaseDB
      .from('admins')
      .insert({
        id: authData.user.id,
        first_name,
        last_name,
        full_name: `${first_name} ${last_name}`,
        email,
        role,
        password_hash: passwordHash,
        email_verified,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })
      .select()
      .single();

    if (adminError) throw adminError;

    // Log the creation
    try {
      await logAdminAction(req.user.id, 'CREATE_ADMIN', {
        admin_id: req.user.id,
        created_admin_id: newAdmin.id,
        created_admin_email: newAdmin.email,
        created_admin_role: newAdmin.role,
        ip_address: req.ip
      });
    } catch (logError) {
      console.log('Audit logging failed:', logError.message);
    }

    // Remove sensitive data from response
    const { password_hash, ...adminWithoutPassword } = newAdmin;

    return res.status(201).json({
      success: true,
      message: 'Admin created successfully',
      data: adminWithoutPassword
    });

  } catch (error) {
    console.error('Create admin error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to create admin',
      message: error.message,
      code: error.code
    });
  }
};

/**
 * @desc    Update admin details
 * @route   PUT /api/admin/admins/:id
 * @access  Private/SuperAdmin
 */
const updateAdmin = async (req, res) => {
  try {
    const { id } = req.params;
    const {
      first_name,
      last_name,
      email,
      role,
      email_verified
    } = req.body;

    // Check if admin exists
    const { data: existingAdmin, error: checkError } = await supabaseDB
      .from('admins')
      .select('id, email, first_name, last_name, role')
      .eq('id', id)
      .single();

    if (checkError || !existingAdmin) {
      return res.status(404).json({
        success: false,
        error: 'Admin not found'
      });
    }

    // Prevent updating your own role (superadmin can't demote themselves)
    if (id === req.user.id && role && role !== 'superadmin') {
      return res.status(400).json({
        success: false,
        error: 'Cannot change your own role from superadmin'
      });
    }

    // Check if email is being changed and already exists
    if (email && email !== existingAdmin.email) {
      const { data: emailExists } = await supabaseDB
        .from('admins')
        .select('id')
        .eq('email', email)
        .neq('id', id)
        .single();

      if (emailExists) {
        return res.status(400).json({
          success: false,
          error: 'Email already in use by another admin'
        });
      }
    }

    // Prepare update data
    const updateData = {
      updated_at: new Date().toISOString()
    };

    if (first_name !== undefined) updateData.first_name = first_name;
    if (last_name !== undefined) updateData.last_name = last_name;
    if (email !== undefined) updateData.email = email;
    if (role !== undefined) updateData.role = role;
    if (email_verified !== undefined) updateData.email_verified = email_verified;

    // Update full_name if first or last name changed
    if (first_name !== undefined || last_name !== undefined) {
      const finalFirstName = first_name !== undefined ? first_name : existingAdmin.first_name;
      const finalLastName = last_name !== undefined ? last_name : existingAdmin.last_name;
      updateData.full_name = `${finalFirstName} ${finalLastName}`;
    }

    // Update admin in database
    const { data: updatedAdmin, error: updateError } = await supabaseDB
      .from('admins')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (updateError) throw updateError;

    // Log the update action
    try {
      await logAdminAction(req.user.id, 'UPDATE_ADMIN', {
        admin_id: req.user.id,
        target_admin_id: id,
        target_admin_email: existingAdmin.email,
        changes: updateData,
        previous_data: {
          first_name: existingAdmin.first_name,
          last_name: existingAdmin.last_name,
          email: existingAdmin.email,
          role: existingAdmin.role
        },
        ip_address: req.ip
      });
    } catch (logError) {
      console.log('Audit logging failed:', logError.message);
    }

    // Remove sensitive data from response
    const { password_hash, ...adminWithoutPassword } = updatedAdmin;

    return res.status(200).json({
      success: true,
      message: 'Admin updated successfully',
      data: adminWithoutPassword
    });

  } catch (error) {
    console.error('Update admin error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to update admin',
      message: error.message,
      code: error.code
    });
  }
};

/**
 * @desc    Delete admin account (only for superadmins)
 * @route   DELETE /api/admin/admins/:id
 * @access  Private/SuperAdmin
 */
const deleteAdmin = async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body || {};

    // Check if admin exists
    const { data: existingAdmin, error: checkError } = await supabaseDB
      .from('admins')
      .select('id, email, first_name, last_name, role, created_at')
      .eq('id', id)
      .single();

    if (checkError || !existingAdmin) {
      return res.status(404).json({
        success: false,
        error: 'Admin not found'
      });
    }

    // Prevent deleting your own account
    if (id === req.user.id) {
      return res.status(400).json({
        success: false,
        error: 'Cannot delete your own admin account'
      });
    }

    // Prevent deleting other superadmins (optional security measure)
    if (existingAdmin.role === 'superadmin') {
      return res.status(403).json({
        success: false,
        error: 'Cannot delete another superadmin account'
      });
    }

    // HARD DELETE from admins table
    const { error: deleteError } = await supabaseDB
      .from('admins')
      .delete()
      .eq('id', id);

    if (deleteError) {
      console.error('Delete admin error:', deleteError);
      return res.status(500).json({
        success: false,
        error: 'Failed to delete admin from database',
        message: deleteError.message,
        code: deleteError.code
      });
    }

    // Optionally: Also delete from Supabase Auth
    try {
      await supabase.auth.admin.deleteUser(id);
      console.log(`Admin ${id} also deleted from Auth`);
    } catch (authError) {
      console.log(`Note: Could not delete admin ${id} from Auth:`, authError.message);
      // Continue even if Auth deletion fails
    }

    // Log the deletion
    try {
      await logAdminAction(req.user.id, 'DELETE_ADMIN', {
        admin_id: req.user.id,
        deleted_admin_id: id,
        deleted_admin_email: existingAdmin.email,
        deleted_admin_name: `${existingAdmin.first_name} ${existingAdmin.last_name}`,
        deleted_admin_role: existingAdmin.role,
        reason: reason || 'No reason provided',
        ip_address: req.ip,
        deleted_at: new Date().toISOString()
      });
    } catch (logError) {
      console.log('Audit logging failed:', logError.message);
    }

    return res.status(200).json({
      success: true,
      message: 'Admin deleted successfully',
      data: {
        id,
        email: existingAdmin.email,
        name: `${existingAdmin.first_name} ${existingAdmin.last_name}`,
        role: existingAdmin.role,
        deleted_at: new Date().toISOString(),
        method: 'hard_delete'
      }
    });

  } catch (error) {
    console.error('Delete admin error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to delete admin',
      message: error.message,
      code: error.code
    });
  }
};

/**
 * @desc    Get admin statistics
 * @route   GET /api/admin/admins/stats
 * @access  Private/SuperAdmin
 */


// ============= COMMON ENDPOINTS =============

/**
 * @desc    Get user statistics
 * @route   GET /api/admin/users/stats
 * @access  Private/Admin
 */

/**
 * @desc    Search users with advanced filters
 * @route   GET /api/admin/users/search
 * @access  Private/Admin
 */
const searchUsers = async (req, res) => {
  try {
    const {
      query,
      field = 'all' // all, email, name, id
    } = req.query;

    if (!query || query.trim() === '') {
      return res.status(400).json({
        success: false,
        error: 'Search query is required'
      });
    }

    const searchQuery = query.trim();
    let supabaseQuery = supabaseDB.from('users').select('*').limit(20);

    // Apply search based on field
    switch (field) {
      case 'email':
        supabaseQuery = supabaseQuery.ilike('email', `%${searchQuery}%`);
        break;
      case 'name':
        supabaseQuery = supabaseQuery.or(`first_name.ilike.%${searchQuery}%,last_name.ilike.%${searchQuery}%,full_name.ilike.%${searchQuery}%`);
        break;
      case 'id':
        // Check if query is a valid UUID
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (uuidRegex.test(searchQuery)) {
          supabaseQuery = supabaseQuery.eq('id', searchQuery);
        } else {
          return res.status(400).json({
            success: false,
            error: 'Invalid user ID format. Must be a valid UUID.'
          });
        }
        break;
      default: // 'all'
        supabaseQuery = supabaseQuery.or(
          `first_name.ilike.%${searchQuery}%,last_name.ilike.%${searchQuery}%,email.ilike.%${searchQuery}%,full_name.ilike.%${searchQuery}%`
        );
    }

    const { data: users, error } = await supabaseQuery;

    if (error) throw error;

    return res.status(200).json({
      success: true,
      message: users && users.length > 0 ? 'Search completed successfully' : 'No users found',
      data: {
        query: searchQuery,
        field,
        results: users || [],
        count: users ? users.length : 0
      }
    });

  } catch (error) {
    console.error('Search users error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to search users',
      message: error.message,
      code: error.code
    });
  }
};

/**
 * @desc    Search admins with advanced filters
 * @route   GET /api/admin/admins/search
 * @access  Private/SuperAdmin
 */
const searchAdmins = async (req, res) => {
  try {
    const {
      query,
      field = 'all' // all, email, name, id
    } = req.query;

    if (!query || query.trim() === '') {
      return res.status(400).json({
        success: false,
        error: 'Search query is required'
      });
    }

    const searchQuery = query.trim();
    let supabaseQuery = supabaseDB.from('admins').select('*').limit(20);

    // Apply search based on field
    switch (field) {
      case 'email':
        supabaseQuery = supabaseQuery.ilike('email', `%${searchQuery}%`);
        break;
      case 'name':
        supabaseQuery = supabaseQuery.or(`first_name.ilike.%${searchQuery}%,last_name.ilike.%${searchQuery}%,full_name.ilike.%${searchQuery}%`);
        break;
      case 'id':
        // Check if query is a valid UUID
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (uuidRegex.test(searchQuery)) {
          supabaseQuery = supabaseQuery.eq('id', searchQuery);
        } else {
          return res.status(400).json({
            success: false,
            error: 'Invalid admin ID format. Must be a valid UUID.'
          });
        }
        break;
      default: // 'all'
        supabaseQuery = supabaseQuery.or(
          `first_name.ilike.%${searchQuery}%,last_name.ilike.%${searchQuery}%,email.ilike.%${searchQuery}%,full_name.ilike.%${searchQuery}%`
        );
    }

    const { data: admins, error } = await supabaseQuery;

    if (error) throw error;

    // Remove password_hash from response
    const adminsWithoutPassword = admins ? admins.map(admin => {
      const { password_hash, ...adminWithoutPassword } = admin;
      return adminWithoutPassword;
    }) : [];

    return res.status(200).json({
      success: true,
      message: admins && admins.length > 0 ? 'Search completed successfully' : 'No admins found',
      data: {
        query: searchQuery,
        field,
        results: adminsWithoutPassword,
        count: admins ? admins.length : 0
      }
    });

  } catch (error) {
    console.error('Search admins error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to search admins',
      message: error.message,
      code: error.code
    });
  }
};

/**
 * @desc    Export users to CSV/Excel
 * @route   GET /api/admin/users/export
 * @access  Private/Admin
 */
const exportUsers = async (req, res) => {
  try {
    const { format = 'json' } = req.query; // json, csv

    // Get all users
    const { data: users, error } = await supabaseDB
      .from('users')
      .select('id, first_name, last_name, full_name, email, role, email_verified, created_at')
      .order('created_at', { ascending: false });

    if (error) throw error;

    if (format === 'csv') {
      // Convert to CSV
      const csvData = convertToCSV(users || []);
      
      // Set headers for CSV download
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=users_export_${Date.now()}.csv`);
      
      return res.send(csvData);
    }

    // Default to JSON
    return res.status(200).json({
      success: true,
      message: 'Users exported successfully',
      data: users || [],
      count: users ? users.length : 0,
      exportedAt: new Date().toISOString()
    });

  } catch (error) {
    console.error('Export users error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to export users',
      message: error.message,
      code: error.code
    });
  }
};

/**
 * @desc    Toggle user email verification status
 * @route   PATCH /api/admin/users/:id/verify
 * @access  Private/Admin
 */
const toggleEmailVerification = async (req, res) => {
  try {
    const { id } = req.params;
    const { verify } = req.body;

    if (typeof verify !== 'boolean') {
      return res.status(400).json({
        success: false,
        error: 'verify field must be a boolean (true/false)'
      });
    }

    // Check if user exists
    const { data: existingUser, error: checkError } = await supabaseDB
      .from('users')
      .select('id, email, email_verified')
      .eq('id', id)
      .single();

    if (checkError || !existingUser) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Update verification status
    const { data: updatedUser, error: updateError } = await supabaseDB
      .from('users')
      .update({
        email_verified: verify,
        updated_at: new Date().toISOString()
      })
      .eq('id', id)
      .select('id, email, email_verified')
      .single();

    if (updateError) throw updateError;

    return res.status(200).json({
      success: true,
      message: `User email ${verify ? 'verified' : 'unverified'} successfully`,
      data: updatedUser
    });

  } catch (error) {
    console.error('Toggle email verification error:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to update email verification status',
      message: error.message,
      code: error.code
    });
  }
};

// Helper function to log admin actions (optional)
const logAdminAction = async (adminId, action, details = {}) => {
  try {
    // Check if audit_logs table exists before inserting
    const { error } = await supabaseDB
      .from('audit_logs')
      .insert({
        admin_id: adminId,
        action,
        details,
        ip_address: details.ip_address,
        created_at: new Date().toISOString()
      });

    if (error) {
      // Table might not exist, that's okay
      console.log('Note: audit_logs table might not exist:', error.message);
    }
  } catch (error) {
    console.error('Failed to log admin action:', error.message);
    // Don't throw error for logging failure
  }
};

// Helper function to convert data to CSV
const convertToCSV = (data) => {
  if (!data || data.length === 0) {
    return 'No data to export';
  }

  try {
    const headers = Object.keys(data[0]);
    const csvRows = [];

    // Add header row
    csvRows.push(headers.join(','));

    // Add data rows
    for (const row of data) {
      const values = headers.map(header => {
        const value = row[header];
        // Handle null/undefined values
        if (value === null || value === undefined) {
          return '';
        }
        // Handle values that might contain commas or quotes
        const stringValue = String(value);
        if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
          return `"${stringValue.replace(/"/g, '""')}"`;
        }
        return stringValue;
      });
      csvRows.push(values.join(','));
    }

    return csvRows.join('\n');
  } catch (error) {
    console.error('CSV conversion error:', error);
    return 'Error converting data to CSV';
  }
};

module.exports = {
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
};