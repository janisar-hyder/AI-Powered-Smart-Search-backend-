const { supabase, supabaseDB } = require('../config/supabase');
const bcrypt = require('bcrypt');

// Temporary storage for OTP and registration data
const tempRegistrationData = new Map();
const tempLogins = new Map();
const tempPasswordResets = new Map();

// Enhanced storage with debugging
const enhancedTempStorage = {
  set: (key, value) => {
    tempRegistrationData.set(key, {
      ...value,
      storedAt: Date.now(),
      expiresAt: Date.now() + 30 * 60 * 1000 // 30 minutes
    });
    console.log(`✅ Temp data stored for: ${key}`);
    console.log(`📝 Current keys:`, Array.from(tempRegistrationData.keys()));
  },
  
  get: (key) => {
    const item = tempRegistrationData.get(key);
    if (!item) {
      console.log(`❌ No temp data found for: ${key}`);
      console.log(`📝 Available keys:`, Array.from(tempRegistrationData.keys()));
      return null;
    }
    
    if (Date.now() > item.expiresAt) {
      tempRegistrationData.delete(key);
      console.log(`⏰ Temp data expired for: ${key}`);
      return null;
    }
    
    console.log(`✅ Temp data found for: ${key}`);
    return item;
  },
  
  delete: (key) => {
    tempRegistrationData.delete(key);
    console.log(`🗑️ Temp data deleted for: ${key}`);
  }
};

// Helper function to determine table based on role/email
const getUserTableAndData = async (email) => {
  try {
    // Check in users table first
    let { data: user, error: userError } = await supabaseDB
      .from('users')
      .select('id, password_hash, role, email_verified, first_name, last_name, full_name, created_at')
      .eq('email', email)
      .single();

    if (user && !userError) {
      return { 
        table: 'users', 
        data: user,
        exists: true 
      };
    }

    // Check in admins table
    let { data: admin, error: adminError } = await supabaseDB
      .from('admins')
      .select('id, password_hash, role, email_verified, first_name, last_name, full_name, created_at')
      .eq('email', email)
      .single();

    if (admin && !adminError) {
      return { 
        table: 'admins', 
        data: admin,
        exists: true 
      };
    }

    return { exists: false };
  } catch (error) {
    console.error('Error checking user tables:', error);
    return { exists: false };
  }
};

// Registration with OTP (USERS ONLY)
const signUp = async (req, res) => {
  const { firstname, lastname, email, password, confirmpassword } = req.body;

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  if (!email || !firstname || !lastname || !password || !confirmpassword) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (password !== confirmpassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }

  try {
    // Check if user already exists in ANY table
    const { exists } = await getUserTableAndData(email);
    if (exists) {
      return res.status(409).json({ error: 'User/Admin already exists' });
    }

    // Create the user with password in Supabase Auth
    const { data: signUpData, error: signUpError } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          first_name: firstname,
          last_name: lastname,
          full_name: `${firstname} ${lastname}`,
          role: 'user'  // Always user for registration
        }
      }
    });

    if (signUpError) {
      // Handle the specific case where user exists in Auth but not in our DB
      if (signUpError.status === 422 && signUpError.code === 'user_already_exists') {
        console.log('ℹ️ User exists in Auth but not in our DB, proceeding...');
      } else {
        throw signUpError;
      }
    }

    // Store registration data temporarily
    enhancedTempStorage.set(email, {
      firstname,
      lastname,
      email,
      password,
      role: 'user'  // Always user for registration
    });

    // Send OTP for verification
    const { error: otpError } = await supabase.auth.signInWithOtp({
      email,
      options: {
        shouldCreateUser: false // User already exists in Auth
      }
    });

    if (otpError) throw otpError;

    return res.json({ 
      message: 'OTP sent to email for verification',
      email
    });

  } catch (error) {
    console.error('Registration error:', error);
    
    // Clean up on error
    enhancedTempStorage.delete(email);
    
    return res.status(400).json({ 
      error: error.message || 'Registration failed'
    });
  }
};

// Verify OTP and complete registration (USERS ONLY)
const verifyOTP = async (req, res) => {
  const { email, token } = req.body;

  // Validate email format first
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  console.log('🔐 Verifying OTP for:', email);

  try {
    const storedData = enhancedTempStorage.get(email);
    if (!storedData) {
      return res.status(400).json({ 
        error: 'Registration session expired. Please start over.' 
      });
    }

    const { firstname, lastname, password, role } = storedData;

    // Verify OTP
    const { data: otpData, error: otpError } = await supabase.auth.verifyOtp({
      email,
      token,
      type: 'email'
    });
    
    if (otpError) {
      console.error('OTP verification error:', otpError);
      return res.status(400).json({ 
        error: 'Invalid or expired OTP. Please try again.' 
      });
    }

    const user_id = otpData.user.id;

    // Hash password for storage
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user in users table (only users can register)
    const { data: userData, error: userError } = await supabaseDB
      .from('users')
      .insert({
        id: user_id,
        first_name: firstname,
        last_name: lastname,
        full_name: `${firstname} ${lastname}`,
        email: email,
        password_hash: passwordHash,
        role: role || 'user',
        email_verified: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })
      .select()
      .single();

    if (userError) {
      if (userError.code === '23505') {
        return res.status(409).json({ 
          error: 'User already completed registration' 
        });
      }
      throw userError;
    }

    // Clean up
    enhancedTempStorage.delete(email);

    console.log('✅ User registration completed for:', email);

    return res.json({ 
      message: 'Registration complete',
      user: {
        id: userData.id,
        first_name: userData.first_name,
        last_name: userData.last_name,
        full_name: userData.full_name,
        email: userData.email,
        role: userData.role,
        email_verified: userData.email_verified,
        created_at: userData.created_at
      },
      session: otpData.session
    });

  } catch (error) {
    console.error('Complete signup error:', error);
    
    // Clean up on error
    enhancedTempStorage.delete(email);
    
    return res.status(400).json({ 
      error: error.message || 'Registration failed'
    });
  }
};

// UNIFIED LOGIN for both Users and Admins
const loginWithPasswordAndOTP = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check in both tables
    const { table, data: user, exists } = await getUserTableAndData(email);

    if (!exists) {
      return res.status(404).json({ error: 'Account not found' });
    }

    // Check if email is verified
    if (!user.email_verified) {
      return res.status(403).json({ error: 'Please verify your email first' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Store user data temporarily
    tempLogins.set(email, {
      userId: user.id,
      role: user.role,
      table: table,
      userData: {
        first_name: user.first_name,
        last_name: user.last_name,
        full_name: user.full_name,
        email: user.email,
        created_at: user.created_at
      }
    });

    console.log(`Stored login temp data for ${email} (${table})`);

    // Send OTP
    const { error: otpError } = await supabase.auth.signInWithOtp({
      email,
      options: {
        shouldCreateUser: false
      }
    });

    if (otpError) throw otpError;

    return res.json({ 
      message: 'OTP sent to email',
      userType: table // Return whether it's user or admin for frontend reference
    });

  } catch (error) {
    console.error('Login error:', error);
    
    // Clean up on error
    tempLogins.delete(email);
    
    return res.status(400).json({ error: error.message });
  }
};

// UNIFIED Verify login OTP for both Users and Admins
const verifyLoginOTP = async (req, res) => {
  const { email, token } = req.body;

  console.log('Verifying login OTP for:', email);

  try {
    // Verify OTP - this creates the session
    const { data, error: otpError } = await supabase.auth.verifyOtp({
      email,
      token,
      type: 'email'
    });

    if (otpError) throw otpError;

    // Get stored user data
    const loginData = tempLogins.get(email);
    if (!loginData) {
      throw new Error('Login session expired');
    }

    // Get updated user data from the appropriate table
    const { data: user, error: userError } = await supabaseDB
      .from(loginData.table)
      .select('*')
      .eq('id', loginData.userId)
      .single();

    if (userError || !user) {
      throw new Error('User profile not found');
    }

    // Clean up
    tempLogins.delete(email);

    // Return the session and user information
    return res.json({
      user: {
        id: user.id,
        first_name: user.first_name,
        last_name: user.last_name,
        full_name: user.full_name,
        email: user.email,
        role: user.role,
        email_verified: user.email_verified,
        created_at: user.created_at,
        userType: loginData.table // Include user type in response
      },
      session: data.session
    });

  } catch (error) {
    console.error('OTP verification error:', error);
    
    // Clean up on error
    tempLogins.delete(email);
    
    return res.status(400).json({ 
      error: error.message,
      details: 'Please try logging in again' 
    });
  }
};

// UNIFIED Password reset for both Users and Admins
const initiatePasswordReset = async (req, res) => {
  const { email } = req.body;

  try {
    // Check if email exists in any table
    const { table, data: user, exists } = await getUserTableAndData(email);

    if (!exists) {
      return res.status(404).json({ error: 'Account not found' });
    }

    if (!user.email_verified) {
      return res.status(403).json({ error: 'Account not verified. Please verify your account first.' });
    }

    // Store the reset data temporarily
    tempPasswordResets.set(email, {
      userId: user.id,
      table: table,
      verified: false
    });

    // Send OTP
    const { error: otpError } = await supabase.auth.signInWithOtp({
      email,
      options: {
        shouldCreateUser: false
      }
    });

    if (otpError) throw otpError;

    return res.json({ 
      message: 'OTP sent to email for password reset',
      userType: table // Optional: let frontend know what type of account
    });

  } catch (error) {
    console.error('Password reset initiation error:', error);
    
    // Clean up on error
    tempPasswordResets.delete(email);
    
    return res.status(400).json({ error: error.message });
  }
};

// UNIFIED Verify password reset OTP
const verifyPasswordResetOTP = async (req, res) => {
  const { email, token } = req.body;

  try {
    // Verify OTP
    const { error: otpError } = await supabase.auth.verifyOtp({
      email,
      token,
      type: 'email'
    });

    if (otpError) throw otpError;

    // Get stored reset data
    const resetData = tempPasswordResets.get(email);
    if (!resetData) {
      throw new Error('Password reset session expired or not found');
    }

    // Mark as verified
    tempPasswordResets.set(email, {
      ...resetData,
      verified: true
    });

    return res.json({ 
      message: 'OTP verified successfully. You can now reset your password.',
      userType: resetData.table
    });

  } catch (error) {
    console.error('Password reset OTP verification error:', error);
    
    // Clean up on error
    tempPasswordResets.delete(email);
    
    return res.status(400).json({ error: error.message });
  }
};

// UNIFIED Complete password reset for both Users and Admins
const completePasswordReset = async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;

  try {
    // Validate passwords match
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    // Check password strength
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Get stored reset data
    const resetData = tempPasswordResets.get(email);
    if (!resetData || !resetData.verified) {
      return res.status(403).json({ error: 'OTP not verified or session expired' });
    }

    // Hash new password
    const newPasswordHash = await bcrypt.hash(newPassword, 10);

    // Update password in the appropriate table
    const { error: updateError } = await supabaseDB
      .from(resetData.table)
      .update({ 
        password_hash: newPasswordHash,
        updated_at: new Date().toISOString()
      })
      .eq('email', email);

    if (updateError) throw updateError;

    // Clean up
    tempPasswordResets.delete(email);

    return res.json({ 
      message: 'Password updated successfully',
      userType: resetData.table
    });

  } catch (error) {
    console.error('Password reset completion error:', error);
    
    // Clean up on error
    tempPasswordResets.delete(email);
    
    return res.status(400).json({ error: error.message });
  }
};


module.exports = {
  signUp,
  verifyOTP,
  loginWithPasswordAndOTP,
  verifyLoginOTP,
  initiatePasswordReset,
  verifyPasswordResetOTP,
  completePasswordReset,
  getUserTableAndData // Export for testing or other uses
};