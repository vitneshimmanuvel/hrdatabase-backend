import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pkg from 'pg';
const { Pool } = pkg;
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import dotenv from 'dotenv';


dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

// Validate required environment variables
const requiredEnvVars = ['DATABASE_URL', 'JWT_SECRET', 'EMAIL_HOST', 'EMAIL_USER', 'EMAIL_PASS', 'EMAIL_FROM'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`❌ Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// NEON DATABASE CONNECTION
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// EMAIL CONFIGURATION
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: parseInt(process.env.EMAIL_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

// ============================
// MISSING CODE - ADD THESE LINES
// ============================

// In-memory storage for admin OTPs (consider using Redis in production)
const adminOtps = new Map();

// Clean up expired OTPs every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [email, otpData] of adminOtps.entries()) {
    if (now > otpData.expiresAt) {
      adminOtps.delete(email);
      console.log(`🧹 Cleaned up expired OTP for: ${email}`);
    }
  }
}, 5 * 60 * 1000); // 5 minutes

// ============================
// END OF MISSING CODE
// ============================

// MIDDLEWARE SETUP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || [
    'http://localhost:3000',
    'http://localhost:5173',
    'https://hrdatabase-frontend.vercel.app'   // 👈 Add this
  ],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many authentication attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const JWT_SECRET = process.env.JWT_SECRET;

// ============================
// UTILITY FUNCTIONS
// ============================

// *** MISSING FUNCTION - ADD THIS ***
const generateOTP = () => {
  // Generate a cryptographically secure 6-digit OTP
  const buffer = crypto.randomBytes(3);
  const otp = parseInt(buffer.toString('hex'), 16) % 1000000;
  return otp.toString().padStart(6, '0');
};

const generateSecurePassword = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%';
  let password = '';
  for (let i = 0; i < 12; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
};

const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input.trim().replace(/[<>]/g, '');
};

const sendEmail = async (to, subject, htmlContent) => {
  try {
    if (!validateEmail(to)) {
      console.error('❌ Invalid email address:', to);
      return false;
    }

    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: to,
      subject: subject,
      html: htmlContent
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Email sent successfully to ${to}: ${info.messageId}`);
    return true;
  } catch (error) {
    console.error('❌ Email sending failed:', error);
    return false;
  }
};

// ============================
// MIDDLEWARE FUNCTIONS
// ============================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err.name);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: `Access denied. Required roles: ${roles.join(', ')}` });
    }
    next();
  };
};

const logAdminAction = async (adminUserId, actionType, targetType, targetId, actionDetails, ipAddress) => {
  try {
    await pool.query(`
      INSERT INTO admin_actions (admin_user_id, action_type, target_type, target_id, action_details, ip_address)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [adminUserId, actionType, targetType, targetId, JSON.stringify(actionDetails), ipAddress]);
  } catch (error) {
    console.error('Failed to log admin action:', error);
  }
};

// Parameter validation middleware
const validateRouteParams = (req, res, next) => {
  try {
    // Check for common parameter issues
    for (const [key, value] of Object.entries(req.params)) {
      if (value === undefined || value === null || value === '') {
        return res.status(400).json({ error: `Invalid parameter: ${key}` });
      }
      
      // If parameter should be numeric, validate it
      if (['id', 'connectionId', 'notificationId', 'employeeId', 'companyId'].includes(key)) {
        if (isNaN(parseInt(value))) {
          return res.status(400).json({ error: `Parameter ${key} must be a valid number` });
        }
      }
    }
    next();
  } catch (error) {
    console.error('Route parameter validation error:', error);
    res.status(400).json({ error: 'Invalid route parameters' });
  }
};

// ============================
// AUTHENTICATION ROUTES
// ============================

app.get('/auth/check-email', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email || !validateEmail(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    const result = await pool.query('SELECT user_id FROM users WHERE email = $1', [email.toLowerCase()]);
    res.json({ exists: result.rows.length > 0 });
  } catch (error) {
    console.error('Email check error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Test endpoint - remove after confirming it works
app.get('/test-generate-otp', (req, res) => {
  try {
    const testOTP = generateOTP();
    res.json({ 
      success: true,
      otp: testOTP, 
      message: 'OTP generation working!',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});
// ============================
// REGISTRATION OTP ROUTES  
// ============================

// Send OTP for registration verification
app.post('/auth/send-registration-otp', authLimiter, async (req, res) => {
  try {
    const { email, role, userData } = req.body;
    
    console.log(`📧 Registration OTP request - Email: ${email}, Role: ${role}`);
    
    // Validation
    if (!email || !validateEmail(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }
    
    if (!['employee', 'company'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role specified' });
    }
    
    // Check if email already exists
    const existingUser = await pool.query('SELECT user_id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered. Please use a different email.' });
    }
    
    // Generate OTP
    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    
    console.log(`🔢 Generated OTP: ${otp} for ${email} (expires in 10 minutes)`);
    
    // Store OTP with user data
    adminOtps.set(email.toLowerCase(), {
      otp,
      role,
      userData,
      type: 'registration',
      expiresAt,
      attempts: 0,
      createdAt: new Date().toISOString()
    });
    
    // Create welcome email content
    const userName = role === 'employee' ? userData.name : userData.companyName;
    const otpEmailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
        <div style="background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
          <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="color: #1c266a; margin-bottom: 10px; font-size: 28px;">Welcome to Settlo HR Solutions!</h1>
            <p style="color: #666; font-size: 16px; margin: 0;">Thank you for connecting with us</p>
          </div>
          
          <div style="background: linear-gradient(135deg, #1c266a 0%, #1da46f 100%); padding: 30px; border-radius: 10px; text-align: center; margin: 20px 0;">
            <h3 style="color: white; margin-bottom: 15px; font-size: 18px;">Verify Your ${role === 'employee' ? 'Employee' : 'Company'} Registration</h3>
            <p style="color: white; margin-bottom: 20px;">Hello ${userName}, please use the OTP below to complete your registration:</p>
            <div style="background: white; display: inline-block; padding: 20px 30px; border-radius: 8px; margin: 10px 0;">
              <h1 style="font-size: 36px; color: #1c266a; margin: 0; letter-spacing: 8px; font-family: monospace;">${otp}</h1>
            </div>
            <p style="color: white; margin-top: 15px; font-size: 14px;">This OTP will expire in 10 minutes</p>
          </div>
          
          <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h4 style="color: #333; margin-top: 0;">Why Settlo HR Solutions?</h4>
            ${role === 'employee' ? `
              <ul style="color: #666; line-height: 1.6;">
                <li>🎯 Personalized job matching based on your skills</li>
                <li>💼 Direct connections with top companies</li>
                <li>🚀 Fast-track your career growth</li>
                <li>🆓 Completely free service for job seekers</li>
                <li>🤝 Dedicated support throughout your journey</li>
              </ul>
            ` : `
              <ul style="color: #666; line-height: 1.6;">
                <li>🎯 Access to pre-screened, qualified candidates</li>
                <li>⚡ Quick and efficient hiring process</li>
                <li>💯 3-month warranty on all placements</li>
                <li>📈 Transparent and competitive pricing</li>
                <li>🤝 Dedicated account management</li>
              </ul>
            `}
          </div>
          
          <div style="background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; color: #333; font-size: 14px;">
              <strong>Next Steps:</strong><br>
              1. Enter the OTP in the registration form<br>
              2. Complete your profile setup<br>
              3. Start ${role === 'employee' ? 'exploring opportunities' : 'posting job requirements'}<br>
              4. Connect with our team for personalized assistance
            </p>
          </div>
          
          <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
            <p style="color: #666; font-size: 14px; margin-bottom: 10px;">
              If you didn't request this registration, please ignore this email.
            </p>
            <p style="color: #999; font-size: 12px; margin: 0;">
              <strong>Settlo HR Solutions</strong><br>
               121, Akhil Plaza, Perundurai Road, Erode, Tamil Nadu<br>
                | 📞 Contact: 90036 33356
            </p>
          </div>
        </div>
      </div>
    `;
    
    // Send email
    const emailSent = await sendEmail(
      email,
      `Welcome to Settlo HR! Verify Your ${role === 'employee' ? 'Employee' : 'Company'} Registration`,
      otpEmailHtml
    );
    
    if (!emailSent) {
      console.error(`❌ Failed to send OTP email to: ${email}`);
      adminOtps.delete(email.toLowerCase());
      return res.status(500).json({ error: 'Failed to send OTP email. Please try again.' });
    }
    
    console.log(`✅ Registration OTP sent successfully to: ${email} for role: ${role}`);
    res.json({ 
      message: 'OTP sent successfully! Please check your inbox or spam folder.',
      email: email,
      role: role,
      expiresIn: '10 minutes'
    });
    
  } catch (error) {
    console.error('Send registration OTP error:', error);
    res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
  }
});

// Resend registration OTP
app.post('/auth/resend-registration-otp', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    
    console.log(`🔄 Registration OTP resend request - Email: ${email}`);
    
    if (!email || !validateEmail(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }
    
    // Check if there's an existing OTP request
    const storedOtp = adminOtps.get(email.toLowerCase());
    if (!storedOtp || storedOtp.type !== 'registration') {
      return res.status(400).json({ error: 'No registration OTP request found. Please start the process again.' });
    }
    
    // Generate new OTP
    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    
    console.log(`🔢 Generated new OTP: ${otp} for ${email}`);
    
    // Update stored OTP
    adminOtps.set(email.toLowerCase(), {
      ...storedOtp,
      otp,
      expiresAt,
      attempts: 0 // Reset attempts
    });
    
    const userName = storedOtp.role === 'employee' ? storedOtp.userData.name : storedOtp.userData.companyName;
    
    // Send new OTP email (simplified version)
    const otpEmailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #1c266a; margin-bottom: 10px;">Settlo HR Solutions</h1>
          <h2 style="color: #333; margin: 0;">Registration OTP - Resent</h2>
        </div>
        
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; text-align: center; margin: 20px 0;">
          <h3 style="color: white; margin-bottom: 15px;">Your New Registration OTP</h3>
          <p style="color: white; margin-bottom: 20px;">Hello ${userName}, here's your new OTP:</p>
          <div style="background: white; display: inline-block; padding: 20px 30px; border-radius: 8px; margin: 10px 0;">
            <h1 style="font-size: 36px; color: #1c266a; margin: 0; letter-spacing: 8px; font-family: monospace;">${otp}</h1>
          </div>
          <p style="color: white; margin-top: 15px; font-size: 14px;">This OTP will expire in 10 minutes</p>
        </div>
        
        <p style="color: #666; font-size: 14px; text-align: center;">
          This is a resent OTP. If you didn't request this, please ignore this email.
        </p>
        
        <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
          <p style="color: #999; font-size: 12px; margin: 0;">
            Best regards,<br>Settlo HR Team<br>
            📍 121, Akhil Plaza, Perundurai Road, Erode
          </p>
        </div>
      </div>
    `;
    
    const emailSent = await sendEmail(
      email,
      'Registration OTP (Resent) - Settlo HR',
      otpEmailHtml
    );
    
    if (!emailSent) {
      console.error(`❌ Failed to resend OTP email to: ${email}`);
      return res.status(500).json({ error: 'Failed to resend OTP email. Please try again.' });
    }
    
    console.log(`✅ Registration OTP resent successfully to: ${email}`);
    res.json({ message: 'OTP resent successfully! Please check your inbox or spam folder.' });
    
  } catch (error) {
    console.error('Resend registration OTP error:', error);
    res.status(500).json({ error: 'Failed to resend OTP. Please try again.' });
  }
});

// Verify OTP and complete registration
app.post('/auth/verify-registration-otp', authLimiter, async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { email, otp } = req.body;
    
    console.log(`🔐 Registration OTP verification - Email: ${email}, OTP: ${otp}`);
    
    if (!email || !otp) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Email and OTP are required' });
    }
    
    // Verify OTP
    const storedOtp = adminOtps.get(email.toLowerCase());
    if (!storedOtp || storedOtp.type !== 'registration') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No registration OTP found. Please request a new OTP.' });
    }
    
    if (Date.now() > storedOtp.expiresAt) {
      adminOtps.delete(email.toLowerCase());
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
    }
    
    if (storedOtp.otp !== otp) {
      storedOtp.attempts += 1;
      if (storedOtp.attempts >= 3) {
        adminOtps.delete(email.toLowerCase());
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Too many failed attempts. Please request a new OTP.' });
      }
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Invalid OTP. ${3 - storedOtp.attempts} attempts remaining.` });
    }
    
    // OTP verified, now complete registration
    const { role, userData } = storedOtp;
    
    // Check email doesn't exist (double check)
    const existingUser = await client.query('SELECT user_id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existingUser.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(userData.password, saltRounds);
    
    // Create user
    const userResult = await client.query(`
      INSERT INTO users (email, password_hash, role, is_active) 
      VALUES ($1, $2, $3, true) 
      RETURNING user_id
    `, [email.toLowerCase(), hashedPassword, role]);
    
    const userId = userResult.rows[0].user_id;
    
    // Create role-specific profile
    if (role === 'employee') {
      await client.query(`
        INSERT INTO employees (user_id, full_name, phone, qualification, industry, preferred_location, preferred_salary)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [userId, userData.name, userData.mobile.replace('+91', ''), userData.qualification, 
          userData.industry, userData.emplocation, userData.empsalary || 0]);

      // Handle skills
      if (userData.skills) {
        const skillsArray = userData.skills.split(',').map(skill => skill.trim()).filter(skill => skill);
        for (const skillName of skillsArray) {
          const skillResult = await client.query(`
            INSERT INTO skills (name, category) VALUES ($1, $2) 
            ON CONFLICT (name) DO NOTHING 
            RETURNING skill_id
          `, [skillName, 'General']);
          
          let skillId;
          if (skillResult.rows.length > 0) {
            skillId = skillResult.rows[0].skill_id;
          } else {
            const existingSkill = await client.query('SELECT skill_id FROM skills WHERE name = $1', [skillName]);
            if (existingSkill.rows.length > 0) {
              skillId = existingSkill.rows.skill_id;
            }
          }
          
          if (skillId) {
            const empResult = await client.query('SELECT employee_id FROM employees WHERE user_id = $1', [userId]);
            if (empResult.rows.length > 0) {
              await client.query(`
                INSERT INTO employee_skills (employee_id, skill_id, proficiency_level)
                VALUES ($1, $2, $3)
                ON CONFLICT (employee_id, skill_id) DO NOTHING
              `, [empResult.rows[0].employee_id, skillId, 'intermediate']);
            }
          }
        }
      }
    } else if (role === 'company') {
      await client.query(`
        INSERT INTO companies (user_id, name, companyname, contact_person_phone, contact_email, industry, location, contact_person_name)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `, [userId, userData.companyName, userData.companyName, userData.mobile.replace('+91', ''), 
          email.toLowerCase(), userData.industry, userData.location, userData.contactPersonName]);
    }
    
    await client.query('COMMIT');
    
    // Clean up OTP
    adminOtps.delete(email.toLowerCase());
    
    console.log(`✅ Registration completed successfully: ${email} as ${role}`);
    
    res.status(201).json({ 
      message: 'Registration successful! Welcome to Settlo HR Solutions.',
      userId: userId,
      role: role
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Registration verification error:', error);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  } finally {
    client.release();
  }
});


app.post('/auth/register', authLimiter, async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');

    const { 
      role, email, password, mobile, name, companyName, contactPersonName,
      location, qualification, industry, emplocation, empsalary, skills
    } = req.body;

    // Sanitize inputs
    const sanitizedData = {
      role: sanitizeInput(role),
      email: sanitizeInput(email)?.toLowerCase(),
      name: sanitizeInput(name),
      companyName: sanitizeInput(companyName),
      contactPersonName: sanitizeInput(contactPersonName),
      location: sanitizeInput(location),
      qualification: sanitizeInput(qualification),
      industry: sanitizeInput(industry),
      emplocation: sanitizeInput(emplocation),
      mobile: sanitizeInput(mobile),
      skills: sanitizeInput(skills)
    };

    console.log('📝 Registration attempt:', { email: sanitizedData.email, role: sanitizedData.role });

    // Validation
    if (!sanitizedData.role || !sanitizedData.email || !password) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Role, email, and password are required' });
    }

    if (!validateEmail(sanitizedData.email)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (!['employee', 'company', 'admin', 'super_admin'].includes(sanitizedData.role)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Invalid role specified' });
    }

    if (password.length < 8) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    const existingUser = await client.query('SELECT user_id FROM users WHERE email = $1', [sanitizedData.email]);
    if (existingUser.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Email already registered' });
    }

    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const userResult = await client.query(`
      INSERT INTO users (email, password_hash, role, is_active) 
      VALUES ($1, $2, $3, true) 
      RETURNING user_id
    `, [sanitizedData.email, hashedPassword, sanitizedData.role]);

    const userId = userResult.rows[0].user_id;

    if (sanitizedData.role === 'employee') {
      await client.query(`
        INSERT INTO employees (user_id, full_name, phone, qualification, industry, preferred_location, preferred_salary)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [userId, sanitizedData.name, sanitizedData.mobile, sanitizedData.qualification, 
          sanitizedData.industry, sanitizedData.emplocation, empsalary || 0]);

      if (sanitizedData.skills) {
        const skillsArray = sanitizedData.skills.split(',').map(skill => skill.trim()).filter(skill => skill);
        for (const skillName of skillsArray) {
          const skillResult = await client.query(`
            INSERT INTO skills (name, category) VALUES ($1, $2) 
            ON CONFLICT (name) DO NOTHING 
            RETURNING skill_id
          `, [skillName, 'General']);
          
          let skillId;
          if (skillResult.rows.length > 0) {
            skillId = skillResult.rows[0].skill_id;
          } else {
            const existingSkill = await client.query('SELECT skill_id FROM skills WHERE name = $1', [skillName]);
            if (existingSkill.rows.length > 0) {
              skillId = existingSkill.rows[0].skill_id;
            }
          }
          
          if (skillId) {
            const empResult = await client.query('SELECT employee_id FROM employees WHERE user_id = $1', [userId]);
            if (empResult.rows.length > 0) {
              await client.query(`
                INSERT INTO employee_skills (employee_id, skill_id, proficiency_level)
                VALUES ($1, $2, $3)
                ON CONFLICT (employee_id, skill_id) DO NOTHING
              `, [empResult.rows[0].employee_id, skillId, 'intermediate']);
            }
          }
        }
      }
    } else if (sanitizedData.role === 'company') {
      await client.query(`
        INSERT INTO companies (user_id, name, companyname, contact_person_phone, contact_email, industry, location, contact_person_name)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `, [userId, sanitizedData.companyName, sanitizedData.companyName, sanitizedData.mobile, 
          sanitizedData.email, sanitizedData.industry, sanitizedData.location, sanitizedData.contactPersonName]);
    }

    await client.query('COMMIT');
    
    // Send welcome email
    const welcomeEmailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Welcome to Settlo HR Solutions!</h2>
        <p>Hello ${sanitizedData.role === 'employee' ? sanitizedData.name : sanitizedData.companyName},</p>
        <p>Your account has been successfully created as a <strong>${sanitizedData.role}</strong>.</p>
        <p>You can now log in and start using our HR management system.</p>
        <div style="margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-left: 4px solid #007bff;">
          <p><strong>Next Steps:</strong></p>
          <ul>
            <li>Complete your profile information</li>
            <li>Explore available features</li>
            <li>Contact support if you need assistance</li>
          </ul>
        </div>
        <p>Best regards,<br>Settlo HR Team</p>
      </div>
    `;
    
    await sendEmail(sanitizedData.email, 'Welcome to Settlo HR Solutions', welcomeEmailHtml);
    
    console.log(`✅ User registered successfully: ${sanitizedData.email} as ${sanitizedData.role}`);
    res.status(201).json({ 
      message: 'Registration successful',
      userId: userId,
      role: sanitizedData.role
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  } finally {
    client.release();
  }
});

app.delete('/api/admin/job-requests/:id', authenticateToken, authorizeRole(['super_admin']), async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    
    // Get job request details before deletion
    const jobResult = await client.query('SELECT title, company_id FROM job_requests WHERE request_id = $1', [id]);
    if (jobResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Job request not found' });
    }
    
    const job = jobResult.rows[0];
    
    // Delete job request (CASCADE will handle related records like connections)
    await client.query('DELETE FROM job_requests WHERE request_id = $1', [id]);
    
    await client.query('COMMIT');
    
    console.log(`✅ Job request deleted: ${job.title}`);
    res.json({ message: 'Job request deleted successfully' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Delete job request error:', error);
    res.status(500).json({ error: 'Failed to delete job request' });
  } finally {
    client.release();
  }
});



// Add this route for sending OTP for password reset
app.post('/auth/send-otp', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email || !validateEmail(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }
    
    // Check if user exists
    const userResult = await pool.query('SELECT user_id, email FROM users WHERE email = $1', [email.toLowerCase()]);
    if (userResult.rows.length === 0) {
      // Don't reveal if email exists or not
      return res.json({ message: 'If the email exists, an OTP has been sent.' });
    }
    
    // Generate OTP
    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    
    // Store OTP (you can reuse the adminOtps Map or create a separate one)
    adminOtps.set(email.toLowerCase(), {
      otp,
      type: 'password_reset',
      expiresAt,
      attempts: 0,
      createdAt: new Date().toISOString()
    });
    
    // Send OTP email
    const otpEmailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #1c266a;">Password Reset OTP</h2>
        <p>Hello,</p>
        <p>You have requested to reset your password. Use the OTP below:</p>
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
          <h1 style="font-size: 36px; color: #1c266a; margin: 0; letter-spacing: 8px;">${otp}</h1>
        </div>
        <p>This OTP will expire in 10 minutes.</p>
        <p>If you didn't request this, please ignore this email.</p>
        <p>Best regards,<br>Settlo HR Team</p>
      </div>
    `;
    
    const emailSent = await sendEmail(email, 'Password Reset OTP - Settlo HR', otpEmailHtml);
    
    if (!emailSent) {
      adminOtps.delete(email.toLowerCase());
      return res.status(500).json({ error: 'Failed to send OTP email. Please try again.' });
    }
    
    res.json({ message: 'OTP sent successfully' });
    
  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
  }
});

// Add this route for resending OTP
app.post('/auth/resend-otp', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email || !validateEmail(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }
    
    // Check if there's an existing OTP request
    const storedOtp = adminOtps.get(email.toLowerCase());
    if (!storedOtp || storedOtp.type !== 'password_reset') {
      return res.status(400).json({ error: 'No OTP request found. Please start the process again.' });
    }
    
    // Generate new OTP
    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    
    // Update stored OTP
    adminOtps.set(email.toLowerCase(), {
      ...storedOtp,
      otp,
      expiresAt,
      attempts: 0 // Reset attempts
    });
    
    // Send new OTP email (same format as above)
    const otpEmailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #1c266a;">Password Reset OTP (Resent)</h2>
        <p>Hello,</p>
        <p>You have requested a new OTP. Use the OTP below:</p>
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
          <h1 style="font-size: 36px; color: #1c266a; margin: 0; letter-spacing: 8px;">${otp}</h1>
        </div>
        <p>This OTP will expire in 10 minutes.</p>
        <p>Best regards,<br>Settlo HR Team</p>
      </div>
    `;
    
    const emailSent = await sendEmail(email, 'Password Reset OTP (Resent) - Settlo HR', otpEmailHtml);
    
    if (!emailSent) {
      return res.status(500).json({ error: 'Failed to resend OTP email. Please try again.' });
    }
    
    res.json({ message: 'OTP resent successfully' });
    
  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ error: 'Failed to resend OTP. Please try again.' });
  }
});

// Add this route for resetting password with OTP
app.post('/auth/reset-password-with-otp', authLimiter, async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ error: 'Email, OTP, and new password are required' });
    }
    
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }
    
    // Verify OTP
    const storedOtp = adminOtps.get(email.toLowerCase());
    if (!storedOtp || storedOtp.type !== 'password_reset') {
      return res.status(400).json({ error: 'No OTP found. Please request a new OTP.' });
    }
    
    if (Date.now() > storedOtp.expiresAt) {
      adminOtps.delete(email.toLowerCase());
      return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
    }
    
    if (storedOtp.otp !== otp) {
      storedOtp.attempts += 1;
      if (storedOtp.attempts >= 3) {
        adminOtps.delete(email.toLowerCase());
        return res.status(400).json({ error: 'Too many failed attempts. Please request a new OTP.' });
      }
      return res.status(400).json({ error: `Invalid OTP. ${3 - storedOtp.attempts} attempts remaining.` });
    }
    
    // Get user
    const userResult = await pool.query('SELECT user_id, email FROM users WHERE email = $1', [email.toLowerCase()]);
    if (userResult.rows.length === 0) {
      adminOtps.delete(email.toLowerCase());
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = userResult.rows[0];
    
    // Hash new password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    
    // Update password
    await pool.query(`
      UPDATE users SET 
        password_hash = $1,
        failed_login_attempts = 0,
        locked_until = NULL
      WHERE user_id = $2
    `, [hashedPassword, user.user_id]);
    
    // Clean up OTP
    adminOtps.delete(email.toLowerCase());
    
    console.log(`✅ Password reset successfully for: ${user.email}`);
    res.json({ message: 'Password reset successfully' });
    
  } catch (error) {
    console.error('Reset password with OTP error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

app.delete('/api/admin/connections/:id', authenticateToken, authorizeRole(['super_admin']), async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    
    // Get connection details before deletion
    const connResult = await client.query(`
      SELECT jrc.*, e.full_name as employee_name, jr.title as job_title, c.name as company_name
      FROM job_request_connections jrc
      JOIN employees e ON jrc.employee_id = e.employee_id
      JOIN job_requests jr ON jrc.request_id = jr.request_id
      JOIN companies c ON jrc.company_id = c.company_id
      WHERE jrc.connection_id = $1
    `, [id]);
    
    if (connResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Connection not found' });
    }
    
    const connection = connResult.rows[0];
    
    // Delete connection
    await client.query('DELETE FROM job_request_connections WHERE connection_id = $1', [id]);
    
    await client.query('COMMIT');
    
    console.log(`✅ Connection deleted: ${connection.employee_name} - ${connection.job_title}`);
    res.json({ message: 'Connection deleted successfully' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Delete connection error:', error);
    res.status(500).json({ error: 'Failed to delete connection' });
  } finally {
    client.release();
  }
});
app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log('🔐 Login attempt:', { email });

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const userResult = await pool.query(`
      SELECT user_id, email, password_hash, role, is_active 
      FROM users 
      WHERE email = $1
    `, [email.toLowerCase()]);

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = userResult.rows[0];

    if (!user.is_active) {
      return res.status(401).json({ error: 'Account is deactivated. Please contact administrator.' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = $1', [user.user_id]);

    const token = jwt.sign(
      { 
        userId: user.user_id, 
        email: user.email, 
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    console.log(`✅ User logged in: ${email} as ${user.role}`);
    res.json({
      token,
      role: user.role,
      userId: user.user_id,
      email: user.email
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

app.post('/auth/send-admin-otp', authLimiter, async (req, res) => {
  try {
    const { email, role } = req.body;
    
    console.log(`📧 Admin OTP request - Email: ${email}, Role: ${role}`);
    
    // Validation
    if (!email || !validateEmail(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }
    
    if (!['admin', 'super_admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid admin role' });
    }
    
    // Validate super_admin email requirement
    if (role === 'super_admin' && !email.toLowerCase().includes('settlo')) {
      return res.status(400).json({ error: 'Super admin email must contain "settlo"' });
    }
    
    // Check if email already exists in database
    const existingUser = await pool.query('SELECT user_id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    // Generate OTP - This should now work!
    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes from now
    
    console.log(`🔢 Generated OTP: ${otp} for ${email} (expires in 10 minutes)`);
    
    // Store OTP in memory
    adminOtps.set(email.toLowerCase(), {
      otp,
      role,
      expiresAt,
      attempts: 0,
      createdAt: new Date().toISOString()
    });
    
    // Create email content
    const otpEmailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #1c266a; margin-bottom: 10px;">Settlo HR</h1>
          <h2 style="color: #333; margin: 0;">Admin Account Verification</h2>
        </div>
        
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; text-align: center; margin: 20px 0;">
          <h3 style="color: white; margin-bottom: 15px;">Your ${role === 'super_admin' ? 'Super Admin' : 'Admin'} Account OTP</h3>
          <div style="background: white; display: inline-block; padding: 20px 30px; border-radius: 8px; margin: 10px 0;">
            <h1 style="font-size: 36px; color: #1c266a; margin: 0; letter-spacing: 8px; font-family: monospace;">${otp}</h1>
          </div>
          <p style="color: white; margin-top: 15px; font-size: 14px;">This OTP will expire in 10 minutes</p>
        </div>
        
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <p style="margin: 0; color: #666; font-size: 14px;"><strong>Account Details:</strong></p>
          <p style="margin: 5px 0; color: #333;">Email: ${email}</p>
          <p style="margin: 5px 0; color: #333;">Role: ${role === 'super_admin' ? 'Super Administrator' : 'Administrator'}</p>
        </div>
        
        <p style="color: #666; font-size: 14px; text-align: center;">
          If you didn't request this, please ignore this email.
        </p>
        
        <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
          <p style="color: #999; font-size: 12px; margin: 0;">Best regards,<br>Settlo HR Team</p>
        </div>
      </div>
    `;
    
    // Send email
    const emailSent = await sendEmail(
      email,
      `${role === 'super_admin' ? 'Super Admin' : 'Admin'} Account OTP - Settlo HR`,
      otpEmailHtml
    );
    
    if (!emailSent) {
      console.error(`❌ Failed to send email to: ${email}`);
      // Clean up stored OTP if email failed
      adminOtps.delete(email.toLowerCase());
      return res.status(500).json({ error: 'Failed to send OTP email. Please try again.' });
    }
    
    console.log(`✅ Admin OTP sent successfully to: ${email} for role: ${role}`);
    res.json({ 
      message: 'OTP sent successfully',
      email: email,
      role: role,
      expiresIn: '10 minutes'
    });
    
  } catch (error) {
    console.error('Send admin OTP error:', error);
    res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
  }
});

app.post('/auth/register/admin', authLimiter, async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { email, password, otp, role } = req.body;
    
    console.log(`🔐 Admin registration attempt - Email: ${email}, Role: ${role}`);
    
    // Validation
    if (!email || !password || !otp || !role) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Email, password, OTP, and role are required' });
    }
    
    if (!['admin', 'super_admin'].includes(role)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Invalid admin role' });
    }
    
    if (password.length < 8) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }
    
    const sanitizedEmail = email.toLowerCase().trim();
    
    // Verify OTP
    const storedOtp = adminOtps.get(sanitizedEmail);
    if (!storedOtp) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No OTP found. Please request a new OTP.' });
    }
    
    if (Date.now() > storedOtp.expiresAt) {
      adminOtps.delete(sanitizedEmail);
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
    }
    
    if (storedOtp.otp !== otp) {
      storedOtp.attempts += 1;
      if (storedOtp.attempts >= 3) {
        adminOtps.delete(sanitizedEmail);
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Too many failed attempts. Please request a new OTP.' });
      }
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Invalid OTP. ${3 - storedOtp.attempts} attempts remaining.` });
    }
    
    if (storedOtp.role !== role) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Role mismatch. Please try again.' });
    }
    
    // Check if email already exists
    const existingUser = await client.query('SELECT user_id FROM users WHERE email = $1', [sanitizedEmail]);
    if (existingUser.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Create admin user
    const userResult = await client.query(`
      INSERT INTO users (email, password_hash, role, is_active, created_at) 
      VALUES ($1, $2, $3, true, NOW()) 
      RETURNING user_id, email, role, created_at
    `, [sanitizedEmail, hashedPassword, role]);
    
    const newUser = userResult.rows[0];
    
    // Clean up OTP
    adminOtps.delete(sanitizedEmail);
    
    await client.query('COMMIT');
    
    console.log(`✅ ${role} account created successfully: ${sanitizedEmail} (ID: ${newUser.user_id})`);
    
    res.status(201).json({ 
      message: `${role === 'super_admin' ? 'Super Admin' : 'Admin'} account created successfully`,
      userId: newUser.user_id,
      role: role,
      email: sanitizedEmail,
      createdAt: newUser.created_at
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Admin registration error:', error);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  } finally {
    client.release();
  }
});

app.post('/auth/resend-admin-otp', authLimiter, async (req, res) => {
  try {
    const { email, role } = req.body;
    
    console.log(`🔄 Admin OTP resend request - Email: ${email}, Role: ${role}`);
    
    if (!email || !validateEmail(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }
    
    // Check if there's an existing OTP request
    const storedOtp = adminOtps.get(email.toLowerCase());
    if (!storedOtp) {
      return res.status(400).json({ error: 'No OTP request found. Please start the process again.' });
    }
    
    // Generate new OTP
    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    
    console.log(`🔢 Generated new OTP: ${otp} for ${email}`);
    
    // Update stored OTP
    adminOtps.set(email.toLowerCase(), {
      ...storedOtp,
      otp,
      expiresAt,
      attempts: 0 // Reset attempts
    });
    
    // Send new OTP email (same format as above)
    const otpEmailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #1c266a; margin-bottom: 10px;">Settlo HR</h1>
          <h2 style="color: #333; margin: 0;">Admin Account Verification - Resent</h2>
        </div>
        
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; text-align: center; margin: 20px 0;">
          <h3 style="color: white; margin-bottom: 15px;">Your New ${role === 'super_admin' ? 'Super Admin' : 'Admin'} Account OTP</h3>
          <div style="background: white; display: inline-block; padding: 20px 30px; border-radius: 8px; margin: 10px 0;">
            <h1 style="font-size: 36px; color: #1c266a; margin: 0; letter-spacing: 8px; font-family: monospace;">${otp}</h1>
          </div>
          <p style="color: white; margin-top: 15px; font-size: 14px;">This OTP will expire in 10 minutes</p>
        </div>
        
        <p style="color: #666; font-size: 14px; text-align: center;">
          This is a resent OTP. If you didn't request this, please ignore this email.
        </p>
        
        <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
          <p style="color: #999; font-size: 12px; margin: 0;">Best regards,<br>Settlo HR Team</p>
        </div>
      </div>
    `;
    
    const emailSent = await sendEmail(
      email,
      `${role === 'super_admin' ? 'Super Admin' : 'Admin'} Account OTP (Resent) - Settlo HR`,
      otpEmailHtml
    );
    
    if (!emailSent) {
      console.error(`❌ Failed to resend email to: ${email}`);
      return res.status(500).json({ error: 'Failed to resend OTP email. Please try again.' });
    }
    
    console.log(`✅ Admin OTP resent successfully to: ${email} for role: ${role}`);
    res.json({ message: 'OTP resent successfully' });
    
  } catch (error) {
    console.error('Resend admin OTP error:', error);
    res.status(500).json({ error: 'Failed to resend OTP. Please try again.' });
  }
});

// ============================
// PROFILE MANAGEMENT ROUTES
// ============================

app.get('/users/profile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    if (req.user.role === 'employee') {
      const result = await pool.query(`
        SELECT 
          u.user_id, u.email, u.role, u.is_active, u.created_at,
          e.employee_id, e.full_name, e.phone, e.qualification, e.industry, 
          e.preferred_location, e.preferred_salary, e.experience_years,
          e.current_status, e.resume_url, e.linkedin_url, e.portfolio_url,
          e.date_of_birth, e.address, e.emergency_contact, e.emergency_contact_name
        FROM users u 
        JOIN employees e ON u.user_id = e.user_id 
        WHERE u.user_id = $1
      `, [userId]);
      
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Employee profile not found' });
      }
      
      // Get employee skills
      const skillsResult = await pool.query(`
        SELECT s.name, es.proficiency_level, es.years_of_experience
        FROM employee_skills es
        JOIN skills s ON es.skill_id = s.skill_id
        WHERE es.employee_id = $1
      `, [result.rows[0].employee_id]);
      
      const profile = {
        ...result.rows[0],
        skills: skillsResult.rows
      };
      
      console.log('✅ Employee profile fetched successfully');
      res.json(profile);
      
    } else if (req.user.role === 'company') {
      const result = await pool.query(`
        SELECT 
          u.user_id, u.email, u.role, u.is_active, u.created_at,
          c.company_id, c.name, c.companyname, c.contact_person_name, c.contact_person_phone,
          c.contact_email, c.industry, c.location, c.company_size, c.website_url,
          c.about_us, c.logo_url, c.established_year, c.verified, c.rating, c.total_placements
        FROM users u 
        JOIN companies c ON u.user_id = c.user_id 
        WHERE u.user_id = $1
      `, [userId]);
      
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Company profile not found' });
      }
      
      res.json(result.rows[0]);
      
    } else {
      const result = await pool.query(`
        SELECT user_id, email, role, is_active, created_at
        FROM users WHERE user_id = $1
      `, [userId]);
      
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      res.json(result.rows[0]);
    }
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// ============================
// JOB MANAGEMENT ROUTES
// ============================

app.post('/jobs/create', authenticateToken, authorizeRole(['company', 'admin', 'super_admin']), async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const userId = req.user.userId;
    const {
      title, domain, description, requirements, employment_type, location, 
      salary_range, min_salary, max_salary, count, status = 'open', 
      expires_at, required_experience_years, remote_allowed, benefits, 
      working_hours, required_skills, company_id
    } = req.body;

    let actualCompanyId = company_id;
    
    // If user is company, get their company_id
    if (req.user.role === 'company') {
      const companyResult = await client.query('SELECT company_id FROM companies WHERE user_id = $1', [userId]);
      
      if (companyResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Company profile not found' });
      }
      
      actualCompanyId = companyResult.rows[0].company_id;
    }

    if (!actualCompanyId) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Company ID is required' });
    }

    // **ADD THIS: Normalize employment_type to match database constraint**
    const normalizeEmploymentType = (type) => {
      if (!type) return null;
      
      const typeMap = {
        'Full-time': 'full_time',
        'full-time': 'full_time',
        'Full Time': 'full_time',
        'full time': 'full_time',
        'FULL_TIME': 'full_time',
        'FULLTIME': 'full_time',
        
        'Part-time': 'part_time',
        'part-time': 'part_time',
        'Part Time': 'part_time',
        'part time': 'part_time',
        'PART_TIME': 'part_time',
        'PARTTIME': 'part_time',
        
        'Contract': 'contract',
        'CONTRACT': 'contract',
        'Contractor': 'contract',
        
        'Internship': 'internship',
        'INTERNSHIP': 'internship',
        'Intern': 'internship'
      };
      
      // First try exact match from map
      if (typeMap[type]) {
        return typeMap[type];
      }
      
      // If not found, try case-insensitive match
      const lowerType = type.toLowerCase();
      for (const [key, value] of Object.entries(typeMap)) {
        if (key.toLowerCase() === lowerType) {
          return value;
        }
      }
      
      // If still not found, return lowercase with underscores
      return type.toLowerCase().replace(/[\s-]+/g, '_');
    };

    const normalizedEmploymentType = normalizeEmploymentType(employment_type);

    const sanitizedData = {
      title: sanitizeInput(title),
      domain: sanitizeInput(domain),
      description: sanitizeInput(description),
      requirements: sanitizeInput(requirements),
      employment_type: normalizedEmploymentType, // Use normalized value
      location: sanitizeInput(location),
      salary_range: sanitizeInput(salary_range),
      status: sanitizeInput(status),
      benefits: sanitizeInput(benefits),
      working_hours: sanitizeInput(working_hours)
    };

    if (!sanitizedData.title || !sanitizedData.description || 
        !sanitizedData.employment_type || !sanitizedData.location) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'All required fields must be filled' });
    }

    // **ADD THIS: Validate employment type against allowed values**
    const allowedEmploymentTypes = ['full_time', 'part_time', 'contract', 'internship'];
    if (!allowedEmploymentTypes.includes(sanitizedData.employment_type)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        error: `Invalid employment type. Allowed values: ${allowedEmploymentTypes.join(', ')}`,
        received: employment_type,
        normalized: sanitizedData.employment_type
      });
    }

    if (!count || count < 1) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Number of positions must be at least 1' });
    }

    const result = await client.query(`
      INSERT INTO job_requests 
      (company_id, title, domain, description, requirements, employment_type, 
       location, salary_range, min_salary, max_salary, count, status, expires_at, 
       required_experience_years, remote_allowed, benefits, working_hours, 
       created_by_admin)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
      RETURNING *
    `, [actualCompanyId, sanitizedData.title, sanitizedData.domain, sanitizedData.description, 
        sanitizedData.requirements, sanitizedData.employment_type, sanitizedData.location, 
        sanitizedData.salary_range, min_salary, max_salary, parseInt(count), sanitizedData.status, 
        expires_at, required_experience_years || 0, remote_allowed || false, 
        sanitizedData.benefits, sanitizedData.working_hours, req.user.role !== 'company']);

    const jobId = result.rows[0].request_id;

    // Add required skills if provided (rest of the code remains the same)
    if (required_skills && Array.isArray(required_skills)) {
      for (const skill of required_skills) {
        if (skill.name && skill.name.trim()) {
          const skillResult = await client.query(`
            INSERT INTO skills (name, category) VALUES ($1, $2) 
            ON CONFLICT (name) DO NOTHING 
            RETURNING skill_id
          `, [skill.name.trim(), skill.category || 'General']);
          
          let skillId;
          if (skillResult.rows.length > 0) {
            skillId = skillResult.rows[0].skill_id;
          } else {
            const existingSkill = await client.query('SELECT skill_id FROM skills WHERE name = $1', [skill.name.trim()]);
            if (existingSkill.rows.length > 0) {
              skillId = existingSkill.rows[0].skill_id;
            }
          }
          
          if (skillId) {
            await client.query(`
              INSERT INTO job_required_skills (request_id, skill_id, importance_level, min_experience_years)
              VALUES ($1, $2, $3, $4)
            `, [jobId, skillId, skill.importance_level || 'preferred', skill.min_experience_years || 0]);
          }
        }
      }
    }

    await client.query('COMMIT');

    console.log(`✅ Job request created: ${sanitizedData.title} by ${req.user.role} ${userId}`);
    res.status(201).json(result.rows[0]);

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Create job request error:', error);
    res.status(500).json({ error: 'Failed to create job request' });
  } finally {
    client.release();
  }
});

app.get('/jobs/requests', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { status, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    let query = `
      SELECT jr.*, c.name as company_name, c.industry as company_industry,
             (SELECT COUNT(*) FROM job_request_connections jrc WHERE jrc.request_id = jr.request_id) as connection_count,
             (SELECT COUNT(*) FROM job_request_connections jrc WHERE jrc.request_id = jr.request_id AND jrc.placement_status = 'placed') as placed_count,
             (SELECT array_agg(json_build_object('name', s.name, 'importance', jrs.importance_level)) 
              FROM job_required_skills jrs 
              JOIN skills s ON jrs.skill_id = s.skill_id 
              WHERE jrs.request_id = jr.request_id) as required_skills
      FROM job_requests jr 
      JOIN companies c ON jr.company_id = c.company_id
    `;
    
    const queryParams = [];
    const conditions = [];

    // Role-based filtering
    if (req.user.role === 'company') {
      const companyResult = await pool.query('SELECT company_id FROM companies WHERE user_id = $1', [userId]);
      if (companyResult.rows.length === 0) {
        return res.status(404).json({ error: 'Company profile not found' });
      }
      conditions.push(`jr.company_id = $${queryParams.length + 1}`);
      queryParams.push(companyResult.rows[0].company_id);
    }

    if (status) {
      conditions.push(`jr.status = $${queryParams.length + 1}`);
      queryParams.push(status);
    }

    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }

    query += ` ORDER BY jr.created_at DESC LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`;
    queryParams.push(limit, offset);

    const result = await pool.query(query, queryParams);

    console.log(`📋 Fetched ${result.rows.length} job requests for ${req.user.role}`);
    res.json(result.rows);

  } catch (error) {
    console.error('Get job requests error:', error);
    res.status(500).json({ error: 'Failed to fetch job requests' });
  }
});

// Continue with the rest of your routes... (Employee Dashboard, Company Dashboard, Profile Updates, Notifications, Skills, Password Reset, Admin Management, etc.)

// I'll continue with the remaining routes in the next part to avoid hitting message length limits

// ============================
// EMPLOYEE DASHBOARD ROUTES
// ============================

app.get('/api/employee/admin-connected-jobs', authenticateToken, authorizeRole(['employee']), async (req, res) => {
  try {
    const userId = req.user.userId;

    const empResult = await pool.query('SELECT employee_id FROM employees WHERE user_id = $1', [userId]);
    
    if (empResult.rows.length === 0) {
      return res.status(404).json({ error: 'Employee profile not found' });
    }

    const employeeId = empResult.rows[0].employee_id;

    const result = await pool.query(`
      SELECT 
        jr.request_id as id,
        jr.title,
        jr.domain,
        jr.description,
        jr.requirements,
        jr.employment_type,
        jr.location,
        jr.salary_range,
        jr.min_salary,
        jr.max_salary,
        jr.created_at,
        c.name as company_name,
        c.industry as company_industry,
        jrc.connection_id,
        jrc.connection_date,
        jrc.status,
        jrc.placement_status,
        jrc.profile_shared_date,
        jrc.shortlist_date,
        jrc.interview_date,
        jrc.selection_date,
        jrc.offer_date,
        jrc.placement_date,
        jrc.joining_date,
        jrc.separation_date,
        jrc.offered_salary,
        jrc.final_salary,
        jrc.interview_feedback,
        jrc.rejection_reason,
        jrc.company_feedback,
        jrc.admin_notes,
        -- Get interview details
        (SELECT json_agg(json_build_object(
          'interview_id', i.interview_id,
          'round_number', i.round_number,
          'interview_type', i.interview_type,
          'scheduled_date', i.scheduled_date,
          'status', i.status,
          'result', i.result
        )) FROM interview_schedules i WHERE i.connection_id = jrc.connection_id) as interviews
      FROM job_request_connections jrc
      JOIN job_requests jr ON jrc.request_id = jr.request_id
      JOIN companies c ON jrc.company_id = c.company_id
      WHERE jrc.employee_id = $1 
      ORDER BY jrc.connection_date DESC
    `, [employeeId]);

    console.log(`📋 Found ${result.rows.length} connected jobs for employee`);
    res.json(result.rows);
  } catch (error) {
    console.error('Get admin connected jobs error:', error);
    res.json([]);
  }
});

app.get('/api/employee/dashboard-stats', authenticateToken, authorizeRole(['employee']), async (req, res) => {
  try {
    const userId = req.user.userId;

    const empResult = await pool.query('SELECT employee_id FROM employees WHERE user_id = $1', [userId]);
    
    if (empResult.rows.length === 0) {
      return res.status(404).json({ error: 'Employee profile not found' });
    }

    const employeeId = empResult.rows[0].employee_id;

    const [
      totalConnections,
      activeConnections,
      interviews,
      placements,
      rejections
    ] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM job_request_connections WHERE employee_id = $1', [employeeId]),
      pool.query('SELECT COUNT(*) FROM job_request_connections WHERE employee_id = $1 AND status = $2', [employeeId, 'active']),
      pool.query('SELECT COUNT(*) FROM job_request_connections WHERE employee_id = $1 AND placement_status IN ($2, $3)', [employeeId, 'interview_scheduled', 'interview_completed']),
      pool.query('SELECT COUNT(*) FROM job_request_connections WHERE employee_id = $1 AND placement_status = $2', [employeeId, 'placed']),
      pool.query('SELECT COUNT(*) FROM job_request_connections WHERE employee_id = $1 AND placement_status = $2', [employeeId, 'rejected'])
    ]);

    const stats = {
      totalConnections: parseInt(totalConnections.rows[0].count),
      activeConnections: parseInt(activeConnections.rows[0].count),
      interviews: parseInt(interviews.rows[0].count),
      placements: parseInt(placements.rows[0].count),
      rejections: parseInt(rejections.rows[0].count)
    };

    res.json(stats);
  } catch (error) {
    console.error('Employee dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
  }
});

// ============================
// COMPANY DASHBOARD ROUTES
// ============================

app.get('/api/company/dashboard-stats', authenticateToken, authorizeRole(['company']), async (req, res) => {
  try {
    const userId = req.user.userId;

    const companyResult = await pool.query('SELECT company_id FROM companies WHERE user_id = $1', [userId]);
    
    if (companyResult.rows.length === 0) {
      return res.status(404).json({ error: 'Company profile not found' });
    }

    const companyId = companyResult.rows[0].company_id;

    const [
      totalJobs,
      activeJobs,
      totalConnections,
      successfulPlacements,
      pendingInterviews
    ] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM job_requests WHERE company_id = $1', [companyId]),
      pool.query('SELECT COUNT(*) FROM job_requests WHERE company_id = $1 AND status IN ($2, $3)', [companyId, 'open', 'active']),
      pool.query('SELECT COUNT(*) FROM job_request_connections WHERE company_id = $1', [companyId]),
      pool.query('SELECT COUNT(*) FROM job_request_connections WHERE company_id = $1 AND placement_status = $2', [companyId, 'placed']),
      pool.query('SELECT COUNT(*) FROM job_request_connections WHERE company_id = $1 AND placement_status IN ($2, $3)', [companyId, 'interview_scheduled', 'interview_completed'])
    ]);

    const stats = {
      totalJobs: parseInt(totalJobs.rows[0].count),
      activeJobs: parseInt(activeJobs.rows[0].count),
      totalConnections: parseInt(totalConnections.rows[0].count),
      successfulPlacements: parseInt(successfulPlacements.rows[0].count),
      pendingInterviews: parseInt(pendingInterviews.rows[0].count)
    };

    res.json(stats);
  } catch (error) {
    console.error('Company dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
  }
});

// ============================
// PROFILE UPDATE ROUTES
// ============================

app.put('/api/employee/profile', authenticateToken, authorizeRole(['employee']), async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const userId = req.user.userId;
    const { 
      full_name, phone, qualification, industry, preferred_location, 
      preferred_salary, experience_years, resume_url, linkedin_url, 
      portfolio_url, date_of_birth, address, emergency_contact, 
      emergency_contact_name, skills 
    } = req.body;

    if (!full_name || !phone) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Full name and phone are required' });
    }

    // Update employee details
    const result = await client.query(`
      UPDATE employees 
      SET full_name = $1, phone = $2, qualification = $3, 
          industry = $4, preferred_location = $5, preferred_salary = $6,
          experience_years = $7, resume_url = $8, linkedin_url = $9,
          portfolio_url = $10, date_of_birth = $11, address = $12,
          emergency_contact = $13, emergency_contact_name = $14,
          updated_at = CURRENT_TIMESTAMP
      WHERE user_id = $15
      RETURNING employee_id, full_name, phone, qualification, industry, 
              preferred_location, preferred_salary, experience_years
    `, [full_name, phone, qualification, industry, preferred_location, 
        preferred_salary, experience_years || 0, resume_url, linkedin_url,
        portfolio_url, date_of_birth, address, emergency_contact, 
        emergency_contact_name, userId]);

    if (result.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Employee profile not found' });
    }

    const employeeId = result.rows[0].employee_id;

    // Update skills if provided
    if (skills && Array.isArray(skills)) {
      // Clear existing skills
      await client.query('DELETE FROM employee_skills WHERE employee_id = $1', [employeeId]);
      
      // Add new skills
      for (const skill of skills) {
        if (skill.name && skill.name.trim()) {
          // Insert or get skill
          const skillResult = await client.query(`
            INSERT INTO skills (name, category) VALUES ($1, $2) 
            ON CONFLICT (name) DO NOTHING 
            RETURNING skill_id
          `, [skill.name.trim(), skill.category || 'General']);
          
          let skillId;
          if (skillResult.rows.length > 0) {
            skillId = skillResult.rows[0].skill_id;
          } else {
            const existingSkill = await client.query('SELECT skill_id FROM skills WHERE name = $1', [skill.name.trim()]);
            if (existingSkill.rows.length > 0) {
              skillId = existingSkill.rows[0].skill_id;
            }
          }
          
          if (skillId) {
            await client.query(`
              INSERT INTO employee_skills (employee_id, skill_id, proficiency_level, years_of_experience)
              VALUES ($1, $2, $3, $4)
            `, [employeeId, skillId, skill.proficiency_level || 'intermediate', skill.years_of_experience || 0]);
          }
        }
      }
    }

    await client.query('COMMIT');

    console.log('✅ Employee profile updated successfully');
    res.json({
      message: 'Profile updated successfully',
      ...result.rows[0]
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  } finally {
    client.release();
  }
});

app.put('/api/company/profile', authenticateToken, authorizeRole(['company']), async (req, res) => {
  try {
    const userId = req.user.userId;
    const {
      name, contact_person_name, contact_person_phone, industry, 
      location, company_size, website_url, about_us, logo_url, established_year
    } = req.body;

    const sanitizedData = {
      name: sanitizeInput(name),
      contact_person_name: sanitizeInput(contact_person_name),
      contact_person_phone: sanitizeInput(contact_person_phone),
      industry: sanitizeInput(industry),
      location: sanitizeInput(location),
      company_size: sanitizeInput(company_size),
      website_url: sanitizeInput(website_url),
      about_us: sanitizeInput(about_us),
      logo_url: sanitizeInput(logo_url)
    };

    if (!sanitizedData.name || !sanitizedData.contact_person_name || !sanitizedData.contact_person_phone) {
      return res.status(400).json({ error: 'Company name, contact person, and phone are required' });
    }

    const result = await pool.query(`
      UPDATE companies 
      SET name = $1, companyname = $1, contact_person_name = $2, contact_person_phone = $3,
          industry = $4, location = $5, company_size = $6, website_url = $7, 
          about_us = $8, logo_url = $9, established_year = $10,
          updated_at = CURRENT_TIMESTAMP
      WHERE user_id = $11
      RETURNING *
    `, [sanitizedData.name, sanitizedData.contact_person_name, sanitizedData.contact_person_phone,
        sanitizedData.industry, sanitizedData.location, sanitizedData.company_size, 
        sanitizedData.website_url, sanitizedData.about_us, sanitizedData.logo_url, 
        established_year, userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Company profile not found' });
    }

    console.log(`✅ Company profile updated: ${sanitizedData.name}`);
    res.json({
      message: 'Profile updated successfully',
      ...result.rows[0]
    });

  } catch (error) {
    console.error('Update company profile error:', error);
    res.status(500).json({ error: 'Failed to update company profile' });
  }
});

// ============================
// NOTIFICATION ROUTES
// ============================

app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { page = 1, limit = 20, unread_only = false } = req.query;
    const offset = (page - 1) * limit;

    let query = `
      SELECT * FROM notifications 
      WHERE user_id = $1
    `;
    const queryParams = [userId];

    if (unread_only === 'true') {
      query += ` AND is_read = false`;
    }

    query += ` ORDER BY created_at DESC LIMIT $2 OFFSET $3`;
    queryParams.push(limit, offset);

    const result = await pool.query(query, queryParams);

    res.json(result.rows);
  } catch (error) {
    console.error('Get notifications error:', error);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

app.put('/api/notifications/:notificationId/read', validateRouteParams, authenticateToken, async (req, res) => {
  try {
    const { notificationId } = req.params;
    const userId = req.user.userId;

    const result = await pool.query(`
      UPDATE notifications 
      SET is_read = true, read_at = CURRENT_TIMESTAMP 
      WHERE notification_id = $1 AND user_id = $2
      RETURNING *
    `, [notificationId, userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Mark notification read error:', error);
    res.status(500).json({ error: 'Failed to mark notification as read' });
  }
});

// ============================
// SKILLS ROUTES
// ============================

app.get('/api/skills', async (req, res) => {
  try {
    const { category, search } = req.query;
    
    let query = 'SELECT * FROM skills WHERE is_active = true';
    const queryParams = [];
    
    if (category) {
      query += ` AND category = $${queryParams.length + 1}`;
      queryParams.push(category);
    }
    
    if (search) {
      query += ` AND name ILIKE $${queryParams.length + 1}`;
      queryParams.push(`%${search}%`);
    }
    
    query += ' ORDER BY name';
    
    const result = await pool.query(query, queryParams);
    res.json(result.rows);
  } catch (error) {
    console.error('Get skills error:', error);
    res.status(500).json({ error: 'Failed to fetch skills' });
  }
});

// ============================
// PASSWORD RESET ROUTES
// ============================

app.post('/auth/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !validateEmail(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    const userResult = await pool.query('SELECT user_id, email FROM users WHERE email = $1', [email.toLowerCase()]);

    if (userResult.rows.length === 0) {
      // Don't reveal if email exists or not
      return res.json({ message: 'If the email exists, a password reset link has been sent.' });
    }

    const user = userResult.rows[0];
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpiry = new Date(Date.now() + 3600000); // 1 hour

    await pool.query(`
      UPDATE users SET 
        password_reset_token = $1, 
        password_reset_expires = $2 
      WHERE user_id = $3
    `, [resetToken, resetExpiry, user.user_id]);

    const resetEmailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Password Reset Request</h2>
        <p>You have requested to reset your password for your Settlo HR account.</p>
        <p>Click the link below to reset your password (valid for 1 hour):</p>
        <div style="margin: 20px 0;">
          <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}" 
             style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
            Reset Password
          </a>
        </div>
        <p>If you didn't request this password reset, please ignore this email.</p>
        <p>Best regards,<br>Settlo HR Team</p>
      </div>
    `;

    await sendEmail(user.email, 'Password Reset Request - Settlo HR', resetEmailHtml);

    res.json({ message: 'If the email exists, a password reset link has been sent.' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to process password reset request' });
  }
});

app.post('/auth/reset-password', authLimiter, async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ error: 'Token and password are required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    const userResult = await pool.query(`
      SELECT user_id, email FROM users 
      WHERE password_reset_token = $1 AND password_reset_expires > CURRENT_TIMESTAMP
    `, [token]);

    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    const user = userResult.rows[0];
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await pool.query(`
      UPDATE users SET 
        password_hash = $1,
        password_reset_token = NULL,
        password_reset_expires = NULL,
        failed_login_attempts = 0,
        locked_until = NULL
      WHERE user_id = $2
    `, [hashedPassword, user.user_id]);

    console.log(`✅ Password reset successfully for: ${user.email}`);
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ============================
// ADMIN MANAGEMENT ROUTES
// ============================

app.get('/api/admin/dashboard-stats', authenticateToken, authorizeRole(['admin', 'super_admin']), async (req, res) => {
  try {
    console.log('📊 Fetching enhanced dashboard stats...');

    const [
      totalEmployees,
      totalCompanies,
      totalJobRequests,
      totalPlacements,
      thisMonthPlacements,
      lastMonthPlacements,
      thisMonthEmployees,
      lastMonthEmployees,
      thisMonthCompanies,
      lastMonthCompanies,
      thisMonthJobs,
      lastMonthJobs,
      avgSalaryResult,
      activeConnections,
      pendingConnections,
      topPerformingCompanies,
      placementTrends
    ] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM employees WHERE user_id IN (SELECT user_id FROM users WHERE is_active = true)'),
      pool.query('SELECT COUNT(*) FROM companies WHERE user_id IN (SELECT user_id FROM users WHERE is_active = true)'),
      pool.query('SELECT COUNT(*) FROM job_requests WHERE status IN ($1, $2)', ['open', 'active']),
      pool.query('SELECT COUNT(*) FROM job_request_connections WHERE placement_status = $1', ['placed']),
      
      // This month placements
      pool.query(`
        SELECT COUNT(*) FROM job_request_connections 
        WHERE placement_status = $1 AND placement_date >= date_trunc('month', CURRENT_DATE)
      `, ['placed']),
      
      // Last month placements
      pool.query(`
        SELECT COUNT(*) FROM job_request_connections 
        WHERE placement_status = $1 
        AND placement_date >= date_trunc('month', CURRENT_DATE - interval '1 month')
        AND placement_date < date_trunc('month', CURRENT_DATE)
      `, ['placed']),
      
      // This month employees
      pool.query(`
        SELECT COUNT(*) FROM employees e
        JOIN users u ON e.user_id = u.user_id
        WHERE u.created_at >= date_trunc('month', CURRENT_DATE)
      `),
      
      // Last month employees
      pool.query(`
        SELECT COUNT(*) FROM employees e
        JOIN users u ON e.user_id = u.user_id
        WHERE u.created_at >= date_trunc('month', CURRENT_DATE - interval '1 month')
        AND u.created_at < date_trunc('month', CURRENT_DATE)
      `),
      
      // This month companies
      pool.query(`
        SELECT COUNT(*) FROM companies c
        JOIN users u ON c.user_id = u.user_id
        WHERE u.created_at >= date_trunc('month', CURRENT_DATE)
      `),
      
      // Last month companies
      pool.query(`
        SELECT COUNT(*) FROM companies c
        JOIN users u ON c.user_id = u.user_id
        WHERE u.created_at >= date_trunc('month', CURRENT_DATE - interval '1 month')
        AND u.created_at < date_trunc('month', CURRENT_DATE)
      `),
      
      // This month jobs
      pool.query(`
        SELECT COUNT(*) FROM job_requests 
        WHERE created_at >= date_trunc('month', CURRENT_DATE)
      `),
      
      // Last month jobs
      pool.query(`
        SELECT COUNT(*) FROM job_requests 
        WHERE created_at >= date_trunc('month', CURRENT_DATE - interval '1 month')
        AND created_at < date_trunc('month', CURRENT_DATE)
      `),
      
      // Average salary
      pool.query(`
        SELECT AVG(
          CASE 
            WHEN jrc.final_salary IS NOT NULL THEN jrc.final_salary
            WHEN jrc.offered_salary IS NOT NULL THEN jrc.offered_salary
            WHEN jr.min_salary IS NOT NULL THEN jr.min_salary
            ELSE NULL 
          END
        ) as avg_salary
        FROM job_request_connections jrc
        JOIN job_requests jr ON jrc.request_id = jr.request_id
        WHERE jrc.placement_status = $1
      `, ['placed']),
      
      // Active connections
      pool.query('SELECT COUNT(*) FROM job_request_connections WHERE status = $1', ['active']),
      
      // Pending connections
      pool.query('SELECT COUNT(*) FROM job_request_connections WHERE placement_status = $1', ['pending']),
      
      // Top performing companies
      pool.query(`
        SELECT c.name, COUNT(jrc.connection_id) as total_placements
        FROM companies c
        JOIN job_request_connections jrc ON c.company_id = jrc.company_id
        WHERE jrc.placement_status = 'placed'
        GROUP BY c.company_id, c.name
        ORDER BY total_placements DESC
        LIMIT 5
      `),
      
      // Placement trends (last 6 months)
      pool.query(`
        SELECT 
          DATE_TRUNC('month', jrc.placement_date) as month,
          COUNT(*) as placements
        FROM job_request_connections jrc
        WHERE jrc.placement_status = 'placed'
        AND jrc.placement_date >= DATE_TRUNC('month', CURRENT_DATE - interval '6 months')
        GROUP BY DATE_TRUNC('month', jrc.placement_date)
        ORDER BY month
      `)
    ]);

    // Calculate trends
    const calculateTrend = (current, previous) => {
      if (previous === 0) return current > 0 ? 100 : 0;
      return Math.round(((current - previous) / previous) * 100);
    };

    const currentStats = {
      employees: parseInt(thisMonthEmployees.rows[0].count),
      companies: parseInt(thisMonthCompanies.rows[0].count),
      jobs: parseInt(thisMonthJobs.rows[0].count),
      placements: parseInt(thisMonthPlacements.rows[0].count)
    };

    const previousStats = {
      employees: parseInt(lastMonthEmployees.rows[0].count),
      companies: parseInt(lastMonthCompanies.rows[0].count),
      jobs: parseInt(lastMonthJobs.rows[0].count),
      placements: parseInt(lastMonthPlacements.rows[0].count)
    };

    const stats = {
      totalEmployees: parseInt(totalEmployees.rows[0].count),
      totalCompanies: parseInt(totalCompanies.rows[0].count),
      totalJobRequests: parseInt(totalJobRequests.rows[0].count),
      totalPlacements: parseInt(totalPlacements.rows[0].count),
      activeConnections: parseInt(activeConnections.rows[0].count),
      pendingConnections: parseInt(pendingConnections.rows[0].count),
      
      // Monthly stats
      thisMonthPlacements: currentStats.placements,
      lastMonthPlacements: previousStats.placements,
      
      // Trends
      employeeTrend: calculateTrend(currentStats.employees, previousStats.employees),
      companyTrend: calculateTrend(currentStats.companies, previousStats.companies),
      jobTrend: calculateTrend(currentStats.jobs, previousStats.jobs),
      placementTrend: calculateTrend(currentStats.placements, previousStats.placements),
      
      averageSalary: Math.round(parseFloat(avgSalaryResult.rows[0].avg_salary) || 0),
      topPerformingCompanies: topPerformingCompanies.rows,
      placementTrends: placementTrends.rows.map(row => ({
        month: row.month,
        placements: parseInt(row.placements)
      }))
    };

    console.log('✅ Enhanced dashboard stats fetched:', stats);
    res.json(stats);
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
  }
});

app.get('/api/admin/employees', authenticateToken, authorizeRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { page = 1, limit = 50, search, status, industry } = req.query;
    const offset = (page - 1) * limit;
    
    let query = `
      SELECT 
        e.*,
        u.email,
        u.is_active,
        u.created_at as user_created_at,
        u.last_login,
        COALESCE(
          json_agg(
            json_build_object(
              'skill_name', s.name,
              'proficiency', es.proficiency_level,
              'experience_years', es.years_of_experience
            )
          ) FILTER (WHERE s.name IS NOT NULL), 
          '[]'::json
        ) as skills,
        -- Latest connection info
        latest_conn.placement_status as latest_placement_status,
        latest_conn.company_name as latest_company,
        latest_conn.job_title as latest_job_title,
        latest_conn.connection_date as latest_connection_date,
        latest_conn.placement_date as latest_placement_date,
        -- Statistics
        (SELECT COUNT(*) FROM job_request_connections jrc WHERE jrc.employee_id = e.employee_id) as total_connections,
        (SELECT COUNT(*) FROM job_request_connections jrc WHERE jrc.employee_id = e.employee_id AND jrc.placement_status = 'placed') as total_placements,
        (SELECT COUNT(*) FROM job_request_connections jrc WHERE jrc.employee_id = e.employee_id AND jrc.placement_status = 'rejected') as total_rejections
      FROM employees e 
      JOIN users u ON e.user_id = u.user_id 
      LEFT JOIN employee_skills es ON e.employee_id = es.employee_id
      LEFT JOIN skills s ON es.skill_id = s.skill_id
      LEFT JOIN LATERAL (
        SELECT 
          jrc.placement_status,
          jrc.connection_date,
          jrc.placement_date,
          c.name as company_name,
          jr.title as job_title
        FROM job_request_connections jrc
        JOIN job_requests jr ON jrc.request_id = jr.request_id
        JOIN companies c ON jrc.company_id = c.company_id
        WHERE jrc.employee_id = e.employee_id
        ORDER BY jrc.connection_date DESC
        LIMIT 1
      ) latest_conn ON true
    `;
    
    const queryParams = [];
    const conditions = [];
    
    if (search) {
      conditions.push(`(e.full_name ILIKE $${queryParams.length + 1} OR u.email ILIKE $${queryParams.length + 1})`);
      queryParams.push(`%${search}%`);
    }
    
    if (status) {
      conditions.push(`e.current_status = $${queryParams.length + 1}`);
      queryParams.push(status);
    }
    
    if (industry) {
      conditions.push(`e.industry = $${queryParams.length + 1}`);
      queryParams.push(industry);
    }
    
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }
    
    query += ` GROUP BY e.employee_id, u.user_id, latest_conn.placement_status, latest_conn.company_name, latest_conn.job_title, latest_conn.connection_date, latest_conn.placement_date ORDER BY e.created_at DESC LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`;
    queryParams.push(limit, offset);
    
    const result = await pool.query(query, queryParams);
    
    console.log(`📋 Fetched ${result.rows.length} employees with enhanced data`);
    res.json(result.rows);
  } catch (error) {
    console.error('Get employees error:', error);
    res.status(500).json({ error: 'Failed to fetch employees' });
  }
});
app.get('/api/admin/job-requests', authenticateToken, authorizeRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { search, status, industry, page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;
    
    let query = `
      SELECT 
        jr.*,
        c.name as company_name,
        c.industry as company_industry,
        (SELECT COUNT(*) FROM job_request_connections jrc WHERE jrc.request_id = jr.request_id) as connection_count,
        (SELECT COUNT(*) FROM job_request_connections jrc WHERE jrc.request_id = jr.request_id AND jrc.placement_status = 'placed') as placed_count
      FROM job_requests jr 
      JOIN companies c ON jr.company_id = c.company_id
    `;
    
    const queryParams = [];
    const conditions = [];
    
    if (search) {
      conditions.push(`(jr.title ILIKE $${queryParams.length + 1} OR c.name ILIKE $${queryParams.length + 1} OR jr.location ILIKE $${queryParams.length + 1})`);
      queryParams.push(`%${search}%`);
    }
    
    if (status) {
      conditions.push(`jr.status = $${queryParams.length + 1}`);
      queryParams.push(status);
    }
    
    if (industry) {
      conditions.push(`c.industry = $${queryParams.length + 1}`);
      queryParams.push(industry);
    }
    
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }
    
    query += ` ORDER BY jr.created_at DESC LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`;
    queryParams.push(limit, offset);
    
    const result = await pool.query(query, queryParams);
    res.json(result.rows);
  } catch (error) {
    console.error('Get job requests error:', error);
    res.status(500).json({ error: 'Failed to fetch job requests' });
  }
});
app.get('/api/admin/employees/:employeeId', validateRouteParams, authenticateToken, authorizeRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { employeeId } = req.params;
    
    // Get employee details
    const employeeResult = await pool.query(`
      SELECT 
        e.*,
        u.email,
        u.is_active,
        u.created_at as user_created_at,
        u.last_login,
        COALESCE(
          json_agg(
            json_build_object(
              'skill_name', s.name,
              'proficiency', es.proficiency_level,
              'experience_years', es.years_of_experience
            )
          ) FILTER (WHERE s.name IS NOT NULL), 
          '[]'::json
        ) as skills
      FROM employees e 
      JOIN users u ON e.user_id = u.user_id 
      LEFT JOIN employee_skills es ON e.employee_id = es.employee_id
      LEFT JOIN skills s ON es.skill_id = s.skill_id
      WHERE e.employee_id = $1
      GROUP BY e.employee_id, u.user_id
    `, [employeeId]);
    
    if (employeeResult.rows.length === 0) {
      return res.status(404).json({ error: 'Employee not found' });
    }
    
    // Get connection history
    const connectionsResult = await pool.query(`
      SELECT 
        jrc.*,
        jr.title as job_title,
        jr.description as job_description,
        jr.salary_range,
        c.name as company_name,
        c.industry as company_industry,
        c.location as company_location,
        -- Interview details
        (SELECT json_agg(json_build_object(
          'interview_id', i.interview_id,
          'round_number', i.round_number,
          'interview_type', i.interview_type,
          'scheduled_date', i.scheduled_date,
          'status', i.status,
          'result', i.result,
          'feedback', i.feedback,
          'rating', i.rating
        )) FROM interview_schedules i WHERE i.connection_id = jrc.connection_id) as interviews
      FROM job_request_connections jrc
      JOIN job_requests jr ON jrc.request_id = jr.request_id
      JOIN companies c ON jrc.company_id = c.company_id
      WHERE jrc.employee_id = $1
      ORDER BY jrc.connection_date DESC
    `, [employeeId]);
    
    // Get placement history
    const placementsResult = await pool.query(`
      SELECT 
        ph.*,
        c.name as company_name
      FROM placement_history ph
      JOIN companies c ON ph.company_id = c.company_id
      WHERE ph.employee_id = $1
      ORDER BY ph.start_date DESC
    `, [employeeId]);
    
    // Get performance reviews
    const performanceResult = await pool.query(`
      SELECT 
        ep.*,
        c.name as company_name
      FROM employee_performance ep
      JOIN job_request_connections jrc ON ep.connection_id = jrc.connection_id
      JOIN companies c ON jrc.company_id = c.company_id
      WHERE ep.employee_id = $1
      ORDER BY ep.review_date DESC
    `, [employeeId]);
    
    const employeeDetails = {
      ...employeeResult.rows[0],
      connections: connectionsResult.rows,
      placements: placementsResult.rows,
      performance: performanceResult.rows,
      statistics: {
        totalConnections: connectionsResult.rows.length,
        totalPlacements: connectionsResult.rows.filter(c => c.placement_status === 'placed').length,
        totalRejections: connectionsResult.rows.filter(c => c.placement_status === 'rejected').length,
        successRate: connectionsResult.rows.length > 0 ? 
          Math.round((connectionsResult.rows.filter(c => c.placement_status === 'placed').length / connectionsResult.rows.length) * 100) : 0
      }
    };
    
    res.json(employeeDetails);
  } catch (error) {
    console.error('Get employee details error:', error);
    res.status(500).json({ error: 'Failed to fetch employee details' });
  }
});

app.get('/api/admin/companies', authenticateToken, authorizeRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { page = 1, limit = 50, search, industry, verified } = req.query;
    const offset = (page - 1) * limit;
    
    let query = `
      SELECT 
        c.*,
        u.email,
        u.is_active,
        u.created_at as user_created_at,
        u.last_login,
        (SELECT COUNT(*) FROM job_requests jr WHERE jr.company_id = c.company_id) as total_jobs,
        (SELECT COUNT(*) FROM job_requests jr WHERE jr.company_id = c.company_id AND jr.status IN ('open', 'active')) as active_jobs,
        (SELECT COUNT(*) FROM job_request_connections jrc WHERE jrc.company_id = c.company_id) as total_connections,
        (SELECT COUNT(*) FROM job_request_connections jrc WHERE jrc.company_id = c.company_id AND jrc.placement_status = 'placed') as successful_placements,
        (SELECT AVG(jrc.final_salary) FROM job_request_connections jrc WHERE jrc.company_id = c.company_id AND jrc.placement_status = 'placed') as avg_salary_offered
      FROM companies c 
      JOIN users u ON c.user_id = u.user_id
    `;
    
    const queryParams = [];
    const conditions = [];
    
    if (search) {
      conditions.push(`(c.name ILIKE $${queryParams.length + 1} OR u.email ILIKE $${queryParams.length + 1})`);
      queryParams.push(`%${search}%`);
    }
    
    if (industry) {
      conditions.push(`c.industry = $${queryParams.length + 1}`);
      queryParams.push(industry);
    }
    
    if (verified !== undefined) {
      conditions.push(`c.verified = $${queryParams.length + 1}`);
      queryParams.push(verified === 'true');
    }
    
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }
    
    query += ` ORDER BY c.created_at DESC LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`;
    queryParams.push(limit, offset);
    
    const result = await pool.query(query, queryParams);
    
    console.log(`🏢 Fetched ${result.rows.length} companies with enhanced data`);
    res.json(result.rows);
  } catch (error) {
    console.error('Get companies error:', error);
    res.status(500).json({ error: 'Failed to fetch companies' });
  }
});

app.get('/api/admin/companies/:companyId', validateRouteParams, authenticateToken, authorizeRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { companyId } = req.params;
    
    // Get company details
    const companyResult = await pool.query(`
      SELECT 
        c.*,
        u.email,
        u.is_active,
        u.created_at as user_created_at,
        u.last_login
      FROM companies c 
      JOIN users u ON c.user_id = u.user_id
      WHERE c.company_id = $1
    `, [companyId]);
    
    if (companyResult.rows.length === 0) {
      return res.status(404).json({ error: 'Company not found' });
    }
    
    // Get job requests
    const jobsResult = await pool.query(`
      SELECT 
        jr.*,
        (SELECT COUNT(*) FROM job_request_connections jrc WHERE jrc.request_id = jr.request_id) as total_connections,
        (SELECT COUNT(*) FROM job_request_connections jrc WHERE jrc.request_id = jr.request_id AND jrc.placement_status = 'placed') as successful_placements,
        (SELECT json_agg(json_build_object('name', s.name, 'importance', jrs.importance_level)) 
         FROM job_required_skills jrs 
         JOIN skills s ON jrs.skill_id = s.skill_id 
         WHERE jrs.request_id = jr.request_id) as required_skills
      FROM job_requests jr
      WHERE jr.company_id = $1
      ORDER BY jr.created_at DESC
    `, [companyId]);
    
    // Get all connections
    const connectionsResult = await pool.query(`
      SELECT 
        jrc.*,
        e.full_name as employee_name,
        e.phone as employee_phone,
        u.email as employee_email,
        jr.title as job_title
      FROM job_request_connections jrc
      JOIN employees e ON jrc.employee_id = e.employee_id
      JOIN users u ON e.user_id = u.user_id
      JOIN job_requests jr ON jrc.request_id = jr.request_id
      WHERE jrc.company_id = $1
      ORDER BY jrc.connection_date DESC
    `, [companyId]);
    
    // Get ratings and reviews
    const ratingsResult = await pool.query(`
      SELECT 
        cr.*,
        e.full_name as employee_name
      FROM company_ratings cr
      JOIN employees e ON cr.employee_id = e.employee_id
      WHERE cr.company_id = $1
      ORDER BY cr.created_at DESC
    `, [companyId]);
    
    const companyDetails = {
      ...companyResult.rows[0],
      jobs: jobsResult.rows,
      connections: connectionsResult.rows,
      ratings: ratingsResult.rows,
      statistics: {
        totalJobs: jobsResult.rows.length,
        activeJobs: jobsResult.rows.filter(j => ['open', 'active'].includes(j.status)).length,
        totalConnections: connectionsResult.rows.length,
        successfulPlacements: connectionsResult.rows.filter(c => c.placement_status === 'placed').length,
        successRate: connectionsResult.rows.length > 0 ? 
          Math.round((connectionsResult.rows.filter(c => c.placement_status === 'placed').length / connectionsResult.rows.length) * 100) : 0,
        averageRating: ratingsResult.rows.length > 0 ?
          Math.round((ratingsResult.rows.reduce((sum, r) => sum + r.rating, 0) / ratingsResult.rows.length) * 10) / 10 : 0
      }
    };
    
    res.json(companyDetails);
  } catch (error) {
    console.error('Get company details error:', error);
    res.status(500).json({ error: 'Failed to fetch company details' });
  }
});

app.post('/api/admin/create-connection', authenticateToken, authorizeRole(['admin', 'super_admin']), async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { request_id, employee_id, notes, priority = 'medium', expected_salary } = req.body;
    
    console.log('🔗 Creating connection:', { request_id, employee_id });

    if (!request_id || !employee_id) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Job request ID and employee ID are required' });
    }
    
    // Verify job request exists and get details
    const jobResult = await client.query(`
      SELECT jr.*, c.name as company_name 
      FROM job_requests jr 
      JOIN companies c ON jr.company_id = c.company_id 
      WHERE jr.request_id = $1 AND jr.status IN ('open', 'active')
    `, [request_id]);
    
    if (jobResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Job request not found or not active' });
    }
    
    const jobData = jobResult.rows[0];
    
    // Check if connection already exists
    const existingConnection = await client.query(`
      SELECT connection_id FROM job_request_connections 
      WHERE request_id = $1 AND employee_id = $2
    `, [request_id, employee_id]);
    
    if (existingConnection.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Connection already exists for this employee and job' });
    }
    
    // Verify employee exists and get details
    const empResult = await client.query(`
      SELECT e.*, u.email 
      FROM employees e 
      JOIN users u ON e.user_id = u.user_id 
      WHERE e.employee_id = $1 AND u.is_active = true
    `, [employee_id]);
    
    if (empResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Employee not found or inactive' });
    }
    
    const empData = empResult.rows[0];
    
    // Create connection
    const connectionResult = await client.query(`
      INSERT INTO job_request_connections 
      (request_id, employee_id, company_id, connected_by, connected_by_user_id, 
       status, placement_status, admin_notes, connection_date)
      VALUES ($1, $2, $3, 'admin', $4, 'active', 'pending', $5, CURRENT_TIMESTAMP)
      RETURNING *
    `, [request_id, employee_id, jobData.company_id, req.user.userId, sanitizeInput(notes)]);
    
    const connectionId = connectionResult.rows[0].connection_id;
    
    // Update employee status to interviewing if they were available
    if (empData.current_status === 'available') {
      await client.query(`
        UPDATE employees SET current_status = 'interviewing', updated_at = CURRENT_TIMESTAMP 
        WHERE employee_id = $1
      `, [employee_id]);
    }
    
    // Create notification for employee
    await client.query(`
      INSERT INTO notifications (user_id, type, title, message, data, priority)
      VALUES ($1, 'connection', $2, $3, $4, $5)
    `, [
      empData.user_id,
      'New Job Opportunity',
      `You have been connected to a ${jobData.title} position at ${jobData.company_name}`,
      JSON.stringify({
        connection_id: connectionId,
        job_title: jobData.title,
        company_name: jobData.company_name,
        job_id: request_id
      }),
      'high'
    ]);
    
    await client.query('COMMIT');
    
    // Send email notification
    const connectionEmailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h3 style="color: #007bff;">🎯 New Job Opportunity!</h3>
        <p>Hello ${empData.full_name},</p>
        <p>Great news! Our admin team has connected you to an exciting job opportunity.</p>
        <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <h4 style="margin-top: 0; color: #333;">Job Details:</h4>
          <p><strong>Position:</strong> ${jobData.title}</p>
          <p><strong>Company:</strong> ${jobData.company_name}</p>
          <p><strong>Location:</strong> ${jobData.location}</p>
          <p><strong>Employment Type:</strong> ${jobData.employment_type}</p>
          <p><strong>Salary Range:</strong> ${jobData.salary_range || 'As per industry standards'}</p>
        </div>
        <div style="background-color: #d4edda; padding: 15px; border-radius: 5px; border-left: 4px solid #28a745;">
          <p><strong>Next Steps:</strong></p>
          <ul>
            <li>Log in to your dashboard to view complete job details</li>
            <li>Review the job description and requirements</li>
            <li>Update your profile if needed</li>
            <li>Wait for further updates from our team</li>
          </ul>
        </div>
        <p>We'll keep you informed about the progress of your application.</p>
        <p>Best regards,<br>Settlo HR Team</p>
      </div>
    `;
    
    await sendEmail(empData.email, 'New Job Opportunity - Action Required', connectionEmailHtml);
    
    await logAdminAction(
      req.user.userId, 
      'CREATE_CONNECTION', 
      'job_connection', 
      connectionId,
      { 
        request_id, 
        employee_id, 
        employee_name: empData.full_name,
        job_title: jobData.title, 
        company_name: jobData.company_name 
      },
      req.ip
    );
    
    console.log('✅ Connection created successfully');
    res.json({
      message: 'Connection created successfully',
      connection: connectionResult.rows[0],
      employee: {
        name: empData.full_name,
        email: empData.email
      },
      job: {
        title: jobData.title,
        company: jobData.company_name
      }
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Create connection error:', error);
    
    if (error.code === '23505') {
      return res.status(400).json({ error: 'Connection already exists for this employee and job' });
    }
    
    res.status(500).json({ error: 'Failed to create connection' });
  } finally {
    client.release();
  }
});
app.get('/api/admin/connections', authenticateToken, authorizeRole(['admin', 'super_admin']), async (req, res) => {
  try {
    const { search, status, page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;
    
    let query = `
      SELECT 
        jrc.*,
        e.full_name as employee_name,
        e.phone as employee_phone,
        u_emp.email as employee_email,
        jr.title as job_title,
        jr.domain as job_domain,
        jr.location as job_location,
        c.name as company_name,
        c.industry as company_industry
      FROM job_request_connections jrc
      JOIN employees e ON jrc.employee_id = e.employee_id
      JOIN users u_emp ON e.user_id = u_emp.user_id
      JOIN job_requests jr ON jrc.request_id = jr.request_id
      JOIN companies c ON jrc.company_id = c.company_id
    `;
    
    const queryParams = [];
    const conditions = [];
    
    if (search) {
      conditions.push(`(
        e.full_name ILIKE $${queryParams.length + 1} OR
        c.name ILIKE $${queryParams.length + 1} OR
        jr.title ILIKE $${queryParams.length + 1} OR
        u_emp.email ILIKE $${queryParams.length + 1}
      )`);
      queryParams.push(`%${search}%`);
    }
    
    if (status) {
      conditions.push(`jrc.placement_status = $${queryParams.length + 1}`);
      queryParams.push(status);
    }
    
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }
    
    query += ` ORDER BY jrc.connection_date DESC LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`;
    queryParams.push(limit, offset);
    
    const result = await pool.query(query, queryParams);
    res.json(result.rows);
  } catch (error) {
    console.error('Get connections error:', error);
    res.status(500).json({ error: 'Failed to fetch connections' });
  }
});

app.put('/api/admin/connections/:connectionId/status', validateRouteParams, authenticateToken, authorizeRole(['admin', 'super_admin']), async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { connectionId } = req.params;
    const { 
      placement_status, 
      interview_date, 
      salary_offered, 
      feedback, 
      admin_notes, 
      rejection_reason,
      interview_rounds_completed,
      performance_rating 
    } = req.body;

    console.log(`📝 Updating connection status ${connectionId}:`, { placement_status });

    const sanitizedData = {
      placement_status: sanitizeInput(placement_status),
      feedback: sanitizeInput(feedback),
      admin_notes: sanitizeInput(admin_notes),
      rejection_reason: sanitizeInput(rejection_reason)
    };

    if (!sanitizedData.placement_status) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Placement status is required' });
    }

    const validStatuses = [
      'pending', 'profile_shared', 'shortlisted', 'interview_scheduled', 
      'interview_completed', 'interview_rescheduled', 'selected', 'offer_made', 
      'offer_accepted', 'offer_rejected', 'placed', 'joined', 'rejected', 
      'dropped', 'resigned', 'terminated'
    ];
    
    if (!validStatuses.includes(sanitizedData.placement_status)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Invalid placement status' });
    }

    // Get current connection details
    const currentConnection = await client.query(`
      SELECT jrc.*, e.full_name, e.employee_id, e.user_id as emp_user_id, u.email as employee_email, 
             jr.title as job_title, c.name as company_name, c.company_id
      FROM job_request_connections jrc
      JOIN employees e ON jrc.employee_id = e.employee_id
      JOIN users u ON e.user_id = u.user_id
      JOIN job_requests jr ON jrc.request_id = jr.request_id
      JOIN companies c ON jrc.company_id = c.company_id
      WHERE jrc.connection_id = $1
    `, [connectionId]);

    if (currentConnection.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Connection not found' });
    }

    const connectionData = currentConnection.rows[0];
    
    // Determine what date fields to update based on status
    let updateFields = [];
    let updateValues = [];
    let paramIndex = 1;
    
    // Base fields
    updateFields.push(`placement_status = $${paramIndex++}`);
    updateValues.push(sanitizedData.placement_status);
    
    updateFields.push(`updated_at = CURRENT_TIMESTAMP`);
    
    if (sanitizedData.admin_notes) {
      updateFields.push(`admin_notes = $${paramIndex++}`);
      updateValues.push(sanitizedData.admin_notes);
    }
    
    if (sanitizedData.feedback) {
      updateFields.push(`interview_feedback = $${paramIndex++}`);
      updateValues.push(sanitizedData.feedback);
    }
    
    if (sanitizedData.rejection_reason) {
      updateFields.push(`rejection_reason = $${paramIndex++}`);
      updateValues.push(sanitizedData.rejection_reason);
    }
    
    if (salary_offered) {
      updateFields.push(`offered_salary = $${paramIndex++}`);
      updateValues.push(parseInt(salary_offered));
    }
    
    if (interview_rounds_completed) {
      updateFields.push(`interview_rounds_completed = $${paramIndex++}`);
      updateValues.push(parseInt(interview_rounds_completed));
    }
    
    if (performance_rating) {
      updateFields.push(`performance_rating = $${paramIndex++}`);
      updateValues.push(parseFloat(performance_rating));
    }
    
    // Update specific date fields based on status
    switch (sanitizedData.placement_status) {
      case 'profile_shared':
        if (!connectionData.profile_shared_date) {
          updateFields.push(`profile_shared_date = CURRENT_TIMESTAMP`);
        }
        break;
      case 'shortlisted':
        if (!connectionData.shortlist_date) {
          updateFields.push(`shortlist_date = CURRENT_TIMESTAMP`);
        }
        break;
      case 'interview_scheduled':
        if (interview_date) {
          updateFields.push(`interview_date = $${paramIndex++}`);
          updateValues.push(interview_date);
        }
        break;
      case 'selected':
        if (!connectionData.selection_date) {
          updateFields.push(`selection_date = CURRENT_TIMESTAMP`);
        }
        break;
      case 'offer_made':
        if (!connectionData.offer_date) {
          updateFields.push(`offer_date = CURRENT_TIMESTAMP`);
        }
        break;
      case 'placed':
        if (!connectionData.placement_date) {
          updateFields.push(`placement_date = CURRENT_TIMESTAMP`);
        }
        if (salary_offered) {
          updateFields.push(`final_salary = $${paramIndex++}`);
          updateValues.push(parseInt(salary_offered));
        }
        break;
      case 'joined':
        if (!connectionData.joining_date) {
          updateFields.push(`joining_date = CURRENT_TIMESTAMP`);
        }
        break;
    }
    
    // Update connection
    const updateQuery = `
      UPDATE job_request_connections 
      SET ${updateFields.join(', ')}
      WHERE connection_id = $${paramIndex}
      RETURNING *
    `;
    updateValues.push(connectionId);
    
    const result = await client.query(updateQuery, updateValues);
    
    // Update employee status based on placement status
    let newEmployeeStatus = connectionData.current_status;
    switch (sanitizedData.placement_status) {
      case 'interview_scheduled':
        newEmployeeStatus = 'interviewing';
        break;
      case 'placed':
      case 'joined':
        newEmployeeStatus = 'placed';
        break;
      case 'rejected':
      case 'dropped':
        newEmployeeStatus = 'available';
        break;
    }
    
    if (newEmployeeStatus !== connectionData.current_status) {
      await client.query(`
        UPDATE employees SET current_status = $1, updated_at = CURRENT_TIMESTAMP 
        WHERE employee_id = $2
      `, [newEmployeeStatus, connectionData.employee_id]);
    }
    
    // Create notification for employee
    const statusMessages = {
      'profile_shared': 'Your profile has been shared with the company',
      'shortlisted': 'Congratulations! You have been shortlisted',
      'interview_scheduled': 'Interview has been scheduled',
      'interview_completed': 'Interview completed successfully',
      'selected': 'Great news! You have been selected',
      'offer_made': 'Job offer has been made',
      'offer_accepted': 'Offer accepted successfully',
      'placed': 'Congratulations! You have been placed',
      'joined': 'Welcome to your new role!',
      'rejected': 'Application was not successful this time',
      'dropped': 'Application has been withdrawn'
    };
    
    const notificationTitle = statusMessages[sanitizedData.placement_status] || 'Status Update';
    
    await client.query(`
      INSERT INTO notifications (user_id, type, title, message, data, priority)
      VALUES ($1, 'status_update', $2, $3, $4, $5)
    `, [
      connectionData.emp_user_id,
      notificationTitle,
      `Status update for ${connectionData.job_title} at ${connectionData.company_name}: ${sanitizedData.placement_status}`,
      JSON.stringify({
        connection_id: connectionId,
        job_title: connectionData.job_title,
        company_name: connectionData.company_name,
        new_status: sanitizedData.placement_status
      }),
      ['selected', 'offer_made', 'placed', 'joined'].includes(sanitizedData.placement_status) ? 'high' : 'normal'
    ]);
    
    await client.query('COMMIT');
    
    // Send email notification
    const emailSubject = `Status Update: ${connectionData.job_title} at ${connectionData.company_name}`;
    const emailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h3 style="color: #007bff;">📄 Application Status Update</h3>
        <p>Hello ${connectionData.full_name},</p>
        <p>We have an update regarding your application for <strong>${connectionData.job_title}</strong> at <strong>${connectionData.company_name}</strong>.</p>
        <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <p><strong>New Status:</strong> ${notificationTitle}</p>
          ${sanitizedData.feedback ? `<p><strong>Feedback:</strong> ${sanitizedData.feedback}</p>` : ''}
          ${salary_offered ? `<p><strong>Salary Offered:</strong> ₹${salary_offered}</p>` : ''}
        </div>
        <p>Please log in to your dashboard for more details.</p>
        <p>Best regards,<br>Settlo HR Team</p>
      </div>
    `;
    
    await sendEmail(connectionData.employee_email, emailSubject, emailHtml);
    
    await logAdminAction(
      req.user.userId,
      'UPDATE_CONNECTION_STATUS',
      'job_connection',
      parseInt(connectionId),
      {
        old_status: connectionData.placement_status,
        new_status: sanitizedData.placement_status,
        employee_name: connectionData.full_name,
        job_title: connectionData.job_title,
        company_name: connectionData.company_name
      },
      req.ip
    );
    
    console.log(`✅ Connection status updated successfully: ${sanitizedData.placement_status}`);
    res.json({
      message: 'Connection status updated successfully',
      connection: result.rows[0],
      employee: {
        name: connectionData.full_name,
        email: connectionData.employee_email
      }
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Update connection status error:', error);
    res.status(500).json({ error: 'Failed to update connection status' });
  } finally {
    client.release();
  }
});
// PUT /api/companies/:companyId - Update company profile (email non-editable, phone without +91)
// PUT /api/companies/:companyId - Update company profile (CORRECTED)
// PUT /api/companies/:companyId - Update company profile (PostgreSQL)
app.put('/api/companies/:companyId', authenticateToken, async (req, res) => {
  try {
    const { companyId } = req.params;
    const { 
      name, contact_person_phone, industry, location, 
      contact_person_name, company_size, website_url, about_us 
    } = req.body;

    // Validate that the company belongs to the user
    if (req.user.company_id && req.user.company_id !== parseInt(companyId)) {
      return res.status(403).json({ error: 'Unauthorized to update this company' });
    }

    // Validate required fields
    if (!name || !contact_person_name || !contact_person_phone) {
      return res.status(400).json({ error: 'Company name, contact person, and phone are required' });
    }

    // Validate phone number (10 digits only, no +91)
    if (!/^[0-9]{10}$/.test(contact_person_phone)) {
      return res.status(400).json({ error: 'Phone number must be exactly 10 digits' });
    }

    // Update company profile using PostgreSQL syntax
    const updateQuery = `
      UPDATE companies SET 
        companyname = $1, 
        contact_person_name = $2, 
        contact_person_phone = $3, 
        industry = $4, 
        location = $5, 
        company_size = $6, 
        website_url = $7, 
        about_us = $8, 
        updated_at = NOW()
      WHERE company_id = $9
      RETURNING *
    `;

    const updateValues = [
      name, 
      contact_person_name, 
      contact_person_phone, 
      industry || null, 
      location || null, 
      company_size || null, 
      website_url || null, 
      about_us || null, 
      parseInt(companyId)
    ];

    const result = await pool.query(updateQuery, updateValues);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Company not found' });
    }

    console.log(`✅ Company profile updated: ${name} (ID: ${companyId})`);
    res.json({
      message: 'Profile updated successfully',
      ...result.rows[0]
    });

  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Failed to update company profile' });
  }
});


// PUT /jobs/requests/:requestId - Update job request (status only for existing jobs)
app.put('/jobs/requests/:requestId', authenticateToken, async (req, res) => {
  try {
    const { requestId } = req.params;
    const { status } = req.body;
    
    // Validate that the job belongs to the company
    let companyId;
    if (req.user.role === 'company') {
      const companyResult = await pool.query(
        'SELECT company_id FROM companies WHERE user_id = $1',
        [req.user.userId]
      );
      
      if (companyResult.rows.length === 0) {
        return res.status(404).json({ error: 'Company profile not found' });
      }
      companyId = companyResult.rows[0].company_id;
    }

    // Verify job ownership
    const jobCheck = await pool.query(
      'SELECT * FROM job_requests WHERE request_id = $1' + 
      (req.user.role === 'company' ? ' AND company_id = $2' : ''),
      req.user.role === 'company' ? [requestId, companyId] : [requestId]
    );

    if (jobCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Job request not found or access denied' });
    }

    // Validate status
    const allowedStatuses = ['open', 'closed', 'pending', 'active'];
    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({ 
        error: `Invalid status. Allowed values: ${allowedStatuses.join(', ')}` 
      });
    }

    // Update only the status
    const result = await pool.query(`
      UPDATE job_requests 
      SET status = $1, updated_at = NOW() 
      WHERE request_id = $2
      RETURNING *
    `, [status, requestId]);

    console.log(`✅ Job request status updated: ${requestId} -> ${status}`);
    res.json({
      message: 'Job status updated successfully',
      ...result.rows[0]
    });

  } catch (error) {
    console.error('Job status update error:', error);
    res.status(500).json({ error: 'Failed to update job status' });
  }
});
app.delete('/api/admin/employees/:id', authenticateToken, authorizeRole(['admin', 'super_admin']), async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    
    // Get employee details before deletion
    const empResult = await client.query('SELECT user_id, full_name FROM employees WHERE employee_id = $1', [id]);
    if (empResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Employee not found' });
    }
    
    const employee = empResult.rows[0];
    
    // Delete employee (CASCADE will handle related records)
    await client.query('DELETE FROM employees WHERE employee_id = $1', [id]);
    
    // Delete user account
    await client.query('DELETE FROM users WHERE user_id = $1', [employee.user_id]);
    
    await client.query('COMMIT');
    
    res.json({ message: 'Employee deleted successfully' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Delete employee error:', error);
    res.status(500).json({ error: 'Failed to delete employee' });
  } finally {
    client.release();
  }
});

// DELETE /api/admin/companies/:id
app.delete('/api/admin/companies/:id', authenticateToken, authorizeRole(['admin', 'super_admin']), async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const { id } = req.params;
    
    // Get company details before deletion
    const compResult = await client.query('SELECT user_id, name FROM companies WHERE company_id = $1', [id]);
    if (compResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Company not found' });
    }
    
    const company = compResult.rows[0];
    
    // Delete company (CASCADE will handle related records)
    await client.query('DELETE FROM companies WHERE company_id = $1', [id]);
    
    // Delete user account
    await client.query('DELETE FROM users WHERE user_id = $1', [company.user_id]);
    
    await client.query('COMMIT');
    
    res.json({ message: 'Company deleted successfully' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Delete company error:', error);
    res.status(500).json({ error: 'Failed to delete company' });
  } finally {
    client.release();
  }
});


// ============================
// HEALTH CHECK AND ERROR HANDLING
// ============================

app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { details: err.message })
  });
});

app.use('/*catchall', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Remove endpoints with no frontend usage or that are unused
// Keep necessary global error handling and graceful shutdown

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  pool.end(() => {
    console.log('Database pool closed'); 
    process.exit(0);
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health check: http://localhost:${PORT}/health`);
});
