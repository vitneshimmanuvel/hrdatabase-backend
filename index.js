import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { Pool } from 'pg';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

dotenv.config();

if (!process.env.DATABASE_URL) {
  console.error('Missing DATABASE_URL in .env');
  process.exit(1);
}
if (!process.env.JWT_SECRET) {
  console.error('Missing JWT_SECRET in .env');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.connect()
  .then(client => {
    console.log('Connected to PostgreSQL database');
    client.release();
  })
  .catch(err => {
    console.error('Unable to connect to PostgreSQL', err);
    process.exit(1);
  });

pool.on('error', err => {
  console.error('Unexpected PG pool error', err);
  process.exit(-1);
});

const app = express();
app.use(cors());
app.use(express.json());

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization || '';
  const [scheme, token] = authHeader.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = payload;
    next();
  });
};

// Registration route
app.post('/auth/register', async (req, res) => {
  const { role, email, password, confirmPassword, ...rest } = req.body;
  
  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }

  try {
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rowCount > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const passwordHash = await bcrypt.hash(password, 12);
      const userResult = await client.query(
        'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING user_id',
        [email, passwordHash, role]
      );
      const userId = userResult.rows[0].user_id;

      if (role === 'employee') {
        const {
          name,
          mobile,
          qualification,
          industry,
          emplocation,
          empsalary,
          skills
        } = rest;

        const empResult = await client.query(
          'INSERT INTO employees (user_id, full_name, phone, qualification, industry, preferred_location, preferred_salary) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING employee_id',
          [userId, name, mobile, qualification, industry, emplocation, empsalary]
        );
        const employeeId = empResult.rows[0].employee_id;

        const skillList = skills.split(',').map(s => s.trim()).filter(Boolean);
        for (const skill of skillList) {
          const skillRes = await client.query(
            'INSERT INTO skills (name) VALUES ($1) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING skill_id',
            [skill]
          );
          const skillId = skillRes.rows[0].skill_id;
          await client.query(
            'INSERT INTO employee_skills (employee_id, skill_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [employeeId, skillId]
          );
        }
      } else if (role === 'company') {
        const {
          companyName,
          mobile,
          industry,
          location,
          contactPersonName
        } = rest;

        await client.query(
          'INSERT INTO companies (user_id, name, contact_person_phone, contact_email, industry, location, contact_person_name) VALUES ($1, $2, $3, $4, $5, $6, $7)',
          [userId, companyName, mobile, email, industry, location, contactPersonName]
        );
      }

      await client.query('COMMIT');
      res.status(201).json({ message: 'Registration successful' });
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Registration failed' });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Request error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login route
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const userRes = await pool.query(
      'SELECT user_id, password_hash, role FROM users WHERE email = $1',
      [email]
    );
    if (userRes.rowCount === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { user_id, password_hash, role } = userRes.rows[0];
    const isValid = await bcrypt.compare(password, password_hash);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user_id, role }, process.env.JWT_SECRET, { expiresIn: '8h' });
    console.log(`User ${user_id} logged in`);
    res.json({ token, role });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Create new job request
app.post('/jobs/create', authenticate, async (req, res) => {
  const { userId, role } = req.user;
  const { 
    title, 
    domain, 
    description, 
    employment_type, 
    location,
    salary_range,
    count,
    interview_time
  } = req.body;
  
  if (role !== 'company') {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    const companyIdResult = await pool.query(
      'SELECT company_id FROM companies WHERE user_id = $1',
      [userId]
    );

    if (companyIdResult.rowCount === 0) {
      return res.status(404).json({ error: 'Company profile not found' });
    }

    const companyId = companyIdResult.rows[0].company_id;

    const requestResult = await pool.query(
      `INSERT INTO job_requests 
      (company_id, title, domain, description, employment_type, 
      location, salary_range, count, interview_time, status) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'open') 
      RETURNING *`,
      [
        companyId,
        title,
        domain,
        description,
        employment_type,
        location,
        salary_range,
        count,
        interview_time
      ]
    );

    res.status(201).json(requestResult.rows[0]);
  } catch (error) {
    console.error('Job creation error:', error);
    res.status(500).json({ error: 'Job creation failed' });
  }
});

// Update job request
app.put('/jobs/requests/:id', authenticate, async (req, res) => {
  const { userId, role } = req.user;
  const { id } = req.params;
  const { count, interview_time, status } = req.body;

  if (role !== 'company') {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    // Verify ownership
    const ownershipCheck = await pool.query(
      `SELECT j.request_id 
      FROM job_requests j
      JOIN companies c ON j.company_id = c.company_id
      WHERE j.request_id = $1 AND c.user_id = $2`,
      [id, userId]
    );

    if (ownershipCheck.rowCount === 0) {
      return res.status(404).json({ error: 'Job request not found or access denied' });
    }

    // Convert empty string to null and handle datetime format
    const interviewTimeValue = interview_time === "" ? 
      null : 
      (interview_time ? new Date(interview_time).toISOString() : null);

    const updateResult = await pool.query(
      `UPDATE job_requests 
      SET 
        count = COALESCE($1, count),
        interview_time = $2,
        status = COALESCE($3, status)
      WHERE request_id = $4
      RETURNING *`,
      [
        count ? parseInt(count, 10) : null,
        interviewTimeValue,  
        status,
        id
      ]
    );

    res.json(updateResult.rows[0]);
  } catch (error) {
    console.error('Job update error:', error);
    res.status(500).json({ 
      error: 'Job update failed',
      message: error.message
    });
  }
});

// Get job requests for a company
app.get('/jobs/requests', authenticate, async (req, res) => {
  const { userId, role } = req.user;
  if (role !== 'company') {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    const companyId = await pool.query(
      'SELECT company_id FROM companies WHERE user_id = $1',
      [userId]
    );

    if (companyId.rowCount === 0) {
      return res.status(404).json({ error: 'Company profile not found' });
    }

    const requests = await pool.query(
      `SELECT request_id, title, domain, description, employment_type, 
              location, salary_range, count, interview_time, status, created_at 
      FROM job_requests 
      WHERE company_id = $1 
      ORDER BY created_at DESC`,
      [companyId.rows[0].company_id]
    );

    res.json(requests.rows);
  } catch (error) {
    console.error('Job requests error:', error);
    res.status(500).json({ error: 'Could not fetch job requests' });
  }
});

// Profile route
app.get('/users/profile', authenticate, async (req, res) => {
  try {
    const { userId, role } = req.user;
    
    if (role === 'employee') {
      const emp = await pool.query(
        'SELECT full_name, phone, qualification, industry, preferred_location, preferred_salary FROM employees WHERE user_id = $1',
        [userId]
      );
      return res.json(emp.rows[0]);
    }
    
    if (role === 'company') {
      const comp = await pool.query(
        'SELECT name AS companyname, contact_person_phone, contact_email, industry, location, contact_person_name FROM companies WHERE user_id = $1',
        [userId]
      );
      return res.json(comp.rows[0]);
    }
    
    res.status(400).json({ error: 'Unknown role' });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Could not fetch profile' });
  }
});

// Get all employees - Admin only
app.get('/api/employees', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const result = await pool.query(`SELECT employee_id, full_name FROM employees`);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching employees:', err);
    res.status(500).json({ error: 'Could not fetch employees' });
  }
});

// Get all companies - Admin only
app.get('/api/companies', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const result = await pool.query(`SELECT company_id, name FROM companies`);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching companies:', err);
    res.status(500).json({ error: 'Could not fetch companies' });
  }
});

// Get employee details by ID - Admin only
app.get('/api/employees/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT employee_id, full_name, phone, qualification, industry, preferred_location, preferred_salary 
      FROM employees 
      WHERE employee_id = $1`, [id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Employee not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching employee details:', err);
    res.status(500).json({ error: 'Could not fetch employee details' });
  }
});

// Get company details by ID - Admin only
app.get('/api/companies/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT company_id, name, industry, location, contact_person_name, contact_person_phone, contact_email 
      FROM companies 
      WHERE company_id = $1`, [id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Company not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching company details:', err);
    res.status(500).json({ error: 'Could not fetch company details' });
  }
});

// Get job requests for a company by company ID - Company only
app.get('/api/companies/:companyId/job-requests', authenticate, async (req, res) => {
  if (req.user.role !== 'company') {
    return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const { companyId } = req.params;
    const result = await pool.query(
      `SELECT request_id, title, location, employment_type, created_at, status 
      FROM job_requests 
      WHERE company_id = $1 
      ORDER BY created_at DESC`, [companyId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching job requests:', err);
    res.status(500).json({ error: 'Could not fetch job requests' });
  }
});

// Get job requests - Employee only
app.get('/api/job-requests', authenticate, async (req, res) => {
  if (req.user.role !== 'employee') {
    return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const result = await pool.query(`
      SELECT 
        request_id AS id,
        title,
        domain,
        location,
        salary_range,
        description,
        employment_type,
        created_at,
        status
      FROM job_requests
      ORDER BY created_at DESC
    `);
    
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching job requests:', err);
    res.status(500).json({ error: 'Could not fetch job requests' });
  }
});

// Update employee profile - Employee only
app.put('/api/employee/profile', authenticate, async (req, res) => {
  if (req.user.role !== 'employee') {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { userId } = req.user;
  const { full_name, phone, qualification, industry, preferred_location, preferred_salary } = req.body;

  try {
    const updateQuery = `
      UPDATE employees
      SET 
        full_name = $1,
        phone = $2,
        qualification = $3,
        industry = $4,
        preferred_location = $5,
        preferred_salary = $6
      WHERE user_id = $7
      RETURNING *;
    `;

    const values = [
      full_name,
      phone,
      qualification,
      industry,
      preferred_location,
      preferred_salary,
      userId
    ];

    const result = await pool.query(updateQuery, values);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Employee not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get connections for a job request - Company only
app.get('/api/job-requests/:request_id/connections', authenticate, async (req, res) => {
  if (req.user.role !== 'company') {
    return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const { request_id } = req.params;
    const result = await pool.query(
      `SELECT c.connection_id, c.employee_id, c.connected_by, c.connection_date, c.status,
              e.full_name AS employee_name, e.phone AS employee_phone
      FROM job_request_connections c
      JOIN employees e ON c.employee_id = e.employee_id
      WHERE c.request_id = $1`,
      [request_id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching connections:', error);
    res.status(500).json({ error: 'Failed to fetch connections' });
  }
});

// Create new connection between employee and job request - Admin only
app.post('/api/connections', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { employee_id, company_id, request_id } = req.body;
  
  if (!employee_id || !company_id || !request_id) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    // Verify all IDs exist
    const [employee, company, jobRequest] = await Promise.all([
      pool.query('SELECT employee_id FROM employees WHERE employee_id = $1', [employee_id]),
      pool.query('SELECT company_id FROM companies WHERE company_id = $1', [company_id]),
      pool.query('SELECT request_id FROM job_requests WHERE request_id = $1 AND company_id = $2', [request_id, company_id])
    ]);

    if (employee.rowCount === 0) return res.status(404).json({ error: 'Employee not found' });
    if (company.rowCount === 0) return res.status(404).json({ error: 'Company not found' });
    if (jobRequest.rowCount === 0) return res.status(404).json({ error: 'Job request not found for this company' });

    // Create connection
    const result = await pool.query(
      `INSERT INTO job_request_connections 
      (request_id, employee_id, company_id, connected_by, status) 
      VALUES ($1, $2, $3, 'admin', 'accepted')
      RETURNING *`,
      [request_id, employee_id, company_id]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Connection creation error:', error);
    
    if (error.code === '23505') { // Unique violation
      return res.status(409).json({ error: 'This employee is already connected to this job request' });
    }
    
    res.status(500).json({ error: 'Connection creation failed' });
  }
});

app.post('/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userRes.rowCount === 0) {
      return res.status(200).json({ message: 'If the email exists, a reset link will be sent' });
    }

    const user = userRes.rows[0];
    // Generate reset token (valid for 1 hour)
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour

    await pool.query(
      'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE user_id = $3',
      [resetToken, resetTokenExpiry, user.user_id]
    );

    // Send email
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const resetLink = `http://your-frontend.com/reset-password?token=  ${resetToken}`;
    
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'Password Reset Request',
      html: `<p>You requested a password reset. Click <a href="${resetLink}">here</a> to reset your password. This link expires in 1 hour.</p>`
    });

    res.status(200).json({ message: 'Reset link sent to email if account exists' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Could not process request' });
  }
});

// Reset Password
app.post('/auth/reset-password', async (req, res) => {
  const { token, newPassword, confirmPassword } = req.body;
  
  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }

  try {
    const userRes = await pool.query(
      'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expiry > NOW()',
      [token]
    );
    
    if (userRes.rowCount === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const user = userRes.rows[0];
    const passwordHash = await bcrypt.hash(newPassword, 12);
    
    await pool.query(
      'UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expiry = NULL WHERE user_id = $2',
      [passwordHash, user.user_id]
    );

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Could not reset password' });
  }
});

// OTP Generation & Email Sending
app.post('/auth/send-otp', async (req, res) => {
  const { email } = req.body;
  
  try {
    const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userRes.rowCount === 0) {
      // Don't reveal if email exists
      return res.status(200).json({ message: 'If registered, an OTP has been sent' });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date(Date.now() + 3 * 60000); // 3 minutes

    await pool.query(
      'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3',
      [otp, otpExpiry, email]
    );

    // Send email with OTP
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'Password Reset OTP',
      html: `<p>Your password reset OTP is: <strong>${otp}</strong>. Valid for 3 minutes.</p>`
    });

    res.status(200).json({ message: 'OTP sent to email' });
  } catch (error) {
    console.error('OTP send error:', error);
    res.status(500).json({ error: 'Could not send OTP' });
  }
});

// OTP Verification & Password Reset
app.post('/auth/reset-password-with-otp', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  
  try {
    const userRes = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND reset_token = $2 AND reset_token_expiry > NOW()',
      [email, otp]
    );
    
    if (userRes.rowCount === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);
    
    await pool.query(
      'UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expiry = NULL WHERE email = $2',
      [passwordHash, email]
    );

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ error: 'Password reset failed' });
  }
});

// Resend OTP Endpoint
app.post('/auth/resend-otp', async (req, res) => {
  const { email } = req.body;
  
  try {
    const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userRes.rowCount === 0) {
      return res.status(200).json({ message: 'If registered, an OTP has been sent' });
    }

    // Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date(Date.now() + 3 * 60000);

    await pool.query(
      'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3',
      [otp, otpExpiry, email]
    );

    // Resend email
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'New Password Reset OTP',
      html: `<p>Your new OTP is: <strong>${otp}</strong>. Valid for 3 minutes.</p>`
    });

    res.status(200).json({ message: 'New OTP sent' });
  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ error: 'Could not resend OTP' });
  }
});

// Update company profile - Company only
app.put('/api/companies/:companyId', authenticate, async (req, res) => {
  const { userId, role } = req.user;
  const { companyId } = req.params;
  
  if (role !== 'company') {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    // Verify company ownership
    const companyCheck = await pool.query(
      'SELECT company_id FROM companies WHERE company_id = $1 AND user_id = $2',
      [companyId, userId]
    );

    if (companyCheck.rowCount === 0) {
      return res.status(404).json({ error: 'Company not found or access denied' });
    }

    const {
      name,
      industry,
      location,
      contact_person_name,
      contact_person_phone,
      contact_email,
      company_size,
      website_url,
      about_us,
      hiring_status
    } = req.body;

    const updateResult = await pool.query(
      `UPDATE companies
      SET
        name = $1,
        industry = $2,
        location = $3,
        contact_person_name = $4,
        contact_person_phone = $5,
        contact_email = $6,
        company_size = $7,
        website_url = $8,
        about_us = $9,
        hiring_status = $10
      WHERE company_id = $11
      RETURNING *`,
      [
        name,
        industry,
        location,
        contact_person_name,
        contact_person_phone,
        contact_email,
        company_size,
        website_url,
        about_us,
        hiring_status,
        companyId
      ]
    );

    res.json(updateResult.rows[0]);
  } catch (error) {
    console.error('Company profile update error:', error);
    res.status(500).json({ error: 'Failed to update company profile' });
  }
});

// Get dashboard statistics - Admin only
app.get('/api/admin/dashboard-stats', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const [jobRequests, adminConnections, joinRequests] = await Promise.all([
      pool.query("SELECT COUNT(DISTINCT request_id) FROM job_requests WHERE status = 'open'"),
      pool.query("SELECT COUNT(*) FROM job_request_connections WHERE connected_by = 'admin'"),
      pool.query("SELECT COUNT(*) FROM job_request_connections WHERE connected_by = 'employee' AND status = 'requested'")
    ]);
    
    res.json({
      totalJobRequests: parseInt(jobRequests.rows[0].count),
      totalAdminConnections: parseInt(adminConnections.rows[0].count),
      totalJoinRequests: parseInt(joinRequests.rows[0].count)
    });
  } catch (err) {
    console.error('Error fetching dashboard stats:', err);
    res.status(500).json({ error: 'Could not fetch dashboard stats' });
  }
});

// Get all active job requests with interview dates - Admin only
app.get('/api/admin/job-requests', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const result = await pool.query(`
      SELECT 
        jr.request_id,
        jr.title,
        jr.domain,
        jr.interview_time AS "interviewDate",
        jr.status,
        jr.count,
        c.name AS company_name
      FROM job_requests jr
      JOIN companies c ON jr.company_id = c.company_id
      WHERE jr.status = 'active'
      ORDER BY jr.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching job requests:', err);
    res.status(500).json({ error: 'Could not fetch job requests' });
  }
});

// Get employees connected by admin - Admin only
app.get('/api/admin/connected-employees', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const result = await pool.query(`
      SELECT
        jrc.connection_id,
        e.full_name AS employee_name,
        jr.title AS job_title,
        jrc.connection_date,
        jrc.status
      FROM job_request_connections jrc
      JOIN employees e ON jrc.employee_id = e.employee_id
      JOIN job_requests jr ON jrc.request_id = jr.request_id
      WHERE jrc.connected_by = 'admin'
        AND jrc.status = 'confirmed'
      ORDER BY jrc.connection_date DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching admin connections:', err);
    res.status(500).json({ error: 'Could not fetch connections' });
  }
});

// Get join requests from employees - Admin only
// Get join requests from employees - Admin only
app.get('/api/admin/join-requests', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const result = await pool.query(`
      SELECT
        jrc.connection_id,
        e.full_name AS employee_name,
        jr.title AS job_title,
        c.name AS company_name,
        jrc.status
      FROM job_request_connections jrc
      JOIN employees e ON jrc.employee_id = e.employee_id
      JOIN job_requests jr ON jrc.request_id = jr.request_id
      JOIN companies c ON jr.company_id = c.company_id
      WHERE jrc.connected_by = 'employee'
        AND jrc.status = 'pending'
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching join requests:', error);
    res.status(500).json({ error: 'Failed to fetch join requests' });
  }
});
// Get employee's applications
// Create new application
app.post('/api/applications', authenticate, async (req, res) => {
  const { userId, role } = req.user;
  const { job_request_id } = req.body;
  
  if (role !== 'employee') {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    // Get employee ID
    const empRes = await pool.query(
      'SELECT employee_id FROM employees WHERE user_id = $1',
      [userId]
    );
    
    if (empRes.rowCount === 0) {
      return res.status(404).json({ error: 'Employee profile not found' });
    }
    
    const employeeId = empRes.rows[0].employee_id;
    
    // Get job request details
    const jobRes = await pool.query(
      `SELECT company_id FROM job_requests WHERE request_id = $1`,
      [job_request_id]
    );
    
    if (jobRes.rowCount === 0) {
      return res.status(404).json({ error: 'Job request not found' });
    }
    
    const companyId = jobRes.rows[0].company_id || 0; // Use 0 if company_id is null
    
    // Create connection with status 'pending'
    const result = await pool.query(
      `INSERT INTO job_request_connections 
      (request_id, employee_id, company_id, connected_by, status) 
      VALUES ($1, $2, $3, 'employee', 'pending')
      RETURNING *`,
      [job_request_id, employeeId, companyId]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Application creation error:', error);
    
    if (error.code === '23505') {
      return res.status(409).json({ error: 'Already applied to this job' });
    }
    
    res.status(500).json({ error: 'Application failed' });
  }
});


// Create new application
app.get('/api/applications/details', authenticate, async (req, res) => {
  const { userId, role } = req.user;
  
  if (role !== 'employee') {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    // Get employee ID
    const empRes = await pool.query(
      'SELECT employee_id FROM employees WHERE user_id = $1',
      [userId]
    );
    
    if (empRes.rowCount === 0) {
      return res.status(404).json({ error: 'Employee profile not found' });
    }
    
    const employeeId = empRes.rows[0].employee_id;
    
    // Get applications with job details
    const result = await pool.query(`
      SELECT 
        jrc.connection_id,
        jrc.request_id,
        jrc.employee_id,
        jrc.company_id,
        jrc.connected_by,
        jrc.connection_date,
        jrc.status,
        jr.title,
        jr.domain,
        jr.description,
        jr.salary_range,
        jr.location,
        jr.employment_type,
        jr.contact_email,
        jr.contact_person,
        jr.interview_time,
        jr.interview_location,
        c.company_name
      FROM job_request_connections jrc
      JOIN job_requests jr ON jrc.request_id = jr.request_id
      LEFT JOIN companies c ON jr.company_id = c.company_id
      WHERE jrc.employee_id = $1
    `, [employeeId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching applications:', error);
    res.status(500).json({ error: 'Failed to fetch applications' });
  }
});
// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));