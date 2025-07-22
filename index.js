// ⚠️ FILE INI HANYA UNTUK DEVELOPMENT DI REPLIT
// Untuk deployment Vercel, otak utama ada di api/index.js
// File ini tetap lengkap untuk testing dan development

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const supabase = require('./supabase');
const PANEL_CONFIG = require('./config.js');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Email transporter setup (configure with your email service)
console.log('📧 Email configuration:');
console.log('EMAIL_USER:', process.env.EMAIL_USER ? '✅ Set' : '❌ Not set');
console.log('EMAIL_PASS:', process.env.EMAIL_PASS ? '✅ Set (length: ' + process.env.EMAIL_PASS.length + ')' : '❌ Not set');

const transporter = nodemailer.createTransport({
  service: 'gmail', // atau service email lainnya
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-app-password'
  }
});

// Middleware untuk check authentication
async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ success: false, error: 'Token required' });
  }

  // Simple token validation (bisa diganti dengan JWT jika perlu)
  const { data: users } = await supabase
    .from('users')
    .select('*')
    .eq('id', token);

  if (!users || users.length === 0) {
    return res.status(401).json({ success: false, error: 'Invalid token' });
  }

  req.user = users[0];
  next();
}

// Middleware untuk check admin only
async function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ success: false, error: 'Token required' });
  }

  const { data: users } = await supabase
    .from('users')
    .select('*')
    .eq('id', token);

  if (!users || users.length === 0 || !users[0].is_admin) {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }

  req.user = users[0];
  next();
}

// Function untuk generate password acak
function generatePassword() {
  return crypto.randomBytes(3).toString('hex');
}

// Function untuk mengirim notifikasi ke admin
async function notifyAdminNewUser(fullName, username, email) {
  try {
    // Ambil semua admin dari database
    const { data: admins } = await supabase
      .from('users')
      .select('email, username')
      .eq('is_admin', true);

    if (!admins || admins.length === 0) {
      console.log('⚠️ No admin found to notify');
      return;
    }

    // Kirim email ke semua admin
    for (const admin of admins) {
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: admin.email,
        subject: '🆕 Pendaftar Baru - Pterodactyl Deploy',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
              <h1 style="color: white; margin: 0;">🆕 Pendaftar Baru!</h1>
            </div>
            <div style="background: white; padding: 30px; border-radius: 0 0 10px 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
              <h2 style="color: #333; margin-top: 0;">Detail Pendaftar:</h2>
              <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr style="background: #f8f9fa;">
                  <td style="padding: 12px; border: 1px solid #dee2e6; font-weight: bold;">Nama Lengkap:</td>
                  <td style="padding: 12px; border: 1px solid #dee2e6;">${fullName}</td>
                </tr>
                <tr>
                  <td style="padding: 12px; border: 1px solid #dee2e6; font-weight: bold;">Username:</td>
                  <td style="padding: 12px; border: 1px solid #dee2e6;">${username}</td>
                </tr>
                <tr style="background: #f8f9fa;">
                  <td style="padding: 12px; border: 1px solid #dee2e6; font-weight: bold;">Email:</td>
                  <td style="padding: 12px; border: 1px solid #dee2e6;">${email}</td>
                </tr>
                <tr>
                  <td style="padding: 12px; border: 1px solid #dee2e6; font-weight: bold;">Waktu Daftar:</td>
                  <td style="padding: 12px; border: 1px solid #dee2e6;">${new Date().toLocaleString('id-ID')}</td>
                </tr>
              </table>
              
              <div style="background: #e3f2fd; padding: 15px; border-radius: 8px; margin: 20px 0;">
                <p style="margin: 0; color: #1976d2;">
                  <strong>🔔 Tindakan Diperlukan:</strong><br>
                  Silakan login ke Admin Panel untuk menyetujui atau menolak pendaftar ini.
                </p>
              </div>
              
              <div style="text-align: center; margin-top: 30px;">
                <p style="color: #666; font-size: 14px;">
                  Email ini dikirim otomatis dari sistem Pterodactyl Auto Deploy<br>
                  Admin yang menerima: ${admin.username}
                </p>
              </div>
            </div>
          </div>
        `
      };

      if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
        await transporter.sendMail(mailOptions);
        console.log('📧 New user notification sent to admin:', admin.email);
      } else {
        console.log('⚠️ Email not configured, new user registered:', { fullName, username, email });
      }
    }

  } catch (error) {
    console.error('❌ Failed to notify admin:', error);
    // Tidak throw error agar registrasi tetap berhasil meski notifikasi gagal
  }
}

// Function untuk mendapatkan allocation kosong
async function getAvailableAllocation(nodeId) {
  try {
    const response = await axios.get(`${PANEL_CONFIG.url}/api/application/nodes/${nodeId}/allocations`, {
      headers: {
        'Authorization': `Bearer ${PANEL_CONFIG.apiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'Application/vnd.pterodactyl.v1+json'
      }
    });

    const allocations = response.data.data;
    const available = allocations.find(alloc => !alloc.attributes.assigned);

    if (!available) {
      throw new Error('Tidak ada allocation kosong');
    }

    return available.attributes;
  } catch (error) {
    console.error('Error getting allocation:', error.message);
    throw error;
  }
}

// Function untuk membuat user baru
async function createUser(username, password) {
  try {
    const userData = {
      email: `${username}@generated.local`,
      username: username,
      first_name: username,
      last_name: 'User',
      password: password
    };

    const response = await axios.post(`${PANEL_CONFIG.url}/api/application/users`, userData, {
      headers: {
        'Authorization': `Bearer ${PANEL_CONFIG.apiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'Application/vnd.pterodactyl.v1+json'
      }
    });

    return response.data.attributes;
  } catch (error) {
    console.error('Error creating user:', error.message);
    throw error;
  }
}

// Function untuk membuat server
async function createServer(userId, username, allocation, ram, cpu) {
  try {
    const serverData = {
      name: `Server-${username}`,
      user: userId,
      egg: PANEL_CONFIG.eggId,
      docker_image: PANEL_CONFIG.dockerImage,
      startup: PANEL_CONFIG.environment.STARTUP,
      environment: PANEL_CONFIG.environment,
      limits: {
        memory: ram === 0 ? 999999 : ram,
        swap: 0,
        disk: 1024,
        io: 500,
        cpu: cpu === 0 ? 999999 : cpu
      },
      feature_limits: {
        databases: 0,
        allocations: 1,
        backups: 0
      },
      allocation: {
        default: allocation.id
      }
    };

    const response = await axios.post(`${PANEL_CONFIG.url}/api/application/servers`, serverData, {
      headers: {
        'Authorization': `Bearer ${PANEL_CONFIG.apiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'Application/vnd.pterodactyl.v1+json'
      }
    });

    return response.data.attributes;
  } catch (error) {
    console.error('Error creating server:', error.message);
    throw error;
  }
}

// AUTH ROUTES

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, fullName } = req.body;

    // Validasi input
    if (!username || !email || !password || !fullName) {
      return res.status(400).json({ 
        success: false, 
        error: 'Semua field harus diisi' 
      });
    }

    // Cek apakah email atau username sudah ada
    const { data: existingUsers } = await supabase
      .from('users')
      .select('*')
      .or(`email.eq.${email},username.eq.${username}`);

    if (existingUsers && existingUsers.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email atau username sudah terdaftar' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user ke database dengan approval false
    const { data, error } = await supabase
      .from('users')
      .insert([
        {
          username,
          email,
          password: hashedPassword,
          full_name: fullName,
          is_approved: false,
          created_at: new Date().toISOString()
        }
      ])
      .select();

    if (error) {
      throw error;
    }

    // Kirim notifikasi email ke admin
    await notifyAdminNewUser(fullName, username, email);

    res.json({ 
      success: true, 
      message: 'Registrasi berhasil! Menunggu persetujuan admin.' 
    });

  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Terjadi kesalahan saat registrasi' 
    });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;

    if (!emailOrUsername || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email/username dan password harus diisi' 
      });
    }

    // Cari user berdasarkan email atau username
    const { data: users } = await supabase
      .from('users')
      .select('*')
      .or(`email.eq.${emailOrUsername},username.eq.${emailOrUsername}`);

    if (!users || users.length === 0) {
      return res.status(401).json({ 
        success: false, 
        error: 'Email/username atau password salah' 
      });
    }

    const user = users[0];

    // Cek password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ 
        success: false, 
        error: 'Email/username atau password salah' 
      });
    }

    // Cek apakah user sudah diapprove
    if (!user.is_approved) {
      return res.status(403).json({ 
        success: false, 
        error: 'Akun Anda belum disetujui admin' 
      });
    }

    // Cek apakah user di-ban
    if (user.is_banned) {
      return res.status(403).json({ 
        success: false, 
        error: `Akun Anda telah di-ban. Alasan: ${user.ban_reason || 'Tidak disebutkan'}` 
      });
    }

    // Generate simple token (menggunakan user ID sebagai token)
    const token = user.id;

    res.json({ 
      success: true, 
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        full_name: user.full_name
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Terjadi kesalahan saat login' 
    });
  }
});

// Forgot Password (Public)
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email harus diisi' 
      });
    }

    // Cek apakah email ada di database
    const { data: users } = await supabase
      .from('users')
      .select('*')
      .eq('email', email);

    if (!users || users.length === 0) {
      // Jangan beri tahu kalau email tidak ada (security best practice)
      return res.json({ 
        success: true, 
        message: 'Jika email terdaftar, link reset password akan dikirim.' 
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 3600000).toISOString(); // 1 hour

    // Simpan reset token ke database
    const { error } = await supabase
      .from('users')
      .update({ 
        reset_token: resetToken,
        reset_expires: resetExpires
      })
      .eq('email', email);

    if (error) throw error;

    // Kirim email reset password (jika email service dikonfigurasi)
    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password?token=${resetToken}`;

    try {
      const mailOptions = {
        from: process.env.EMAIL_USER || 'noreply@example.com',
        to: email,
        subject: 'Reset Password - Pterodactyl Deploy',
        html: `
          <h2>Reset Password</h2>
          <p>Anda meminta reset password. Klik link berikut untuk reset password:</p>
          <a href="${resetUrl}" style="background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a>
          <p>Link ini akan kadaluwarsa dalam 1 jam.</p>
          <p>Jika Anda tidak meminta reset password, abaikan email ini.</p>
        `
      };

      if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
        await transporter.sendMail(mailOptions);
        console.log('📧 Reset password email sent to:', email);
      } else {
        console.log('⚠️ Email not configured, reset token:', resetToken);
        console.log('Reset URL:', resetUrl);
      }
    } catch (emailError) {
      console.error('Email sending failed:', emailError);
      // Tetap return success meskipun email gagal kirim
    }

    res.json({ 
      success: true, 
      message: 'Jika email terdaftar, link reset password akan dikirim.' 
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Terjadi kesalahan saat memproses permintaan' 
    });
  }
});

// Admin Reset Password (Admin only)
app.post('/api/admin/reset-user-password', requireAdmin, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email harus diisi' 
      });
    }

    // Cek apakah email ada di database
    const { data: users } = await supabase
      .from('users')
      .select('*')
      .eq('email', email);

    if (!users || users.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Email tidak ditemukan' 
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 3600000).toISOString(); // 1 hour

    // Simpan reset token ke database
    const { error } = await supabase
      .from('users')
      .update({ 
        reset_token: resetToken,
        reset_expires: resetExpires
      })
      .eq('email', email);

    if (error) throw error;

    // Kirim email reset password
    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password?token=${resetToken}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Reset Password - Pterodactyl Deploy',
      html: `
        <h2>Reset Password</h2>
        <p>Anda meminta reset password. Klik link berikut untuk reset password:</p>
        <a href="${resetUrl}" style="background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a>
        <p>Link ini akan kadaluwarsa dalam 1 jam.</p>
        <p>Jika Anda tidak meminta reset password, abaikan email ini.</p>
      `
    };

    await transporter.sendMail(mailOptions);

    res.json({ 
      success: true, 
      message: 'Email reset password telah dikirim' 
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Terjadi kesalahan saat mengirim email reset' 
    });
  }
});

// Reset Password dengan Token
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ 
        success: false, 
        error: 'Token dan password baru harus diisi' 
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false, 
        error: 'Password minimal 6 karakter' 
      });
    }

    // Cari user berdasarkan reset token
    const { data: users } = await supabase
      .from('users')
      .select('*')
      .eq('reset_token', token);

    if (!users || users.length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Token reset tidak valid atau sudah kadaluwarsa' 
      });
    }

    const user = users[0];

    // Cek apakah token masih valid (belum kadaluwarsa)
    if (new Date() > new Date(user.reset_expires)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Token reset sudah kadaluwarsa' 
      });
    }

    // Hash password baru
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password dan hapus reset token
    const { error } = await supabase
      .from('users')
      .update({ 
        password: hashedPassword,
        reset_token: null,
        reset_expires: null,
        updated_at: new Date().toISOString()
      })
      .eq('id', user.id);

    if (error) throw error;

    res.json({ 
      success: true, 
      message: 'Password berhasil direset! Silakan login dengan password baru.' 
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Terjadi kesalahan saat mereset password' 
    });
  }
});

// Admin Change User Password
app.post('/api/admin/change-user-password', requireAdmin, async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email dan password baru harus diisi' 
      });
    }

    // Cari user berdasarkan email
    const { data: users } = await supabase
      .from('users')
      .select('*')
      .eq('email', email);

    if (!users || users.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'User dengan email tersebut tidak ditemukan' 
      });
    }

    const user = users[0];

    // Hash password baru
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    const { error } = await supabase
      .from('users')
      .update({ 
        password: hashedPassword,
        updated_at: new Date().toISOString()
      })
      .eq('id', user.id);

    if (error) throw error;

    res.json({ 
      success: true, 
      message: `Password untuk user ${user.username} berhasil diubah` 
    });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Terjadi kesalahan saat mengubah password' 
    });
  }
});

// Check Auth
app.get('/api/auth/check', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.json({ loggedIn: false });
  }

  const { data: users } = await supabase
    .from('users')
    .select('*')
    .eq('id', token);

  if (!users || users.length === 0) {
    return res.json({ loggedIn: false });
  }

  const user = users[0];
  res.json({ 
    loggedIn: true, 
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      full_name: user.full_name
    }
  });
});

// Logout
app.post('/api/auth/logout', async (req, res) => {
  // Dengan simple token system, logout hanya perlu clear token di frontend
  res.json({ success: true });
});

// ADMIN ROUTES

// Get pending users (admin only)
app.get('/api/admin/pending-users', requireAuth, async (req, res) => {
  try {
    // Cek apakah user adalah admin (bisa ditambahkan role system)
    const { data: users } = await supabase
      .from('users')
      .select('id, username, email, full_name, created_at')
      .eq('is_approved', false)
      .order('created_at', { ascending: false });

    res.json({ success: true, users });

  } catch (error) {
    console.error('Get pending users error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Terjadi kesalahan saat mengambil data user' 
    });
  }
});

// Approve user (admin only)
app.post('/api/admin/approve-user/:userId', requireAuth, async (req, res) => {
  try {
    const { userId } = req.params;

    const { error } = await supabase
      .from('users')
      .update({ is_approved: true })
      .eq('id', userId);

    if (error) throw error;

    res.json({ 
      success: true, 
      message: 'User berhasil disetujui' 
    });

  } catch (error) {
    console.error('Approve user error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Terjadi kesalahan saat menyetujui user' 
    });
  }
});

// Reject user (admin only)
app.delete('/api/admin/reject-user/:userId', requireAuth, async (req, res) => {
  try {
    const { userId } = req.params;

    const { error } = await supabase
      .from('users')
      .delete()
      .eq('id', userId);

    if (error) throw error;

    res.json({ 
      success: true, 
      message: 'User berhasil ditolak' 
    });

  } catch (error) {
    console.error('Reject user error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Terjadi kesalahan saat menolak user' 
    });
  }
});

// Get all users (admin only)
app.get('/api/admin/all-users', requireAdmin, async (req, res) => {
  try {
    const { data: users } = await supabase
      .from('users')
      .select('id, username, email, full_name, created_at, is_approved, is_banned, ban_reason, banned_at')
      .eq('is_approved', true)
      .order('created_at', { ascending: false });

    res.json({ success: true, users });

  } catch (error) {
    console.error('Get all users error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Terjadi kesalahan saat mengambil data user' 
    });
  }
});

// Ban user (admin only)
app.post('/api/admin/ban-user/:userId', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { reason } = req.body;

    const { error } = await supabase
      .from('users')
      .update({ 
        is_banned: true,
        ban_reason: reason || 'Tidak disebutkan',
        banned_at: new Date().toISOString(),
        banned_by: req.user.username
      })
      .eq('id', userId);

    if (error) throw error;

    res.json({ 
      success: true, 
      message: 'User berhasil di-ban' 
    });

  } catch (error) {
    console.error('Ban user error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Terjadi kesalahan saat mem-ban user' 
    });
  }
});

// Unban user (admin only)
app.post('/api/admin/unban-user/:userId', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    const { error } = await supabase
      .from('users')
      .update({ 
        is_banned: false,
        ban_reason: null,
        banned_at: null,
        banned_by: null
      })
      .eq('id', userId);

    if (error) throw error;

    res.json({ 
      success: true, 
      message: 'User berhasil di-unban' 
    });

  } catch (error) {
    console.error('Unban user error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Terjadi kesalahan saat meng-unban user' 
    });
  }
});

// SERVER ROUTES

app.post('/api/server/create', requireAuth, async (req, res) => {
  try {
    const { username, ram, cpu } = req.body;

    const ramMB = ram == 0 ? 999999 : parseInt(ram) * 1024;
    const cpuPercent = cpu == 0 ? 999999 : parseInt(cpu);
    const password = generatePassword();

    const allocation = await getAvailableAllocation(PANEL_CONFIG.nodeId);
    const user = await createUser(username, password);
    const server = await createServer(user.id, username, allocation, ramMB, cpuPercent);

    res.json({
      success: true,
      server: {
        id: server.id,
        username,
        password,
        ip: allocation.ip,
        port: allocation.port,
        ram: ram == 0 ? 'Unlimited' : ram + ' GB',
        cpu: cpu == 0 ? 'Unlimited' : cpu + '%'
      }
    });

  } catch (error) {
    console.error('Deploy error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Static file routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

app.get('/deploy', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'deploy.html'));
});

app.get('/result', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'result.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'alive', timestamp: new Date().toISOString() });
});

// Keep alive mechanism
function keepAlive() {
  const keepAliveInterval = 4 * 60 * 1000; // 4 minutes
  
  setInterval(async () => {
    try {
      // Self ping to keep the server active
      const response = await axios.get(`http://localhost:${PORT}/health`, {
        timeout: 10000 // 10 second timeout
      });
      console.log('🔄 Keep alive ping successful:', new Date().toISOString());
    } catch (error) {
      console.log('❌ Keep alive failed:', error.message);
      
      // Fallback: try external ping
      try {
        const externalResponse = await axios.get('https://httpbin.org/get', {
          timeout: 5000
        });
        console.log('🌐 External ping successful as fallback');
      } catch (fallbackError) {
        console.log('❌ External ping also failed');
      }
    }
  }, keepAliveInterval);
  
  console.log(`🔄 Keep alive started - pinging every ${keepAliveInterval / 60000} minutes`);
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Pterodactyl Auto Deploy berjalan di http://0.0.0.0:${PORT}`);
  console.log('📊 Menggunakan Supabase untuk authentication');
  console.log('🔄 Keep alive mechanism activated');

  // Start keep alive after 1 minute
  setTimeout(keepAlive, 60000);
});