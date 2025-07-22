
const { createClient } = require('@supabase/supabase-js');
const axios = require('axios');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

// Initialize Supabase
const supabaseUrl = process.env.SUPABASE_URL || 'https://placeholder.supabase.co';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || 'placeholder-key';
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Panel Config
const PANEL_CONFIG = {
  url: process.env.PTERODACTYL_URL || 'https://panel.example.com',
  apiKey: process.env.PTERODACTYL_API_KEY || 'plta_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  nodeId: parseInt(process.env.PTERODACTYL_NODE_ID) || 1,
  eggId: parseInt(process.env.PTERODACTYL_EGG_ID) || 15,
  locationId: parseInt(process.env.PTERODACTYL_LOCATION_ID) || 1,
  dockerImage: process.env.PTERODACTYL_DOCKER_IMAGE || 'ghcr.io/parkervcp/yolks:nodejs_18',
  environment: {
    STARTUP: process.env.PTERODACTYL_STARTUP || 'if [[ -d .git ]] && [[ {{AUTO_UPDATE}} == "1" ]]; then git pull; fi; if [[ ! -z ${NODE_PACKAGES} ]]; then /usr/local/bin/npm install ${NODE_PACKAGES}; fi; if [[ ! -z ${UNNODE_PACKAGES} ]]; then /usr/local/bin/npm uninstall ${UNNODE_PACKAGES}; fi; if [ -f /home/container/package.json ]; then /usr/local/bin/npm install; fi; /usr/local/bin/node /home/container/{{BOT_JS_FILE}}',
    P_SERVER_LOCATION: 'test',
    P_SERVER_UUID: '',
    BOT_JS_FILE: 'index.js',
    AUTO_UPDATE: '0',
    NODE_PACKAGES: '',
    UNNODE_PACKAGES: ''
  }
};

// Email transporter setup
console.log('📧 Email configuration:');
console.log('EMAIL_USER:', process.env.EMAIL_USER ? '✅ Set' : '❌ Not set');
console.log('EMAIL_PASS:', process.env.EMAIL_PASS ? '✅ Set (length: ' + process.env.EMAIL_PASS.length + ')' : '❌ Not set');

const transporter = nodemailer.createTransporter({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-app-password'
  }
});

// Helper functions
function generatePassword() {
  return crypto.randomBytes(3).toString('hex');
}

async function requireAuth(req) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    throw new Error('Token required');
  }

  const { data: users } = await supabase
    .from('users')
    .select('*')
    .eq('id', token);

  if (!users || users.length === 0) {
    throw new Error('Invalid token');
  }

  return users[0];
}

async function requireAdmin(req) {
  const user = await requireAuth(req);
  if (!user.is_admin) {
    throw new Error('Admin access required');
  }
  return user;
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

// Main handler function - INI ADALAH OTAK UTAMA UNTUK VERCEL!
module.exports = async (req, res) => {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  try {
    const { method, url } = req;
    const path = url.split('?')[0];

    console.log(`🚀 ${method} ${path} - Otak utama API berjalan di Vercel!`);

    // AUTH ROUTES
    if (method === 'POST' && path === '/api/auth/register') {
      const { username, email, password, fullName } = req.body;

      if (!username || !email || !password || !fullName) {
        return res.status(400).json({ 
          success: false, 
          error: 'Semua field harus diisi' 
        });
      }

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

      const hashedPassword = await bcrypt.hash(password, 10);

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

      if (error) throw error;

      // Kirim notifikasi email ke admin
      await notifyAdminNewUser(fullName, username, email);

      res.json({ 
        success: true, 
        message: 'Registrasi berhasil! Menunggu persetujuan admin.' 
      });

    } else if (method === 'POST' && path === '/api/auth/login') {
      const { emailOrUsername, password } = req.body;

      if (!emailOrUsername || !password) {
        return res.status(400).json({ 
          success: false, 
          error: 'Email/username dan password harus diisi' 
        });
      }

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
      const isValidPassword = await bcrypt.compare(password, user.password);
      
      if (!isValidPassword) {
        return res.status(401).json({ 
          success: false, 
          error: 'Email/username atau password salah' 
        });
      }

      if (!user.is_approved) {
        return res.status(403).json({ 
          success: false, 
          error: 'Akun Anda belum disetujui admin' 
        });
      }

      if (user.is_banned) {
        return res.status(403).json({ 
          success: false, 
          error: `Akun Anda telah di-ban. Alasan: ${user.ban_reason || 'Tidak disebutkan'}` 
        });
      }

      res.json({ 
        success: true, 
        token: user.id,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          full_name: user.full_name,
          is_admin: user.is_admin
        }
      });

    } else if (method === 'GET' && path === '/api/auth/check') {
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
          full_name: user.full_name,
          is_admin: user.is_admin
        }
      });

    } else if (method === 'POST' && path === '/api/auth/forgot-password') {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ 
          success: false, 
          error: 'Email harus diisi' 
        });
      }

      const { data: users } = await supabase
        .from('users')
        .select('*')
        .eq('email', email);

      if (!users || users.length === 0) {
        return res.json({ 
          success: true, 
          message: 'Jika email terdaftar, link reset password akan dikirim.' 
        });
      }

      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpires = new Date(Date.now() + 3600000).toISOString();

      const { error } = await supabase
        .from('users')
        .update({ 
          reset_token: resetToken,
          reset_expires: resetExpires
        })
        .eq('email', email);

      if (error) throw error;

      const resetUrl = `${req.headers.origin}/reset-password?token=${resetToken}`;

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
        }
      } catch (emailError) {
        console.error('Email sending failed:', emailError);
      }

      res.json({ 
        success: true, 
        message: 'Jika email terdaftar, link reset password akan dikirim.' 
      });

    } else if (method === 'POST' && path === '/api/auth/reset-password') {
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

      if (new Date() > new Date(user.reset_expires)) {
        return res.status(400).json({ 
          success: false, 
          error: 'Token reset sudah kadaluwarsa' 
        });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);

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

    } else if (method === 'POST' && path === '/api/auth/logout') {
      res.json({ success: true });

    } else if (method === 'POST' && path === '/api/server/create') {
      const user = await requireAuth(req);
      const { username, ram, cpu } = req.body;

      const ramMB = ram == 0 ? 999999 : parseInt(ram) * 1024;
      const cpuPercent = cpu == 0 ? 999999 : parseInt(cpu);
      const password = generatePassword();

      const allocation = await getAvailableAllocation(PANEL_CONFIG.nodeId);
      const pteroUser = await createUser(username, password);
      const server = await createServer(pteroUser.id, username, allocation, ramMB, cpuPercent);

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

    } else if (method === 'GET' && path === '/api/admin/pending-users') {
      const user = await requireAuth(req);
      
      const { data: users } = await supabase
        .from('users')
        .select('id, username, email, full_name, created_at')
        .eq('is_approved', false)
        .order('created_at', { ascending: false });

      res.json({ success: true, users });

    } else if (method === 'POST' && path.startsWith('/api/admin/approve-user/')) {
      const user = await requireAuth(req);
      const userId = path.split('/').pop();

      const { error } = await supabase
        .from('users')
        .update({ is_approved: true })
        .eq('id', userId);

      if (error) throw error;

      res.json({ 
        success: true, 
        message: 'User berhasil disetujui' 
      });

    } else if (method === 'DELETE' && path.startsWith('/api/admin/reject-user/')) {
      const user = await requireAuth(req);
      const userId = path.split('/').pop();

      const { error } = await supabase
        .from('users')
        .delete()
        .eq('id', userId);

      if (error) throw error;

      res.json({ 
        success: true, 
        message: 'User berhasil ditolak' 
      });

    } else if (method === 'GET' && path === '/api/admin/all-users') {
      const user = await requireAdmin(req);

      const { data: users } = await supabase
        .from('users')
        .select('id, username, email, full_name, created_at, is_approved, is_banned, ban_reason, banned_at')
        .eq('is_approved', true)
        .neq('is_admin', true) // Exclude admin emails from ban list
        .order('created_at', { ascending: false });

      res.json({ success: true, users });

    } else if (method === 'POST' && path.startsWith('/api/admin/ban-user/')) {
      const user = await requireAdmin(req);
      const userId = path.split('/').pop();
      const { reason } = req.body;

      const { error } = await supabase
        .from('users')
        .update({ 
          is_banned: true,
          ban_reason: reason || 'Tidak disebutkan',
          banned_at: new Date().toISOString(),
          banned_by: user.username
        })
        .eq('id', userId);

      if (error) throw error;

      res.json({ 
        success: true, 
        message: 'User berhasil di-ban' 
      });

    } else if (method === 'POST' && path.startsWith('/api/admin/unban-user/')) {
      const user = await requireAdmin(req);
      const userId = path.split('/').pop();

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

    } else if (method === 'POST' && path === '/api/admin/reset-user-password') {
      const user = await requireAdmin(req);
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ 
          success: false, 
          error: 'Email harus diisi' 
        });
      }

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

      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpires = new Date(Date.now() + 3600000).toISOString();

      const { error } = await supabase
        .from('users')
        .update({ 
          reset_token: resetToken,
          reset_expires: resetExpires
        })
        .eq('email', email);

      if (error) throw error;

      const resetUrl = `${req.headers.origin}/reset-password?token=${resetToken}`;

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Reset Password - Pterodactyl Deploy',
        html: `
          <h2>Reset Password</h2>
          <p>Admin telah meminta reset password untuk akun Anda. Klik link berikut untuk reset password:</p>
          <a href="${resetUrl}" style="background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a>
          <p>Link ini akan kadaluwarsa dalam 1 jam.</p>
        `
      };

      if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
        await transporter.sendMail(mailOptions);
      }

      res.json({ 
        success: true, 
        message: 'Email reset password telah dikirim' 
      });

    } else if (method === 'POST' && path === '/api/admin/change-user-password') {
      const user = await requireAdmin(req);
      const { email, newPassword } = req.body;

      if (!email || !newPassword) {
        return res.status(400).json({ 
          success: false, 
          error: 'Email dan password baru harus diisi' 
        });
      }

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

      const targetUser = users[0];
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      const { error } = await supabase
        .from('users')
        .update({ 
          password: hashedPassword,
          updated_at: new Date().toISOString()
        })
        .eq('id', targetUser.id);

      if (error) throw error;

      res.json({ 
        success: true, 
        message: `Password untuk user ${targetUser.username} berhasil diubah` 
      });

    } else if (method === 'GET' && path === '/health') {
      res.json({ 
        status: 'alive', 
        timestamp: new Date().toISOString(),
        message: '🚀 Otak utama API berjalan sempurna di Vercel!' 
      });

    } else {
      res.status(404).json({ success: false, error: 'Endpoint tidak ditemukan' });
    }

  } catch (error) {
    console.error('❌ API Error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message || 'Terjadi kesalahan server' 
    });
  }
};
