
document.addEventListener('DOMContentLoaded', function() {
    checkAuth();
    loadPendingUsers();
    showPendingUsers(); // Show pending users tab by default
});

async function checkAuth() {
    try {
        const token = localStorage.getItem('auth_token');
        if (!token) {
            window.location.href = '/login';
            return;
        }

        const response = await fetch('/api/auth/check', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        const data = await response.json();
        
        if (!data.loggedIn) {
            localStorage.removeItem('auth_token');
            window.location.href = '/login';
            return;
        }

        document.getElementById('currentAdmin').textContent = data.user.username || data.user.email;
        
    } catch (error) {
        console.error('Auth check failed:', error);
        window.location.href = '/login';
    }
}

async function loadPendingUsers() {
    const loadingSpinner = document.getElementById('loadingSpinner');
    const noData = document.getElementById('noData');
    const usersList = document.getElementById('usersList');
    
    // Show loading
    loadingSpinner.classList.remove('hidden');
    noData.classList.add('hidden');
    usersList.classList.add('hidden');
    
    try {
        const token = localStorage.getItem('auth_token');
        const response = await fetch('/api/admin/pending-users', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            if (data.users.length === 0) {
                noData.classList.remove('hidden');
            } else {
                displayUsers(data.users);
                usersList.classList.remove('hidden');
            }
        } else {
            showError(data.error || 'Gagal memuat data user');
        }
        
    } catch (error) {
        console.error('Load pending users error:', error);
        showError('Terjadi kesalahan saat memuat data');
    } finally {
        loadingSpinner.classList.add('hidden');
    }
}

function displayUsers(users) {
    const usersList = document.getElementById('usersList');
    
    usersList.innerHTML = users.map(user => `
        <div class="bg-white/5 border border-white/10 rounded-lg p-6 transition-all hover:bg-white/10">
            <div class="flex justify-between items-start">
                <div class="flex-1">
                    <div class="flex items-center mb-2">
                        <i class="fas fa-user-circle text-blue-400 text-2xl mr-3"></i>
                        <div>
                            <h3 class="text-white font-semibold text-lg">${user.full_name}</h3>
                            <p class="text-white/60">@${user.username}</p>
                        </div>
                    </div>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                        <div>
                            <p class="text-white/50 text-sm">Email</p>
                            <p class="text-white">${user.email}</p>
                        </div>
                        <div>
                            <p class="text-white/50 text-sm">Tanggal Daftar</p>
                            <p class="text-white">${new Date(user.created_at).toLocaleDateString('id-ID')}</p>
                        </div>
                    </div>
                </div>
                
                <div class="flex space-x-2 ml-4">
                    <button onclick="approveUser('${user.id}')" 
                            class="btn-success flex items-center">
                        <i class="fas fa-check mr-2"></i>
                        Setujui
                    </button>
                    <button onclick="rejectUser('${user.id}')" 
                            class="btn-danger flex items-center">
                        <i class="fas fa-times mr-2"></i>
                        Tolak
                    </button>
                </div>
            </div>
        </div>
    `).join('');
}

async function approveUser(userId) {
    try {
        const token = localStorage.getItem('auth_token');
        const response = await fetch(`/api/admin/approve-user/${userId}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess(data.message);
            setTimeout(() => {
                loadPendingUsers();
            }, 1000);
        } else {
            showError(data.error || 'Gagal menyetujui user');
        }
        
    } catch (error) {
        console.error('Approve user error:', error);
        showError('Terjadi kesalahan saat menyetujui user');
    }
}

async function rejectUser(userId) {
    if (!confirm('Yakin ingin menolak user ini?')) return;
    
    try {
        const token = localStorage.getItem('auth_token');
        const response = await fetch(`/api/admin/reject-user/${userId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess('User berhasil ditolak dan dihapus');
            setTimeout(() => {
                loadPendingUsers();
            }, 1000);
        } else {
            showError(data.error || 'Gagal menolak user');
        }
        
    } catch (error) {
        console.error('Reject user error:', error);
        showError('Terjadi kesalahan saat menolak user');
    }
}

async function handleLogout() {
    try {
        const token = localStorage.getItem('auth_token');
        if (token) {
            await fetch('/api/auth/logout', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
        }
    } catch (error) {
        console.log('Logout error:', error);
    } finally {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('user_data');
        window.location.href = '/';
    }
}

function showSuccess(message) {
    const successMsg = document.getElementById('successMsg');
    const successText = document.getElementById('successText');
    
    successText.textContent = message;
    successMsg.classList.remove('hidden');
    
    setTimeout(() => {
        successMsg.classList.add('hidden');
    }, 3000);
}

function showResetPasswordModal() {
    const modal = document.getElementById('resetPasswordModal');
    modal.classList.remove('hidden');
}

function hideResetPasswordModal() {
    const modal = document.getElementById('resetPasswordModal');
    modal.classList.add('hidden');
    document.getElementById('resetPasswordForm').reset();
}

async function handleResetPassword(e) {
    e.preventDefault();
    
    const email = document.getElementById('resetEmail').value;
    const newPassword = document.getElementById('resetNewPassword').value;
    const confirmPassword = document.getElementById('resetConfirmPassword').value;
    
    if (!email || !newPassword || !confirmPassword) {
        showError('Semua field harus diisi');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        showError('Password dan konfirmasi password tidak cocok');
        return;
    }
    
    if (newPassword.length < 6) {
        showError('Password minimal 6 karakter');
        return;
    }
    
    try {
        const token = localStorage.getItem('auth_token');
        const response = await fetch('/api/admin/change-user-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ email, newPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess(data.message);
            hideResetPasswordModal();
        } else {
            showError(data.error || 'Gagal mengubah password');
        }
        
    } catch (error) {
        console.error('Reset password error:', error);
        showError('Terjadi kesalahan saat mengubah password');
    }
}

// Tab Navigation
function showPendingUsers() {
    document.getElementById('pendingUsersSection').classList.remove('hidden');
    document.getElementById('allUsersSection').classList.add('hidden');
    document.getElementById('pendingTab').className = 'btn-primary';
    document.getElementById('allUsersTab').className = 'btn-secondary';
    loadPendingUsers();
}

function showAllUsers() {
    document.getElementById('pendingUsersSection').classList.add('hidden');
    document.getElementById('allUsersSection').classList.remove('hidden');
    document.getElementById('pendingTab').className = 'btn-secondary';
    document.getElementById('allUsersTab').className = 'btn-primary';
    loadAllUsers();
}

// Load All Users
async function loadAllUsers() {
    const loadingSpinner = document.getElementById('allUsersLoadingSpinner');
    const noData = document.getElementById('allUsersNoData');
    const usersList = document.getElementById('allUsersList');
    
    // Show loading
    loadingSpinner.classList.remove('hidden');
    noData.classList.add('hidden');
    usersList.classList.add('hidden');
    
    try {
        const token = localStorage.getItem('auth_token');
        const response = await fetch('/api/admin/all-users', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            if (data.users.length === 0) {
                noData.classList.remove('hidden');
            } else {
                displayAllUsers(data.users);
                usersList.classList.remove('hidden');
            }
        } else {
            showError(data.error || 'Gagal memuat data user');
        }
        
    } catch (error) {
        console.error('Load all users error:', error);
        showError('Terjadi kesalahan saat memuat data');
    } finally {
        loadingSpinner.classList.add('hidden');
    }
}

function displayAllUsers(users) {
    const usersList = document.getElementById('allUsersList');
    
    usersList.innerHTML = users.map(user => `
        <div class="bg-white/5 border border-white/10 rounded-lg p-6 transition-all hover:bg-white/10">
            <div class="flex justify-between items-start">
                <div class="flex-1">
                    <div class="flex items-center mb-2">
                        <i class="fas fa-user-circle text-blue-400 text-2xl mr-3"></i>
                        <div>
                            <h3 class="text-white font-semibold text-lg">${user.full_name}</h3>
                            <p class="text-white/60">@${user.username}</p>
                            ${user.is_banned ? `<span class="bg-red-500 text-white px-2 py-1 rounded text-xs">BANNED</span>` : ''}
                        </div>
                    </div>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                        <div>
                            <p class="text-white/50 text-sm">Email</p>
                            <p class="text-white">${user.email}</p>
                        </div>
                        <div>
                            <p class="text-white/50 text-sm">Tanggal Daftar</p>
                            <p class="text-white">${new Date(user.created_at).toLocaleDateString('id-ID')}</p>
                        </div>
                        ${user.is_banned && user.ban_reason ? `
                        <div class="col-span-2">
                            <p class="text-white/50 text-sm">Alasan Ban</p>
                            <p class="text-red-400">${user.ban_reason}</p>
                        </div>
                        ` : ''}
                    </div>
                </div>
                
                <div class="flex flex-col space-y-2 ml-4">
                    ${user.is_banned ? `
                        <button onclick="unbanUser('${user.id}')" 
                                class="btn-success flex items-center">
                            <i class="fas fa-check mr-2"></i>
                            Unban
                        </button>
                    ` : `
                        <button onclick="showBanUserModal('${user.id}', '${user.username}')" 
                                class="btn-danger flex items-center">
                            <i class="fas fa-ban mr-2"></i>
                            Ban
                        </button>
                    `}
                </div>
            </div>
        </div>
    `).join('');
}

// Ban User Functions
function showBanUserModal(userId, username) {
    document.getElementById('banUserId').value = userId;
    document.getElementById('banUserModal').classList.remove('hidden');
}

function hideBanUserModal() {
    document.getElementById('banUserModal').classList.add('hidden');
    document.getElementById('banUserForm').reset();
}

async function handleBanUser(e) {
    e.preventDefault();
    
    const userId = document.getElementById('banUserId').value;
    const reason = document.getElementById('banReason').value;
    
    try {
        const token = localStorage.getItem('auth_token');
        const response = await fetch(`/api/admin/ban-user/${userId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ reason })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess(data.message);
            hideBanUserModal();
            loadAllUsers();
        } else {
            showError(data.error || 'Gagal mem-ban user');
        }
        
    } catch (error) {
        console.error('Ban user error:', error);
        showError('Terjadi kesalahan saat mem-ban user');
    }
}

async function unbanUser(userId) {
    if (!confirm('Yakin ingin meng-unban user ini?')) return;
    
    try {
        const token = localStorage.getItem('auth_token');
        const response = await fetch(`/api/admin/unban-user/${userId}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess(data.message);
            loadAllUsers();
        } else {
            showError(data.error || 'Gagal meng-unban user');
        }
        
    } catch (error) {
        console.error('Unban user error:', error);
        showError('Terjadi kesalahan saat meng-unban user');
    }
}

function showError(message) {
    const errorMsg = document.getElementById('errorMsg');
    const errorText = document.getElementById('errorText');
    
    errorText.textContent = message;
    errorMsg.classList.remove('hidden');
    
    setTimeout(() => {
        errorMsg.classList.add('hidden');
    }, 3000);
}
