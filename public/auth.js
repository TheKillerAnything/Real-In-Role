
document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const errorMsg = document.getElementById('errorMsg');
    const errorText = document.getElementById('errorText');
    const loginBtn = document.getElementById('loginBtn');
    
    // Only check auth redirect if we're actually on login page (has login form)
    if (loginForm) {
        checkAuthAndRedirect();
    }
    
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    // Add enter key handling
    document.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && loginForm) {
            handleLogin(e);
        }
    });
});

async function checkAuthAndRedirect() {
    try {
        const token = localStorage.getItem('auth_token');
        if (!token) return;

        // Prevent redirect if already on deploy page
        if (window.location.pathname.includes('deploy') || 
            window.location.pathname.includes('result') ||
            window.location.pathname.includes('admin')) {
            return;
        }

        const response = await fetch('/api/auth/check', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        const data = await response.json();
        
        if (data.loggedIn) {
            window.location.href = '/deploy';
        } else {
            localStorage.removeItem('auth_token');
        }
    } catch (error) {
        console.log('Auth check failed:', error);
        localStorage.removeItem('auth_token');
    }
}

async function handleLogin(e) {
    e.preventDefault();
    
    const emailOrUsername = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    if (!emailOrUsername || !password) {
        showError('Harap isi email/username dan password');
        return;
    }
    
    setLoading(true);
    hideError();
    
    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ emailOrUsername, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Simpan token ke localStorage
            localStorage.setItem('auth_token', data.token);
            localStorage.setItem('user_data', JSON.stringify(data.user));
            
            showSuccess('Login berhasil! Mengalihkan...');
            setTimeout(() => {
                window.location.href = '/deploy';
            }, 1000);
        } else {
            showError(data.error || 'Login gagal');
        }
    } catch (error) {
        showError('Terjadi kesalahan koneksi');
    } finally {
        setLoading(false);
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

function showError(message) {
    const errorMsg = document.getElementById('errorMsg');
    const errorText = document.getElementById('errorText');
    
    if (!errorMsg || !errorText) return;
    
    errorText.textContent = message;
    errorMsg.classList.remove('hidden');
    errorMsg.classList.add('animate-pulse');
    
    setTimeout(() => {
        errorMsg.classList.remove('animate-pulse');
    }, 500);
}

function hideError() {
    const errorMsg = document.getElementById('errorMsg');
    if (errorMsg) {
        errorMsg.classList.add('hidden');
    }
}

function showSuccess(message) {
    const errorMsg = document.getElementById('errorMsg');
    const errorText = document.getElementById('errorText');
    
    if (!errorMsg || !errorText) return;
    
    errorMsg.className = 'bg-green-500/20 border border-green-500 text-green-100 px-4 py-3 rounded-lg mb-6';
    errorText.innerHTML = `<i class="fas fa-check mr-2"></i>${message}`;
}

function setLoading(loading) {
    const loginBtn = document.getElementById('loginBtn');
    if (!loginBtn) return;
    
    const spinner = loginBtn.querySelector('.loading-spinner');
    const text = loginBtn.querySelector('span');
    
    if (loading) {
        loginBtn.disabled = true;
        loginBtn.classList.add('opacity-75', 'cursor-not-allowed');
        if (spinner) spinner.classList.remove('hidden');
        if (text) text.textContent = 'Memproses...';
    } else {
        loginBtn.disabled = false;
        loginBtn.classList.remove('opacity-75', 'cursor-not-allowed');
        if (spinner) spinner.classList.add('hidden');
        if (text) text.textContent = 'Masuk';
    }
}

// Add input animations
document.querySelectorAll('.input-field').forEach(input => {
    input.addEventListener('focus', function() {
        this.parentElement.classList.add('transform', 'scale-105');
    });
    
    input.addEventListener('blur', function() {
        this.parentElement.classList.remove('transform', 'scale-105');
    });
});
