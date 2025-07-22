
document.addEventListener('DOMContentLoaded', function() {
    const registerForm = document.getElementById('registerForm');
    const errorMsg = document.getElementById('errorMsg');
    const successMsg = document.getElementById('successMsg');
    const errorText = document.getElementById('errorText');
    const successText = document.getElementById('successText');
    const registerBtn = document.getElementById('registerBtn');
    
    registerForm.addEventListener('submit', handleRegister);
});

async function handleRegister(e) {
    e.preventDefault();
    
    const fullName = document.getElementById('fullName').value;
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    // Validasi
    if (!fullName || !username || !email || !password || !confirmPassword) {
        showError('Semua field harus diisi');
        return;
    }
    
    if (password !== confirmPassword) {
        showError('Password dan konfirmasi password tidak cocok');
        return;
    }
    
    if (password.length < 6) {
        showError('Password minimal 6 karakter');
        return;
    }
    
    setLoading(true);
    hideMessages();
    
    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                fullName, 
                username, 
                email, 
                password 
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess(data.message);
            registerForm.reset();
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        } else {
            showError(data.error || 'Registrasi gagal');
        }
    } catch (error) {
        showError('Terjadi kesalahan koneksi');
    } finally {
        setLoading(false);
    }
}

function showError(message) {
    hideMessages();
    errorText.textContent = message;
    errorMsg.classList.remove('hidden');
    errorMsg.classList.add('animate-pulse');
    
    setTimeout(() => {
        errorMsg.classList.remove('animate-pulse');
    }, 500);
}

function showSuccess(message) {
    hideMessages();
    successText.textContent = message;
    successMsg.classList.remove('hidden');
    successMsg.classList.add('animate-pulse');
    
    setTimeout(() => {
        successMsg.classList.remove('animate-pulse');
    }, 500);
}

function hideMessages() {
    errorMsg.classList.add('hidden');
    successMsg.classList.add('hidden');
}

function setLoading(loading) {
    const registerBtn = document.getElementById('registerBtn');
    const spinner = registerBtn.querySelector('.loading-spinner');
    const text = registerBtn.querySelector('span');
    
    if (loading) {
        registerBtn.disabled = true;
        registerBtn.classList.add('opacity-75', 'cursor-not-allowed');
        spinner.classList.remove('hidden');
        text.textContent = 'Mendaftar...';
    } else {
        registerBtn.disabled = false;
        registerBtn.classList.remove('opacity-75', 'cursor-not-allowed');
        spinner.classList.add('hidden');
        text.textContent = 'Daftar';
    }
}
