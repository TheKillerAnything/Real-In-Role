
document.addEventListener('DOMContentLoaded', function() {
    const resetPasswordForm = document.getElementById('resetPasswordForm');
    const errorMsg = document.getElementById('errorMsg');
    const successMsg = document.getElementById('successMsg');
    const errorText = document.getElementById('errorText');
    const successText = document.getElementById('successText');
    const resetBtn = document.getElementById('resetBtn');
    
    // Get token from URL
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    
    if (!token) {
        showError('Token reset tidak valid');
        setTimeout(() => {
            window.location.href = '/forgot-password';
        }, 3000);
        return;
    }
    
    resetPasswordForm.addEventListener('submit', handleResetPassword);
});

async function handleResetPassword(e) {
    e.preventDefault();
    
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    if (!newPassword || !confirmPassword) {
        showError('Harap isi password baru dan konfirmasi');
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
    
    setLoading(true);
    hideMessages();
    
    try {
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');
        
        const response = await fetch('/api/auth/reset-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token, newPassword })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess(data.message);
            setTimeout(() => {
                window.location.href = '/login';
            }, 3000);
        } else {
            showError(data.error || 'Terjadi kesalahan');
        }
    } catch (error) {
        showError('Terjadi kesalahan koneksi');
    } finally {
        setLoading(false);
    }
}

function showError(message) {
    hideMessages();
    const errorMsg = document.getElementById('errorMsg');
    const errorText = document.getElementById('errorText');
    errorText.textContent = message;
    errorMsg.classList.remove('hidden');
    errorMsg.classList.add('animate-pulse');
    
    setTimeout(() => {
        errorMsg.classList.remove('animate-pulse');
    }, 500);
}

function showSuccess(message) {
    hideMessages();
    const successMsg = document.getElementById('successMsg');
    const successText = document.getElementById('successText');
    successText.textContent = message;
    successMsg.classList.remove('hidden');
    successMsg.classList.add('animate-pulse');
    
    setTimeout(() => {
        successMsg.classList.remove('animate-pulse');
    }, 500);
}

function hideMessages() {
    const errorMsg = document.getElementById('errorMsg');
    const successMsg = document.getElementById('successMsg');
    if (errorMsg) errorMsg.classList.add('hidden');
    if (successMsg) successMsg.classList.add('hidden');
}

function setLoading(loading) {
    const resetBtn = document.getElementById('resetBtn');
    const spinner = resetBtn.querySelector('.loading-spinner');
    const text = resetBtn.querySelector('span');
    
    if (loading) {
        resetBtn.disabled = true;
        resetBtn.classList.add('opacity-75', 'cursor-not-allowed');
        if (spinner) spinner.classList.remove('hidden');
        if (text) text.textContent = 'Memproses...';
    } else {
        resetBtn.disabled = false;
        resetBtn.classList.remove('opacity-75', 'cursor-not-allowed');
        if (spinner) spinner.classList.add('hidden');
        if (text) text.textContent = 'Reset Password';
    }
}

async function handleResetPassword(e) {
    e.preventDefault();
    
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    if (!newPassword || !confirmPassword) {
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
    
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    
    setLoading(true);
    hideMessages();
    
    try {
        const response = await fetch('/api/auth/reset-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                token,
                newPassword
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess(data.message + ' Mengalihkan ke login...');
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        } else {
            showError(data.error || 'Terjadi kesalahan');
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
    const resetBtn = document.getElementById('resetBtn');
    const spinner = resetBtn.querySelector('.loading-spinner');
    const text = resetBtn.querySelector('span');
    
    if (loading) {
        resetBtn.disabled = true;
        resetBtn.classList.add('opacity-75', 'cursor-not-allowed');
        spinner.classList.remove('hidden');
        text.textContent = 'Mereset...';
    } else {
        resetBtn.disabled = false;
        resetBtn.classList.remove('opacity-75', 'cursor-not-allowed');
        spinner.classList.add('hidden');
        text.textContent = 'Reset Password';
    }
}
