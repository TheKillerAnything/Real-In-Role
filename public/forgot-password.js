
document.addEventListener('DOMContentLoaded', function() {
    const forgotPasswordForm = document.getElementById('forgotPasswordForm');
    const errorMsg = document.getElementById('errorMsg');
    const successMsg = document.getElementById('successMsg');
    const errorText = document.getElementById('errorText');
    const successText = document.getElementById('successText');
    const forgotBtn = document.getElementById('forgotBtn');
    
    forgotPasswordForm.addEventListener('submit', handleForgotPassword);
});

async function handleForgotPassword(e) {
    e.preventDefault();
    
    const email = document.getElementById('email').value;
    
    if (!email) {
        showError('Email harus diisi');
        return;
    }
    
    setLoading(true);
    hideMessages();
    
    try {
        const response = await fetch('/api/auth/forgot-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess(data.message + ' Silakan cek email Anda atau cek dibagian SPAM.');
            forgotPasswordForm.reset();
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
    const forgotBtn = document.getElementById('forgotBtn');
    const spinner = forgotBtn.querySelector('.loading-spinner');
    const text = forgotBtn.querySelector('span');
    
    if (loading) {
        forgotBtn.disabled = true;
        forgotBtn.classList.add('opacity-75', 'cursor-not-allowed');
        spinner.classList.remove('hidden');
        text.textContent = 'Mengirim...';
    } else {
        forgotBtn.disabled = false;
        forgotBtn.classList.remove('opacity-75', 'cursor-not-allowed');
        spinner.classList.add('hidden');
        text.textContent = 'Kirim Email Reset';
    }
}
