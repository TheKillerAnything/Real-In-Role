
document.addEventListener('DOMContentLoaded', function() {
    // Get server data from session storage
    const serverData = sessionStorage.getItem('serverData');
    
    if (!serverData) {
        window.location.href = '/deploy';
        return;
    }
    
    const server = JSON.parse(serverData);
    displayServerInfo(server);
    
    // Add typing animation to details
    animateServerDetails();
});

function displayServerInfo(server) {
    const serverDetails = document.getElementById('serverDetails');
    
    const details = [
        { icon: 'fas fa-id-badge', label: 'Server ID', value: server.id },
        { icon: 'fas fa-user', label: 'Username', value: server.username },
        { icon: 'fas fa-key', label: 'Password', value: server.password },
        { icon: 'fas fa-globe', label: 'Host IP', value: server.ip },
        { icon: 'fas fa-plug', label: 'Port', value: server.port },
        { icon: 'fas fa-memory', label: 'RAM', value: server.ram },
        { icon: 'fas fa-microchip', label: 'CPU', value: server.cpu }
    ];
    
    serverDetails.innerHTML = details.map(detail => `
        <div class="detail-card opacity-0 transform translate-y-4">
            <div class="flex items-center">
                <i class="${detail.icon} text-blue-400 mr-3"></i>
                <span class="font-medium">${detail.label}:</span>
            </div>
            <span class="font-mono text-blue-200">${detail.value}</span>
        </div>
    `).join('');
    
    // Store server data globally for copy function
    window.serverInfo = server;
}

function animateServerDetails() {
    const details = document.querySelectorAll('.detail-card');
    
    details.forEach((detail, index) => {
        setTimeout(() => {
            detail.classList.remove('opacity-0', 'transform', 'translate-y-4');
            detail.classList.add('opacity-100');
        }, index * 200 + 500); // Start after title animation
    });
}

function copyToClipboard() {
    const server = window.serverInfo;
    
    const serverText = `
🎉 DETAIL SERVER PTERODACTYL 🎉

🆔 Server ID: ${server.id}
👤 Username: ${server.username}
🔑 Password: ${server.password}
🌐 Host IP: ${server.ip}
🔌 Port: ${server.port}
💾 RAM: ${server.ram}
⚡ CPU: ${server.cpu}

📅 Dibuat: ${new Date().toLocaleString('id-ID')}
    `.trim();
    
    navigator.clipboard.writeText(serverText).then(() => {
        showToast();
        
        // Add visual feedback to copy button
        const copyBtn = document.querySelector('.btn-success');
        const originalText = copyBtn.innerHTML;
        
        copyBtn.innerHTML = '<i class="fas fa-check mr-2"></i>Tersalin!';
        copyBtn.classList.add('bg-green-600');
        
        setTimeout(() => {
            copyBtn.innerHTML = originalText;
            copyBtn.classList.remove('bg-green-600');
        }, 2000);
    }).catch(() => {
        // Fallback for browsers that don't support clipboard API
        const textArea = document.createElement('textarea');
        textArea.value = serverText;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        
        showToast();
    });
}

function showToast() {
    const toast = document.getElementById('toast');
    toast.classList.add('show');
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

// Add particle animation effect
function createParticles() {
    const particleContainer = document.createElement('div');
    particleContainer.className = 'fixed inset-0 pointer-events-none z-0';
    document.body.appendChild(particleContainer);
    
    for (let i = 0; i < 20; i++) {
        const particle = document.createElement('div');
        particle.className = 'absolute w-2 h-2 bg-white/20 rounded-full';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.top = Math.random() * 100 + '%';
        particle.style.animation = `float ${3 + Math.random() * 4}s ease-in-out infinite`;
        particle.style.animationDelay = Math.random() * 2 + 's';
        
        particleContainer.appendChild(particle);
    }
}

// Add floating animation
const style = document.createElement('style');
style.textContent = `
    @keyframes float {
        0%, 100% { transform: translateY(0px) rotate(0deg); }
        50% { transform: translateY(-20px) rotate(180deg); }
    }
`;
document.head.appendChild(style);

// Initialize particles
createParticles();

// Clear session storage when leaving page
window.addEventListener('beforeunload', () => {
    sessionStorage.removeItem('serverData');
});
