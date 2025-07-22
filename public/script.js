
// Main script for index page
document.addEventListener('DOMContentLoaded', function() {
    // Check if user is already logged in
    checkAuthStatus();
    
    // Add smooth animations
    addSmoothAnimations();
    
    // Background music control
    setupAudioControl();
});

async function checkAuthStatus() {
    try {
        const response = await fetch('/api/auth/check');
        const data = await response.json();
        
        if (data.loggedIn) {
            // User is logged in, offer to go to deploy page
            showLoggedInState(data.username);
        }
    } catch (error) {
        console.log('Auth check failed:', error);
    }
}

function showLoggedInState(username) {
    const mainButton = document.querySelector('.btn-primary');
    if (mainButton) {
        mainButton.innerHTML = `
            <i class="fas fa-rocket mr-2"></i>
            Lanjut ke Deploy (${username})
        `;
        mainButton.onclick = () => window.location.href = '/deploy';
    }
}

function addSmoothAnimations() {
    // Add staggered animation to feature cards
    const featureCards = document.querySelectorAll('.feature-card');
    featureCards.forEach((card, index) => {
        card.style.animationDelay = `${index * 0.2}s`;
        card.classList.add('fade-in');
    });
}

function setupAudioControl() {
    const audio = document.getElementById('bgMusic');
    if (audio) {
        // Create audio control button
        const audioBtn = document.createElement('button');
        audioBtn.innerHTML = '<i class="fas fa-volume-up"></i>';
        audioBtn.className = 'fixed top-4 right-4 bg-white/20 text-white p-3 rounded-full backdrop-blur-lg hover:bg-white/30 transition-all duration-300 z-50';
        audioBtn.onclick = toggleAudio;
        document.body.appendChild(audioBtn);
        
        // Set initial volume
        audio.volume = 0.3;
    }
}

function toggleAudio() {
    const audio = document.getElementById('bgMusic');
    const btn = document.querySelector('.fixed.top-4.right-4');
    
    if (audio.paused) {
        audio.play();
        btn.innerHTML = '<i class="fas fa-volume-up"></i>';
    } else {
        audio.pause();
        btn.innerHTML = '<i class="fas fa-volume-mute"></i>';
    }
}

// Add fade-in animation CSS
const style = document.createElement('style');
style.textContent = `
    .fade-in {
        opacity: 0;
        transform: translateY(20px);
        animation: fadeInUp 0.6s ease-out forwards;
    }
    
    @keyframes fadeInUp {
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
`;
document.head.appendChild(style);
