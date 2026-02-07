document.addEventListener('DOMContentLoaded', () => {
    // Create cursor elements
    const cursor = document.createElement('div');
    cursor.id = 'custom-cursor';
    const cursorDot = document.createElement('div');
    cursorDot.id = 'custom-cursor-dot';

    document.body.appendChild(cursor);
    document.body.appendChild(cursorDot);

    // Inject CSS
    const style = document.createElement('style');
    style.textContent = `
        body {
            cursor: none; /* Hide default cursor */
        }
        
        #custom-cursor {
            position: fixed;
            top: 0;
            left: 0;
            width: 40px;
            height: 40px;
            border: 1px solid rgba(0, 151, 54, 0.5);
            border-radius: 50%;
            pointer-events: none;
            z-index: 9999;
            transform: translate(-50%, -50%);
            transition: width 0.3s, height 0.3s, background-color 0.3s, border-color 0.3s;
            mix-blend-mode: difference;
        }

        #custom-cursor-dot {
            position: fixed;
            top: 0;
            left: 0;
            width: 8px;
            height: 8px;
            background-color: #009736;
            border-radius: 50%;
            pointer-events: none;
            z-index: 10000;
            transform: translate(-50%, -50%);
            box-shadow: 0 0 10px rgba(0, 151, 54, 0.8);
        }

        /* Hover effect */
        body.hovering #custom-cursor {
            width: 60px;
            height: 60px;
            background-color: rgba(0, 151, 54, 0.1);
            border-color: #ce1126; /* Red border on hover */
        }
        
        body.hovering #custom-cursor-dot {
            background-color: #ce1126;
            transform: translate(-50%, -50%) scale(1.5);
        }

        /* Hide on mobile */
        @media (max-width: 768px) {
            #custom-cursor, #custom-cursor-dot {
                display: none;
            }
            body {
                cursor: auto;
            }
        }
    `;
    document.head.appendChild(style);

    // Mouse movement
    document.addEventListener('mousemove', (e) => {
        // Dot follows instantly
        cursorDot.style.left = e.clientX + 'px';
        cursorDot.style.top = e.clientY + 'px';
        
        // Circle follows with slight delay (handled by requestAnimationFrame for smoothness, or just simple timeout/css transition)
        // For simple CSS based following with transition, we set coords directly but transition property handles the lag.
        // However, delay is better with JS. Let's stick to direct update with CSS transition doing the smoothing.
        // Or better, let's do JS animation for the outer circle for "magnetic" feel or smooth trailing.
        
        cursor.style.left = e.clientX + 'px';
        cursor.style.top = e.clientY + 'px';
    });

    // Hover effects
    const interactiveElements = document.querySelectorAll('a, button, input, textarea, select, .btn, label, [role="button"]');
    
    interactiveElements.forEach(el => {
        el.addEventListener('mouseenter', () => document.body.classList.add('hovering'));
        el.addEventListener('mouseleave', () => document.body.classList.remove('hovering'));
    });
    
    // Observer for dynamic content (like loaded via JS)
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.addedNodes.length) {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1) { // Element node
                        const newInteractive = node.querySelectorAll ? node.querySelectorAll('a, button, input, textarea, select') : [];
                        if (node.matches && node.matches('a, button, input, textarea, select')) {
                            addHoverListeners(node);
                        }
                        newInteractive.forEach(addHoverListeners);
                    }
                });
            }
        });
    });
    
    observer.observe(document.body, { childList: true, subtree: true });
    
    function addHoverListeners(el) {
        el.addEventListener('mouseenter', () => document.body.classList.add('hovering'));
        el.addEventListener('mouseleave', () => document.body.classList.remove('hovering'));
    }

    // Click effect
    document.addEventListener('mousedown', () => {
        cursor.style.transform = 'translate(-50%, -50%) scale(0.8)';
        cursorDot.style.transform = 'translate(-50%, -50%) scale(0.5)';
    });

    document.addEventListener('mouseup', () => {
        cursor.style.transform = 'translate(-50%, -50%) scale(1)';
        cursorDot.style.transform = 'translate(-50%, -50%) scale(1)';
        if(document.body.classList.contains('hovering')) {
             cursorDot.style.transform = 'translate(-50%, -50%) scale(1.5)';
        }
    });
});
