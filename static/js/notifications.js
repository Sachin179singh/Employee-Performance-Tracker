class NotificationManager {
    constructor(checkInterval = 10000) { // Default 10 seconds
        this.checkInterval = checkInterval;
        this.lastCheck = new Date();
        this.init();
    }

    init() {
        this.startChecking();
        this.handleVisibilityChange();
    }

    async checkNewMessages() {
        try {
            const response = await fetch('/api/check_notifications');
            const data = await response.json();
            
            if (data.unread_count > 0) {
                this.updateBadge(data.unread_count);
                if (data.new_messages) {
                    this.showNotification(data.new_messages);
                }
            }
        } catch (error) {
            console.error('Error checking notifications:', error);
        }
    }

    updateBadge(count) {
        const badge = document.querySelector('.nav-messages-badge');
        if (badge) {
            badge.textContent = count;
            badge.style.display = count > 0 ? 'inline' : 'none';
        }
    }

    showNotification(messages) {
        if (!("Notification" in window)) {
            return;
        }

        if (Notification.permission === "granted" && !document.hidden) {
            messages.forEach(msg => {
                new Notification("New Message", {
                    body: `${msg.sender_name}: ${msg.content.substring(0, 50)}...`,
                    icon: "/static/assets/img/favicon.png"
                });
            });
        } else if (Notification.permission !== "denied") {
            Notification.requestPermission();
        }
    }

    startChecking() {
        this.checkInterval = setInterval(() => {
            this.checkNewMessages();
        }, this.checkInterval);
    }

    stopChecking() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
        }
    }

    handleVisibilityChange() {
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.stopChecking();
            } else {
                this.checkNewMessages();
                this.startChecking();
            }
        });
    }
}

// Initialize notifications when the document is ready
document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelector('.nav-messages-badge')) {
        window.notificationManager = new NotificationManager();
    }
});