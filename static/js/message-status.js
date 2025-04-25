class MessageStatusHandler {
    constructor() {
        this.statusCheckInterval = null;
        this.lastStatusCheck = new Date();
    }

    init(currentUserId) {
        this.currentUserId = currentUserId;
        this.startStatusChecking();
    }

    async checkMessageStatuses() {
        try {
            const response = await fetch(`/api/message_statuses?since=${this.lastStatusCheck.toISOString()}`);
            const data = await response.json();
            
            if (data.updates) {
                this.updateMessageStatuses(data.updates);
            }
            
            this.lastStatusCheck = new Date();
        } catch (error) {
            console.error('Error checking message statuses:', error);
        }
    }

    updateMessageStatuses(updates) {
        updates.forEach(update => {
            const messageEl = document.querySelector(`[data-message-id="${update.message_id}"]`);
            if (!messageEl) return;

            const statusEl = messageEl.querySelector('.message-status');
            if (!statusEl) return;

            if (update.read) {
                statusEl.innerHTML = '<i class="fas fa-check-double text-info"></i>';
                statusEl.title = 'Read';
            } else if (update.delivered) {
                statusEl.innerHTML = '<i class="fas fa-check-double"></i>';
                statusEl.title = 'Delivered';
            }
        });
    }

    startStatusChecking() {
        this.statusCheckInterval = setInterval(() => {
            this.checkMessageStatuses();
        }, 5000); // Check every 5 seconds
    }

    stopStatusChecking() {
        if (this.statusCheckInterval) {
            clearInterval(this.statusCheckInterval);
            this.statusCheckInterval = null;
        }
    }
}