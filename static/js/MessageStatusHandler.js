class MessageStatusHandler {
    constructor() {
        this.currentUserId = null;
        this.observerConfig = {
            root: document.getElementById('messageContainer'),
            rootMargin: '0px',
            threshold: 0.5
        };
    }

    init(currentUserId) {
        this.currentUserId = currentUserId;
        this.setupIntersectionObserver();
        this.startStatusPolling();
    }

    setupIntersectionObserver() {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const messageElement = entry.target;
                    const messageId = messageElement.dataset.messageId;
                    if (messageElement.classList.contains('message') && 
                        !messageElement.classList.contains('text-right')) {
                        this.markAsRead(messageId);
                    }
                }
            });
        }, this.observerConfig);

        // Observe all incoming messages
        document.querySelectorAll('.message:not(.text-right)').forEach(message => {
            observer.observe(message);
        });

        // Setup mutation observer to watch for new messages
        const messageContainer = document.getElementById('messageContainer');
        const mutationObserver = new MutationObserver((mutations) => {
            mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                    if (node.classList && 
                        node.classList.contains('message') && 
                        !node.classList.contains('text-right')) {
                        observer.observe(node);
                    }
                });
            });
        });

        mutationObserver.observe(messageContainer, {
            childList: true,
            subtree: true
        });
    }

    async markAsRead(messageId) {
        try {
            await fetch('/mark_message_read', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message_id: messageId })
            });
        } catch (error) {
            console.error('Error marking message as read:', error);
        }
    }

    startStatusPolling() {
        setInterval(() => this.updateMessageStatuses(), 5000);
    }

    async updateMessageStatuses() {
        try {
            const response = await fetch('/get_message_statuses');
            if (response.ok) {
                const statuses = await response.json();
                this.updateStatusIndicators(statuses);
            }
        } catch (error) {
            console.error('Error updating message statuses:', error);
        }
    }

    updateStatusIndicators(statuses) {
        statuses.forEach(status => {
            const messageElement = document.querySelector(`[data-message-id="${status.message_id}"]`);
            if (messageElement && messageElement.classList.contains('text-right')) {
                const statusIndicator = messageElement.querySelector('.message-status i');
                if (statusIndicator) {
                    statusIndicator.className = `fas fa-check${status.read ? '-double' : ''}`;
                    statusIndicator.parentElement.title = status.read ? 'Read' : 'Delivered';
                }
            }
        });
    }
}