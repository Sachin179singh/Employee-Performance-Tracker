class EmojiReactionHandler {
    constructor() {
        this.setupEventListeners();
    }

    setupEventListeners() {
        // Handle emoji picker toggle
        document.addEventListener('click', (e) => {
            const toggleBtn = e.target.closest('[data-toggle="emoji-picker"]');
            if (toggleBtn) {
                const picker = toggleBtn.nextElementSibling;
                this.togglePicker(picker);
            } else if (!e.target.closest('.emoji-picker-popup')) {
                // Close all pickers when clicking outside
                document.querySelectorAll('.emoji-picker-popup').forEach(picker => {
                    picker.style.display = 'none';
                });
            }
        });

        // Handle emoji selection
        document.addEventListener('click', async (e) => {
            const emojiBtn = e.target.closest('.emoji-btn');
            if (emojiBtn) {
                const messageId = emojiBtn.dataset.messageId;
                const emoji = emojiBtn.dataset.emoji;
                await this.handleReaction(messageId, emoji);
                
                // Close the picker
                const picker = emojiBtn.closest('.emoji-picker-popup');
                if (picker) {
                    picker.style.display = 'none';
                }
            }
        });
    }

    togglePicker(picker) {
        const isVisible = picker.style.display !== 'none';
        // Hide all other pickers first
        document.querySelectorAll('.emoji-picker-popup').forEach(p => {
            p.style.display = 'none';
        });
        // Toggle current picker
        picker.style.display = isVisible ? 'none' : 'block';
    }

    async handleReaction(messageId, emoji) {
        try {
            const response = await fetch(`/api/messages/${messageId}/react`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `emoji=${encodeURIComponent(emoji)}`
            });

            if (!response.ok) throw new Error('Failed to add reaction');
            
            const data = await response.json();
            this.updateReactionsUI(messageId, data);
        } catch (error) {
            console.error('Error handling reaction:', error);
            alert('Failed to add reaction. Please try again.');
        }
    }

    updateReactionsUI(messageId, data) {
        const messageEl = document.querySelector(`[data-message-id="${messageId}"]`);
        if (!messageEl) return;

        const reactionsContainer = messageEl.querySelector('.message-reactions');
        if (data.status === 'removed') {
            // Remove reaction if it exists
            const reactionEl = reactionsContainer.querySelector(`[data-emoji="${data.emoji}"]`);
            if (reactionEl) {
                const count = parseInt(reactionEl.dataset.count) - 1;
                if (count <= 0) {
                    reactionEl.remove();
                } else {
                    reactionEl.dataset.count = count;
                    reactionEl.textContent = `${data.emoji} ${count}`;
                }
            }
        } else {
            // Add new reaction
            if (!reactionsContainer) {
                const newContainer = document.createElement('div');
                newContainer.className = 'message-reactions';
                messageEl.querySelector('.message-bubble').appendChild(newContainer);
            }
            
            const existingReaction = reactionsContainer.querySelector(`[data-emoji="${data.reaction.emoji}"]`);
            if (existingReaction) {
                const count = parseInt(existingReaction.dataset.count) + 1;
                existingReaction.dataset.count = count;
                existingReaction.textContent = `${data.reaction.emoji} ${count}`;
            } else {
                const reactionEl = document.createElement('div');
                reactionEl.className = 'reaction-badge';
                reactionEl.dataset.emoji = data.reaction.emoji;
                reactionEl.dataset.count = '1';
                reactionEl.title = data.reaction.user_name;
                reactionEl.textContent = `${data.reaction.emoji} 1`;
                reactionsContainer.appendChild(reactionEl);
            }
        }
    }
}