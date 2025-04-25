class EmojiReactionHandler {
    constructor() {
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        document.addEventListener('click', (e) => {
            if (e.target.matches('.emoji-picker-toggle')) {
                this.toggleEmojiPicker(e.target);
            } else if (e.target.matches('.emoji-btn')) {
                this.handleEmojiSelection(e.target);
            } else if (!e.target.closest('.emoji-picker')) {
                this.closeAllPickers();
            }
        });
    }

    toggleEmojiPicker(toggleBtn) {
        const picker = toggleBtn.closest('.emoji-picker').querySelector('.emoji-picker-popup');
        this.closeAllPickers();
        picker.style.display = picker.style.display === 'none' ? 'block' : 'none';
    }

    closeAllPickers() {
        document.querySelectorAll('.emoji-picker-popup').forEach(picker => {
            picker.style.display = 'none';
        });
    }

    async handleEmojiSelection(btn) {
        const messageId = btn.dataset.messageId;
        const emoji = btn.dataset.emoji;

        try {
            const response = await fetch('/react_to_message', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    message_id: messageId,
                    emoji: emoji
                })
            });

            if (response.ok) {
                const { reactions } = await response.json();
                this.updateReactions(messageId, reactions);
            }
        } catch (error) {
            console.error('Error adding reaction:', error);
        }

        this.closeAllPickers();
    }

    updateReactions(messageId, reactions) {
        const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
        if (!messageElement) return;

        const reactionsContainer = messageElement.querySelector('.message-reactions');
        if (!reactionsContainer) return;

        // Group reactions by emoji
        const groupedReactions = reactions.reduce((acc, reaction) => {
            if (!acc[reaction.emoji]) {
                acc[reaction.emoji] = [];
            }
            acc[reaction.emoji].push(reaction);
            return acc;
        }, {});

        // Create reaction badges HTML
        const badgesHtml = Object.entries(groupedReactions).map(([emoji, reactionsList]) => `
            <div class="reaction-badge" 
                 title="${reactionsList.map(r => r.user.name).join(', ')}"
                 data-emoji="${emoji}">
                ${emoji} ${reactionsList.length}
            </div>
        `).join('');

        reactionsContainer.innerHTML = badgesHtml;
    }
}