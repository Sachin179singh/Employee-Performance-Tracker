class ChatManager {
    constructor(options) {
        this.messageContainer = document.getElementById(options.containerId);
        this.messageForm = document.getElementById(options.formId);
        this.messageInput = document.getElementById(options.inputId);
        this.otherUserId = options.otherUserId;
        this.lastMessageId = options.lastMessageId || 0;
        this.checkInterval = options.checkInterval || 5000; // Default 5 seconds
        this.sendingMessage = false;
        this.setupTypingIndicator();

        this.initializeEventListeners();
        this.startMessageChecking();
    }

    setupTypingIndicator() {
        this.typingIndicator = document.createElement('div');
        this.typingIndicator.className = 'typing-indicator d-none';
        this.typingIndicator.innerHTML = `
            <span></span>
            <span></span>
            <span></span>
        `;
        this.messageContainer.appendChild(this.typingIndicator);
    }

    showTypingIndicator() {
        this.typingIndicator.classList.remove('d-none');
        this.scrollToBottom();
    }

    hideTypingIndicator() {
        this.typingIndicator.classList.add('d-none');
    }

    async sendMessage() {
        const content = this.messageInput.value.trim();
        const attachments = Array.from(document.querySelectorAll('#attachments .file-attachment'))
            .map(el => el.dataset.filename);
            
        if (!content && attachments.length === 0) return;
        if (this.sendingMessage) return;

        this.sendingMessage = true;
        this.messageForm.querySelector('button').disabled = true;
        
        try {
            const formData = new FormData();
            formData.append('content', content);
            attachments.forEach(filename => formData.append('attachments[]', filename));

            const response = await fetch(`/api/send_message/${this.otherUserId}`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) throw new Error('Failed to send message');
            
            const data = await response.json();
            
            // Clear attachments
            document.getElementById('attachments').innerHTML = '';
            
            this.messageInput.value = '';
            this.messageInput.style.height = 'auto';
            this.lastMessageId = data.id;
            
            // Append the message to the chat
            this.appendMessage(data, true);
        } catch (error) {
            console.error('Error sending message:', error);
            alert('Failed to send message. Please try again.');
        } finally {
            this.sendingMessage = false;
            this.messageForm.querySelector('button').disabled = false;
        }
    }

    appendMessage(message, isOwn = false) {
        const attachmentsHtml = message.attachments ? message.attachments.map(att => `
            <div class="message-attachment">
                <a href="/static/attachments/${att.filename}" target="_blank" class="text-${isOwn ? 'white' : 'dark'}">
                    <i class="fas ${this.getFileIcon(att.file_type)}"></i>
                    <span>${att.original_name}</span>
                    <small class="text-muted">(${this.formatFileSize(att.file_size)})</small>
                </a>
            </div>
        `).join('') : '';

        const messageHtml = `
            <div class="message mb-3 ${isOwn ? 'text-right' : ''}" data-message-id="${message.id}">
                <div class="message-bubble d-inline-block p-2 rounded ${isOwn ? 'bg-primary text-white' : 'bg-light'}" 
                     style="max-width: 70%;">
                    <div class="message-content">
                        ${message.content}
                        ${attachmentsHtml}
                    </div>
                    <div class="message-info d-flex align-items-center justify-content-between">
                        <small class="text-muted">
                            ${new Date(message.timestamp).toLocaleString('en-US', {
                                hour: 'numeric',
                                minute: 'numeric',
                                hour12: true
                            })}
                        </small>
                        ${isOwn ? `
                            <small class="message-status ml-2" title="${message.status === 'sending' ? 'Sending...' : 'Sent'}">
                                <i class="fas fa-${message.status === 'sending' ? 'clock' : 'check'}"></i>
                            </small>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
        
        this.messageContainer.insertAdjacentHTML('beforeend', messageHtml);
        this.scrollToBottom();
    }

    getFileIcon(fileType) {
        const icons = {
            'image': 'fa-image',
            'video': 'fa-video',
            'audio': 'fa-music',
            'application/pdf': 'fa-file-pdf',
            'application/msword': 'fa-file-word',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'fa-file-word',
            'application/vnd.ms-excel': 'fa-file-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'fa-file-excel',
            'text/plain': 'fa-file-alt'
        };

        for (const [type, icon] of Object.entries(icons)) {
            if (fileType.startsWith(type)) return icon;
        }

        return 'fa-file';
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    scrollToBottom() {
        this.messageContainer.scrollTop = this.messageContainer.scrollHeight;
    }

    async checkNewMessages() {
        try {
            const response = await fetch(`/api/messages/${this.otherUserId}?after=${this.lastMessageId}`);
            const data = await response.json();
            
            if (data.messages && data.messages.length > 0) {
                data.messages.forEach(message => {
                    this.appendMessage(message, message.sender_id === this.currentUserId);
                    this.lastMessageId = Math.max(this.lastMessageId, message.id);
                });
            }
        } catch (error) {
            console.error('Error checking messages:', error);
        }
    }

    startMessageChecking() {
        this.messageCheckInterval = setInterval(() => {
            this.checkNewMessages();
        }, this.checkInterval);
    }

    stopMessageChecking() {
        if (this.messageCheckInterval) {
            clearInterval(this.messageCheckInterval);
        }
    }
}

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    const chatManager = window.chatManager;
    if (chatManager) {
        if (document.hidden) {
            chatManager.stopMessageChecking();
        } else {
            chatManager.startMessageChecking();
        }
    }
});