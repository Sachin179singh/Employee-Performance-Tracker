class ChatManager {
    constructor(config) {
        this.container = document.getElementById(config.containerId);
        this.form = document.getElementById(config.formId);
        this.input = document.getElementById(config.inputId);
        this.otherUserId = config.otherUserId;
        this.lastMessageId = config.lastMessageId;
        this.currentUserId = config.currentUserId;
        this.checkInterval = config.checkInterval || 3000;
        this.typingTimeout = null;
        this.isTyping = false;

        this.initializeEventListeners();
        this.startPolling();
        this.scrollToBottom();
    }

    initializeEventListeners() {
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        this.input.addEventListener('input', () => this.handleTyping());
    }

    async handleSubmit(e) {
        e.preventDefault();
        const content = this.input.value.trim();
        if (!content) return;

        const formData = new FormData();
        formData.append('content', content);
        formData.append('recipient_id', this.otherUserId);

        // Add any file attachments
        const fileInput = document.getElementById('fileInput');
        if (fileInput.files.length > 0) {
            Array.from(fileInput.files).forEach(file => {
                formData.append('attachments[]', file);
            });
        }

        try {
            const response = await fetch('/send_message', {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                const message = await response.json();
                this.appendMessage(message);
                this.input.value = '';
                document.getElementById('attachments').innerHTML = '';
                fileInput.value = '';
                this.scrollToBottom();
            }
        } catch (error) {
            console.error('Error sending message:', error);
        }
    }

    handleTyping() {
        if (!this.isTyping) {
            this.isTyping = true;
            fetch('/typing', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recipient_id: this.otherUserId })
            });
        }

        clearTimeout(this.typingTimeout);
        this.typingTimeout = setTimeout(() => {
            this.isTyping = false;
            fetch('/stop_typing', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recipient_id: this.otherUserId })
            });
        }, 1000);
    }

    startPolling() {
        setInterval(() => this.checkNewMessages(), this.checkInterval);
        setInterval(() => this.checkTypingStatus(), 1000);
    }

    async checkNewMessages() {
        try {
            const response = await fetch(`/get_new_messages/${this.otherUserId}/${this.lastMessageId}`);
            if (response.ok) {
                const messages = await response.json();
                messages.forEach(message => {
                    this.appendMessage(message);
                    this.lastMessageId = Math.max(this.lastMessageId, message.id);
                });
            }
        } catch (error) {
            console.error('Error checking new messages:', error);
        }
    }

    async checkTypingStatus() {
        try {
            const response = await fetch(`/typing_status/${this.otherUserId}`);
            if (response.ok) {
                const { is_typing } = await response.json();
                const typingStatus = document.querySelector('.typing-status');
                typingStatus.style.display = is_typing ? 'block' : 'none';
            }
        } catch (error) {
            console.error('Error checking typing status:', error);
        }
    }

    appendMessage(message) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${message.sender_id === this.currentUserId ? 'text-right' : ''}`;
        messageDiv.dataset.messageId = message.id;

        // Create message HTML
        messageDiv.innerHTML = `
            <div class="message-bubble d-inline-block">
                <div class="message-content">
                    ${message.content}
                    ${this.renderAttachments(message.attachments)}
                </div>
                <div class="message-reactions"></div>
                <div class="message-info d-flex align-items-center justify-content-between">
                    <small class="text-${message.sender_id === this.currentUserId ? 'white-50' : 'muted'}">
                        ${new Date(message.timestamp).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}
                    </small>
                    ${this.renderMessageControls(message)}
                </div>
            </div>
        `;

        this.container.appendChild(messageDiv);
        this.scrollToBottom();
    }

    renderAttachments(attachments) {
        if (!attachments || attachments.length === 0) return '';
        
        return attachments.map(attachment => `
            <div class="message-attachment">
                <a href="/static/attachments/${attachment.filename}" 
                   target="_blank" 
                   class="text-${attachment.sender_id === this.currentUserId ? 'white' : 'dark'}">
                    <i class="fas ${this.getFileIcon(attachment.file_type)}"></i>
                    <span>${attachment.filename.split('_', 1)[1]}</span>
                    <small class="text-muted">(${this.formatFileSize(attachment.file_size)})</small>
                </a>
            </div>
        `).join('');
    }

    renderMessageControls(message) {
        if (message.sender_id === this.currentUserId) {
            return `
                <small class="message-status ml-2" title="${message.read ? 'Read' : 'Delivered'}">
                    <i class="fas fa-check${message.read ? '-double' : ''}"></i>
                </small>
            `;
        } else {
            return `<div class="emoji-picker" data-message-id="${message.id}"></div>`;
        }
    }

    getFileIcon(fileType) {
        const icons = {
            'image': 'fa-image',
            'pdf': 'fa-file-pdf',
            'word': 'fa-file-word',
            'excel': 'fa-file-excel',
            'text': 'fa-file-alt'
        };

        for (const [type, icon] of Object.entries(icons)) {
            if (fileType.includes(type)) return icon;
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
        this.container.scrollTop = this.container.scrollHeight;
    }
}