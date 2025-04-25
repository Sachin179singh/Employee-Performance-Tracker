class FileUploadHandler {
    constructor(options) {
        this.dropZone = document.getElementById(options.dropZoneId);
        this.fileInput = document.getElementById(options.fileInputId);
        this.messageInput = document.getElementById(options.messageInputId);
        this.maxFileSize = options.maxFileSize || 5 * 1024 * 1024; // 5MB default
        this.allowedTypes = options.allowedTypes || null;
        
        this.setupEventListeners();
    }

    setupEventListeners() {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            this.dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
            });
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            this.dropZone.addEventListener(eventName, () => {
                this.dropZone.classList.add('drag-active');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            this.dropZone.addEventListener(eventName, () => {
                this.dropZone.classList.remove('drag-active');
            });
        });

        this.dropZone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            this.handleFiles(files);
        });

        this.fileInput.addEventListener('change', (e) => {
            const files = e.target.files;
            this.handleFiles(files);
        });
    }

    async handleFiles(files) {
        for (const file of files) {
            if (this.validateFile(file)) {
                await this.uploadFile(file);
            }
        }
    }

    validateFile(file) {
        if (file.size > this.maxFileSize) {
            alert(`File ${file.name} is too large. Maximum size is ${this.maxFileSize / 1024 / 1024}MB`);
            return false;
        }

        if (this.allowedTypes && !this.allowedTypes.includes(file.type)) {
            alert(`File type ${file.type} is not allowed`);
            return false;
        }

        return true;
    }

    async uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch('/api/messages/upload', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) throw new Error('Upload failed');
            
            const data = await response.json();
            this.addAttachmentToMessage(data);
        } catch (error) {
            console.error('Error uploading file:', error);
            alert('Failed to upload file. Please try again.');
        }
    }

    addAttachmentToMessage(fileData) {
        const fileSize = this.formatFileSize(fileData.file_size);
        const attachmentHtml = `
            <div class="file-attachment" data-filename="${fileData.filename}">
                <i class="fas ${this.getFileIcon(fileData.file_type)}"></i>
                <span class="file-name">${fileData.original_name}</span>
                <span class="file-size">${fileSize}</span>
                <button type="button" class="btn btn-link btn-sm text-danger remove-attachment">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;

        const attachmentsContainer = document.getElementById('attachments');
        if (!attachmentsContainer.querySelector(`[data-filename="${fileData.filename}"]`)) {
            attachmentsContainer.insertAdjacentHTML('beforeend', attachmentHtml);
        }
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
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
}