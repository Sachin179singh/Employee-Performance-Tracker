class FileUploadHandler {
    constructor(config) {
        this.dropZone = document.getElementById(config.dropZoneId);
        this.fileInput = document.getElementById(config.fileInputId);
        this.messageInput = document.getElementById(config.messageInputId);
        this.maxFileSize = config.maxFileSize;
        this.allowedTypes = config.allowedTypes;
        this.attachments = [];

        this.initializeEventListeners();
    }

    initializeEventListeners() {
        this.dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            this.dropZone.classList.add('drag-over');
        });

        this.dropZone.addEventListener('dragleave', () => {
            this.dropZone.classList.remove('drag-over');
        });

        this.dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            this.dropZone.classList.remove('drag-over');
            const files = e.dataTransfer.files;
            this.handleFiles(files);
        });

        this.fileInput.addEventListener('change', () => {
            this.handleFiles(this.fileInput.files);
        });
    }

    handleFiles(files) {
        Array.from(files).forEach(file => {
            if (this.validateFile(file)) {
                this.attachments.push(file);
                this.displayAttachment(file);
            }
        });
    }

    validateFile(file) {
        if (file.size > this.maxFileSize) {
            alert(`File ${file.name} is too large. Maximum size is ${this.maxFileSize / 1024 / 1024}MB`);
            return false;
        }

        const isAllowedType = this.allowedTypes.some(type => {
            if (type.endsWith('/*')) {
                return file.type.startsWith(type.replace('/*', ''));
            }
            return file.type === type;
        });

        if (!isAllowedType) {
            alert(`File type ${file.type} is not allowed`);
            return false;
        }

        return true;
    }

    displayAttachment(file) {
        const attachmentsContainer = document.getElementById('attachments');
        const attachment = document.createElement('div');
        attachment.className = 'attachment-preview';
        
        const icon = document.createElement('i');
        icon.className = `fas ${this.getFileIcon(file.type)}`;
        
        const name = document.createElement('span');
        name.textContent = file.name;
        
        const removeBtn = document.createElement('button');
        removeBtn.className = 'btn btn-sm btn-danger';
        removeBtn.innerHTML = '&times;';
        removeBtn.onclick = () => {
            this.attachments = this.attachments.filter(f => f !== file);
            attachment.remove();
        };

        attachment.appendChild(icon);
        attachment.appendChild(name);
        attachment.appendChild(removeBtn);
        attachmentsContainer.appendChild(attachment);
    }

    getFileIcon(type) {
        if (type.startsWith('image/')) return 'fa-image';
        if (type === 'application/pdf') return 'fa-file-pdf';
        if (type.startsWith('text/')) return 'fa-file-alt';
        return 'fa-file';
    }
}