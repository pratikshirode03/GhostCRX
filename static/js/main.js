document.addEventListener('DOMContentLoaded', function() {
    const uploadContainer = document.getElementById('uploadContainer');
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    const uploadProgress = document.getElementById('uploadProgress');
    const uploadResult = document.getElementById('uploadResult');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const resultIcon = document.getElementById('resultIcon');
    const resultTitle = document.getElementById('resultTitle');
    const resultMessage = document.getElementById('resultMessage');
    const newScanBtn = document.getElementById('newScanBtn');
    
    // Debug: Check if all elements are found
    console.log('Elements found:', {
        uploadContainer: !!uploadContainer,
        uploadArea: !!uploadArea,
        fileInput: !!fileInput,
        uploadProgress: !!uploadProgress,
        uploadResult: !!uploadResult,
        progressFill: !!progressFill,
        progressText: !!progressText,
        resultIcon: !!resultIcon,
        resultTitle: !!resultTitle,
        resultMessage: !!resultMessage,
        newScanBtn: !!newScanBtn
    });
    
    if (!newScanBtn) {
        console.error('New scan button not found!');
    } else {
        console.log('New scan button found:', newScanBtn);
    }

    // Click to upload
    uploadArea.addEventListener('click', (e) => {
        console.log('Upload area clicked');
        fileInput.click();
    });

    // Drag and drop functionality
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadContainer.classList.add('drag-over');
    });

    uploadArea.addEventListener('dragleave', (e) => {
        e.preventDefault();
        uploadContainer.classList.remove('drag-over');
    });

    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadContainer.classList.remove('drag-over');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileUpload(files[0]);
        }
    });

    // File input change
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });

    // New scan button - Multiple event listeners to ensure it works
    if (newScanBtn) {
        // Click event
        newScanBtn.addEventListener('click', (e) => {
            console.log('New scan button clicked');
            e.preventDefault();
            e.stopPropagation();
            
            // Add a small delay to ensure smooth transition
            setTimeout(() => {
                resetUploadArea();
            }, 100);
        });
        
        // Mousedown event
        newScanBtn.addEventListener('mousedown', (e) => {
            console.log('New scan button mousedown');
        });
        
        // Touchstart event for mobile
        newScanBtn.addEventListener('touchstart', (e) => {
            console.log('New scan button touchstart');
        });
        
        // Also add a direct onclick handler as backup
        newScanBtn.onclick = function(e) {
            console.log('New scan button onclick (backup)');
            e.preventDefault();
            e.stopPropagation();
            setTimeout(() => {
                resetUploadArea();
            }, 100);
        };
        
        // Ensure the button is clickable
        newScanBtn.style.pointerEvents = 'auto';
        newScanBtn.style.cursor = 'pointer';
        newScanBtn.style.zIndex = '1000';
        
        console.log('New scan button event listeners added');
    } else {
        console.error('New scan button not found, cannot add event listeners');
    }

    function handleFileUpload(file) {
        // Validate file type
        const fileExtension = file.name.split('.').pop().toLowerCase();
        
        // Check if it's a supported extension file
        if (!['crx', 'zip'].includes(fileExtension)) {
            // Provide specific error message based on file type
            let errorMessage = 'Invalid file type. Only .crx and .zip files are supported.';
            
            // Common unsupported file types
            const unsupportedTypes = {
                'jpg': 'JPEG image files are not supported.',
                'jpeg': 'JPEG image files are not supported.',
                'png': 'PNG image files are not supported.',
                'gif': 'GIF image files are not supported.',
                'pdf': 'PDF files are not supported.',
                'txt': 'Text files are not supported.',
                'doc': 'Word documents are not supported.',
                'docx': 'Word documents are not supported.',
                'xls': 'Excel files are not supported.',
                'xlsx': 'Excel files are not supported.',
                'ppt': 'PowerPoint files are not supported.',
                'pptx': 'PowerPoint files are not supported.',
                'mp3': 'Audio files are not supported.',
                'mp4': 'Video files are not supported.',
                'avi': 'Video files are not supported.',
                'exe': 'Executable files are not supported.',
                'msi': 'Installer files are not supported.',
                'dmg': 'Mac disk image files are not supported.',
                'pkg': 'Mac package files are not supported.',
                'deb': 'Debian package files are not supported.',
                'rpm': 'RPM package files are not supported.',
                'apk': 'Android APK files are not supported.',
                'ipa': 'iOS app files are not supported.'
            };
            
            if (unsupportedTypes[fileExtension]) {
                errorMessage = `${unsupportedTypes[fileExtension]} Please upload a .crx or .zip browser extension file.`;
            }
            
            showError(errorMessage);
            return;
        }

        // Validate file size (50MB max)
        if (file.size > 50 * 1024 * 1024) {
            showError('File too large. Maximum size is 50MB.');
            return;
        }

        // Show progress
        showProgress();
        
        // Create FormData
        const formData = new FormData();
        formData.append('file', file);

        // Simulate progress animation
        let progress = 0;
        const progressInterval = setInterval(() => {
            progress += Math.random() * 15;
            if (progress > 90) {
                progress = 90;
                clearInterval(progressInterval);
            }
            updateProgress(progress);
        }, 200);

        // Upload file
        fetch('/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            clearInterval(progressInterval);
            updateProgress(100);
            
            setTimeout(() => {
                if (data.success) {
                    showAnalysisResults(data);
                } else {
                    showError(data.error || 'Upload failed');
                }
            }, 500);
        })
        .catch(error => {
            clearInterval(progressInterval);
            console.error('Error:', error);
            showError('Upload failed. Please try again.');
        });
    }

    function showProgress() {
        uploadArea.style.display = 'none';
        uploadProgress.style.display = 'block';
        uploadResult.style.display = 'none';
        uploadContainer.classList.add('uploading');
    }

    function updateProgress(percent) {
        progressFill.style.width = `${percent}%`;
        progressText.textContent = `Analyzing Extension... ${Math.round(percent)}%`;
    }

    function showAnalysisResults(data) {
        uploadProgress.style.display = 'none';
        uploadResult.style.display = 'block';
        
        const analysis = data.analysis;
        const summary = data.summary;
        const securityScore = summary.security_score;
        
        // Set icon and title based on security score
        if (securityScore >= 75) {
            resultIcon.innerHTML = '<i class="fas fa-shield-alt"></i>';
            resultIcon.className = 'result-icon success';
            resultTitle.textContent = '✅ Secure Extension';
        } else if (securityScore >= 50) {
            resultIcon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
            resultIcon.className = 'result-icon warning';
            resultTitle.textContent = '⚠️ Medium Risk Extension';
        } else {
            resultIcon.innerHTML = '<i class="fas fa-times-circle"></i>';
            resultIcon.className = 'result-icon error';
            resultTitle.textContent = '❌ High Risk Extension';
        }
        
        // Create detailed result message
        let messageHTML = `
            <div class="analysis-summary">
                <div class="security-score">
                    <span class="score-label">Security Score:</span>
                    <span class="score-value score-${getScoreClass(securityScore)}">${securityScore}/100</span>
                </div>
                
                <div class="analysis-stats">
                    <div class="stat">
                        <i class="fas fa-bug"></i>
                        <span>${summary.threats_count} Threats Detected</span>
                    </div>
                    <div class="stat">
                        <i class="fas fa-file-code"></i>
                        <span>${summary.files_analyzed} Files Analyzed</span>
                    </div>
                    <div class="stat">
                        <i class="fas fa-lightbulb"></i>
                        <span>${summary.recommendations_count} Recommendations</span>
                    </div>
                </div>
            </div>
        `;
        
        // Add threats if any
        if (analysis.threats_detected && analysis.threats_detected.length > 0) {
            messageHTML += `
                <div class="threats-section">
                    <h4><i class="fas fa-exclamation-triangle"></i> Threats Detected:</h4>
                    <ul class="threats-list">
            `;
            
            analysis.threats_detected.forEach(threat => {
                const severityIcon = threat.severity === 'high' ? '🔴' : '🟡';
                messageHTML += `
                    <li class="threat-item ${threat.severity}">
                        <span class="severity-icon">${severityIcon}</span>
                        <div class="threat-content">
                            <strong>${threat.type.replace(/_/g, ' ').toUpperCase()}</strong>
                            <p>${threat.description}</p>
                            <small><strong>Recommendation:</strong> ${threat.recommendation}</small>
                        </div>
                    </li>
                `;
            });
            
            messageHTML += '</ul></div>';
        }
        
        // Add recommendations
        if (analysis.recommendations && analysis.recommendations.length > 0) {
            messageHTML += `
                <div class="recommendations-section">
                    <h4><i class="fas fa-lightbulb"></i> Security Recommendations:</h4>
                    <ul class="recommendations-list">
            `;
            
            analysis.recommendations.forEach(rec => {
                messageHTML += `<li class="recommendation-item">${rec}</li>`;
            });
            
            messageHTML += '</ul></div>';
        }
        
        resultMessage.innerHTML = messageHTML;
        
        // Animate the result icon
        resultIcon.style.animation = 'checkmark 0.6s ease-out';
        
        // Ensure the new scan button is clickable
        if (newScanBtn) {
            newScanBtn.style.pointerEvents = 'auto';
            newScanBtn.style.cursor = 'pointer';
            newScanBtn.style.zIndex = '1000';
            console.log('New scan button made clickable after analysis');
        }
    }

    function getScoreClass(score) {
        if (score >= 75) return 'high';
        if (score >= 50) return 'medium';
        return 'low';
    }

    function showError(errorMessage) {
        uploadProgress.style.display = 'none';
        uploadResult.style.display = 'block';
        
        resultIcon.innerHTML = '<i class="fas fa-exclamation-circle"></i>';
        resultIcon.className = 'result-icon error';
        resultTitle.textContent = 'Upload Failed';
        resultMessage.textContent = errorMessage;
        
        // Animate the error icon
        resultIcon.style.animation = 'checkmark 0.6s ease-out';
        
        // Auto-reset after 3 seconds
        setTimeout(() => {
            resetUploadArea();
        }, 3000);
    }

    function resetUploadArea() {
        console.log('Starting upload area reset...');
        
        // Reset all display states
        uploadArea.style.display = 'block';
        uploadProgress.style.display = 'none';
        uploadResult.style.display = 'none';
        
        // Remove any CSS classes that might affect display
        uploadContainer.classList.remove('uploading', 'drag-over');
        
        // Reset file input
        fileInput.value = '';
        
        // Reset progress bar
        progressFill.style.width = '0%';
        progressText.textContent = 'Uploading... 0%';
        
        // Reset result elements
        resultIcon.innerHTML = '<i class="fas fa-check-circle"></i>';
        resultIcon.className = 'result-icon success';
        resultTitle.textContent = 'Analysis Complete!';
        resultMessage.innerHTML = '';
        
        // Force a reflow to ensure display changes take effect
        uploadContainer.offsetHeight;
        
        // Ensure the container is clickable again
        uploadContainer.style.pointerEvents = 'auto';
        
        // Re-enable the upload area
        uploadArea.style.pointerEvents = 'auto';
        uploadArea.style.cursor = 'pointer';
        
        // Add a small delay to ensure everything is properly reset
        setTimeout(() => {
            console.log('Final reset check - Upload area display:', uploadArea.style.display);
            console.log('Final reset check - Upload container classes:', uploadContainer.className);
            console.log('Final reset check - Upload area pointer events:', uploadArea.style.pointerEvents);
        }, 50);
        
        console.log('Upload area reset successfully');
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // Add smooth scrolling for better UX
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Add entrance animations when elements come into view
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.animationPlayState = 'running';
            }
        });
    }, observerOptions);

    // Observe all animated elements
    document.querySelectorAll('.feature-card').forEach(card => {
        card.style.animationPlayState = 'paused';
        observer.observe(card);
    });
});