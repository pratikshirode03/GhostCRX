from flask import Flask, render_template, request, jsonify
import os
import mimetypes
from werkzeug.utils import secure_filename
from security_analyzer import SecurityAnalyzer
import time

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'crx', 'zip'}

# Initialize security analyzer
security_analyzer = SecurityAnalyzer()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        try:
            # Perform security analysis
            analysis_result = security_analyzer.analyze_extension(file_path)
            
            # Clean up uploaded file after analysis
            os.remove(file_path)
            
            if 'error' in analysis_result:
                return jsonify({
                    'success': False,
                    'error': analysis_result['error']
                }), 400
            
            # Format the response for frontend
            response_data = {
                'success': True,
                'filename': filename,
                'analysis': analysis_result,
                'summary': {
                    'security_score': analysis_result.get('security_score', 0),
                    'threats_count': len(analysis_result.get('threats_detected', [])),
                    'recommendations_count': len(analysis_result.get('recommendations', [])),
                    'files_analyzed': analysis_result.get('code_analysis', {}).get('files_analyzed', 0)
                }
            }
            
            return jsonify(response_data)
            
        except Exception as e:
            # Clean up file in case of error
            if os.path.exists(file_path):
                os.remove(file_path)
            
            return jsonify({
                'success': False,
                'error': f'Analysis failed: {str(e)}'
            }), 500
    
    # Provide more specific error message
    file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'unknown'
    
    # Common unsupported file types with specific messages
    unsupported_messages = {
        'jpg': 'JPEG image files are not supported. Please upload a .crx or .zip browser extension file.',
        'jpeg': 'JPEG image files are not supported. Please upload a .crx or .zip browser extension file.',
        'png': 'PNG image files are not supported. Please upload a .crx or .zip browser extension file.',
        'gif': 'GIF image files are not supported. Please upload a .crx or .zip browser extension file.',
        'pdf': 'PDF files are not supported. Please upload a .crx or .zip browser extension file.',
        'txt': 'Text files are not supported. Please upload a .crx or .zip browser extension file.',
        'doc': 'Word documents are not supported. Please upload a .crx or .zip browser extension file.',
        'docx': 'Word documents are not supported. Please upload a .crx or .zip browser extension file.',
        'xls': 'Excel files are not supported. Please upload a .crx or .zip browser extension file.',
        'xlsx': 'Excel files are not supported. Please upload a .crx or .zip browser extension file.',
        'ppt': 'PowerPoint files are not supported. Please upload a .crx or .zip browser extension file.',
        'pptx': 'PowerPoint files are not supported. Please upload a .crx or .zip browser extension file.',
        'mp3': 'Audio files are not supported. Please upload a .crx or .zip browser extension file.',
        'mp4': 'Video files are not supported. Please upload a .crx or .zip browser extension file.',
        'avi': 'Video files are not supported. Please upload a .crx or .zip browser extension file.',
        'exe': 'Executable files are not supported. Please upload a .crx or .zip browser extension file.',
        'msi': 'Installer files are not supported. Please upload a .crx or .zip browser extension file.',
        'dmg': 'Mac disk image files are not supported. Please upload a .crx or .zip browser extension file.',
        'pkg': 'Mac package files are not supported. Please upload a .crx or .zip browser extension file.',
        'deb': 'Debian package files are not supported. Please upload a .crx or .zip browser extension file.',
        'rpm': 'RPM package files are not supported. Please upload a .crx or .zip browser extension file.',
        'apk': 'Android APK files are not supported. Please upload a .crx or .zip browser extension file.',
        'ipa': 'iOS app files are not supported. Please upload a .crx or .zip browser extension file.'
    }
    
    error_message = unsupported_messages.get(file_extension, f'File type .{file_extension} is not supported. Only .crx and .zip browser extension files are allowed.')
    
    return jsonify({'error': error_message}), 400

@app.route('/api/analysis/<filename>')
def get_analysis(filename):
    """Get detailed analysis results"""
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        analysis_result = security_analyzer.analyze_extension(file_path)
        return jsonify(analysis_result)
        
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'analyzer_ready': True
    })

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 50MB.'}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)