# Browser Extension Security Scanner

A comprehensive web application for analyzing browser extensions (.crx and .zip files) for security risks and malicious behavior.

## 🚀 Features

### Security Analysis Capabilities
- **Malware Detection**: Scans for known malicious patterns and suspicious code
- **Privacy Analysis**: Examines permissions and data collection practices
- **Code Review**: Analyzes JavaScript for obfuscation and dangerous API usage
- **Compliance Check**: Verifies extension compliance with browser security policies

### Analysis Components
- **Manifest Analysis**: Parses and analyzes manifest.json files
- **Permission Analysis**: Identifies high-risk permissions and broad access patterns
- **Code Pattern Detection**: Detects suspicious JavaScript patterns (eval, innerHTML, etc.)
- **Security Scoring**: Provides a comprehensive security score (0-100)

## 🛠️ Backend Architecture

### Core Components

#### 1. Security Analyzer (`security_analyzer.py`)
The main analysis engine that performs comprehensive security checks:

```python
class SecurityAnalyzer:
    - analyze_extension(file_path)  # Main analysis function
    - _analyze_manifest(manifest)   # Manifest.json analysis
    - _analyze_code_files(file_path) # JavaScript code analysis
    - _analyze_permissions(manifest) # Permission risk assessment
    - _calculate_security_score()    # Overall security scoring
```

#### 2. Flask Application (`app.py`)
RESTful API endpoints for file upload and analysis:

- `POST /upload` - Upload and analyze extension files
- `GET /api/analysis/<filename>` - Get detailed analysis results
- `GET /api/health` - Health check endpoint

#### 3. Frontend Integration (`static/js/main.js`)
Enhanced JavaScript for handling analysis results and displaying comprehensive reports.

## 📊 Analysis Results

### Security Score Categories
- **75-100**: ✅ Secure Extension (Green)
- **50-74**: ⚠️ Medium Risk Extension (Yellow)
- **0-49**: ❌ High Risk Extension (Red)

### Detected Threats
- **Code Injection**: eval() usage detection
- **Excessive Permissions**: High-risk permission requests
- **Broad Access**: Access to all URLs patterns
- **Weak CSP**: Unsafe Content Security Policy

### Analysis Statistics
- Files analyzed count
- Threats detected count
- Security recommendations count
- Permission risk assessment

## 🔧 Installation & Setup

### Prerequisites
- Python 3.7+
- pip package manager

### Installation Steps

1. **Clone the repository**
```bash
git clone <repository-url>
cd extension-security-scanner
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the application**
```bash
python app.py
```

4. **Access the application**
Open your browser and navigate to `http://localhost:5000`

## 📦 Dependencies

### Core Dependencies
- `Flask==2.3.3` - Web framework
- `Werkzeug==2.3.7` - WSGI utilities
- `zipfile36==0.1.3` - ZIP file handling
- `requests==2.31.0` - HTTP library
- `beautifulsoup4==4.12.2` - HTML parsing
- `lxml==4.9.3` - XML/HTML processing
- `cryptography==41.0.7` - Cryptographic functions
- `python-magic==0.4.27` - File type detection

## 🔍 Security Analysis Features

### 1. Manifest Analysis
- Extracts and parses manifest.json files
- Analyzes permissions and host permissions
- Checks Content Security Policy
- Identifies externally connectable domains

### 2. Code Analysis
- Scans JavaScript files for suspicious patterns
- Detects eval() usage (code injection risk)
- Identifies innerHTML usage (XSS risk)
- Analyzes Chrome API usage patterns

### 3. Permission Analysis
- Identifies high-risk permissions:
  - `tabs`, `storage`, `cookies`, `history`
  - `bookmarks`, `passwords`, `webRequest`
  - `identity`, `geolocation`, `notifications`
- Detects broad host permissions (`<all_urls>`, `*://*/*`)

### 4. Threat Detection
- **Code Injection**: eval() function usage
- **Excessive Permissions**: Unnecessary high-risk permissions
- **Broad Access**: Access to all websites
- **Weak Security Policies**: Unsafe CSP configurations

## 📈 API Endpoints

### POST /upload
Upload and analyze an extension file.

**Request:**
- Content-Type: `multipart/form-data`
- Body: File upload with key `file`

**Response:**
```json
{
  "success": true,
  "filename": "extension.zip",
  "analysis": {
    "file_info": {...},
    "manifest_analysis": {...},
    "code_analysis": {...},
    "permission_analysis": {...},
    "security_score": 75,
    "threats_detected": [...],
    "recommendations": [...]
  },
  "summary": {
    "security_score": 75,
    "threats_count": 2,
    "recommendations_count": 3,
    "files_analyzed": 5
  }
}
```

### GET /api/health
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": 1640995200.0,
  "analyzer_ready": true
}
```

## 🎨 Frontend Features

### Upload Interface
- Drag & drop file upload
- Progress tracking
- File type validation (.crx, .zip)
- File size validation (50MB max)

### Results Display
- **Security Score**: Visual score with color coding
- **Threats Section**: Detailed threat analysis with severity levels
- **Recommendations**: Actionable security recommendations
- **Statistics**: Analysis summary with key metrics

### Responsive Design
- Mobile-friendly interface
- Smooth animations and transitions
- Modern gradient design
- Interactive hover effects

## 🔒 Security Considerations

### File Handling
- Secure filename handling with `secure_filename()`
- File size limits (50MB max)
- Automatic file cleanup after analysis
- File type validation

### Analysis Safety
- Sandboxed analysis environment
- No external network calls during analysis
- Local file processing only
- Error handling and validation

## 🚀 Usage Examples

### Basic Usage
1. Open the web application
2. Drag and drop a .crx or .zip extension file
3. Wait for analysis to complete
4. Review the security score and recommendations

### API Usage
```python
import requests

# Upload and analyze an extension
with open('extension.zip', 'rb') as f:
    files = {'file': f}
    response = requests.post('http://localhost:5000/upload', files=files)
    
analysis_result = response.json()
print(f"Security Score: {analysis_result['summary']['security_score']}")
```

## 🔧 Configuration

### Environment Variables
- `FLASK_ENV`: Set to `development` for debug mode
- `MAX_CONTENT_LENGTH`: Maximum file size (default: 50MB)

### Customization
- Modify `suspicious_patterns` in `SecurityAnalyzer` for custom detection
- Add new permission types to `high_risk_permissions`
- Adjust security scoring algorithm in `_calculate_security_score()`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Contact: shirodepratik444@gmail.com
- LinkedIn: [Pratik Shirode](https://www.linkedin.com/in/pratikshirode2405)

---

**Developed by Pratik Shirode** 🚀 