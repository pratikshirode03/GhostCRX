import os
import json
import zipfile
import re
import hashlib
import io
import tempfile
import shutil
import math
import requests
from typing import Dict, List, Any
from urllib.parse import urlparse

class SecurityAnalyzer:
    def __init__(self, virustotal_api: str = "e2bd0427c0a450d1a74dde445749dea77e6a16c3b235d20d56d10f0874bc964501705bc434f17bc5"):
        self.suspicious_patterns = {
            'eval_usage': r'eval\s*\(',
            'innerHTML_usage': r'\.innerHTML\s*=',
            'document_write': r'document\.write\s*\(',
            'script_injection': r'<script[^>]*>',
            'data_urls': r'data:text/javascript',
            'chrome_tabs_query': r'chrome\.tabs\.query',
            'chrome_storage_access': r'chrome\.storage\.',
            'chrome_cookies_access': r'chrome\.cookies\.',
            'chrome_history_access': r'chrome\.history\.',
            'chrome_bookmarks_access': r'chrome\.bookmarks\.',
            'chrome_passwords_access': r'chrome\.passwords\.',
            'web_request_access': r'chrome\.webRequest\.',
            'content_script_injection': r'chrome\.tabs\.executeScript',
            'background_script': r'background\.js',
            'manifest_v3': r'"manifest_version":\s*3',
            'permissions': r'"permissions":\s*\[',
            'host_permissions': r'"host_permissions":\s*\[',
            'content_security_policy': r'"content_security_policy"',
            'externally_connectable': r'"externally_connectable"',
            'web_accessible_resources': r'"web_accessible_resources"',
            'fingerprinting': r'navigator\.(userAgent|plugins|platform)|screen\.(width|height)|canvas\.fingerprint',
            'cryptojacking': r'coinimp|cryptonight|miner|coinhive|crypto|webassembly|wasm|mining',
            'data_exfiltration': r'XMLHttpRequest\(\)\.send\(.+\)|fetch\(.+\)|chrome\.runtime\.sendMessage\(.+\)|chrome\.tabs\.sendMessage\(.+\)|window\.postMessage\(.+\)'
        }
        
        self.high_risk_permissions = [
            'tabs', 'storage', 'cookies', 'history', 'bookmarks', 'passwords',
            'webRequest', 'webRequestBlocking', 'downloads', 'geolocation',
            'notifications', 'identity', 'identity.email', 'identity.getRedirectURL',
            'identity.getAuthToken', 'identity.launchWebAuthFlow'
        ]
        
        self.suspicious_domains = [
            'malware.com', 'phishing.com', 'suspicious.com',
            'tracker.com', 'ads.com', 'analytics.com'
        ]
        
        self.virustotal_api = virustotal_api

    def analyze_extension(self, file_path: str) -> Dict[str, Any]:
        """Main analysis function for browser extensions"""
        try:
            analysis_result = {
                'file_info': self._get_file_info(file_path),
                'manifest_analysis': {},
                'code_analysis': {},
                'permission_analysis': {},
                'network_analysis': {},
                'reputation_analysis': {},
                'security_score': 0,
                'threats_detected': [],
                'behavioral_threats': [],
                'recommendations': []
            }
            
            # Extract and analyze manifest
            manifest_data = self._extract_manifest(file_path)
            if isinstance(manifest_data, dict) and not manifest_data.get('error'):
                analysis_result['manifest_analysis'] = self._analyze_manifest(manifest_data)
                analysis_result['permission_analysis'] = self._analyze_permissions(manifest_data)
                analysis_result['network_analysis'] = self._analyze_network_behavior(manifest_data)
            
            # Analyze code files
            analysis_result['code_analysis'] = self._analyze_all_code(file_path)
            
            # Reputation analysis
            if analysis_result['file_info'].get('sha256_hash'):
                analysis_result['reputation_analysis'] = self._check_extension_reputation(
                    analysis_result['file_info']['sha256_hash']
                )
            
            # Behavioral threat detection
            analysis_result['behavioral_threats'] = self._detect_malicious_behaviors(analysis_result)
            
            # Calculate final metrics
            analysis_result['threats_detected'] = self._detect_threats(analysis_result)
            analysis_result['security_score'] = self._calculate_security_score(analysis_result)
            analysis_result['recommendations'] = self._generate_recommendations(analysis_result)
            
            return analysis_result
            
        except Exception as e:
            return {
                'error': f'Analysis failed: {str(e)}',
                'security_score': 0
            }

    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                return {
                    'filename': os.path.basename(file_path),
                    'size': os.path.getsize(file_path),
                    'extension': file_path.split('.')[-1].lower(),
                    'sha256_hash': file_hash,
                    'file_type': 'Chrome Extension' if file_path.endswith('.crx') else 'ZIP Archive'
                }
        except Exception as e:
            return {'error': f'File info error: {str(e)}'}

    def _extract_manifest(self, file_path: str) -> Dict[str, Any]:
        """Unified manifest extraction for both CRX and ZIP"""
        try:
            if file_path.endswith('.crx'):
                with open(file_path, 'rb') as f:
                    header = f.read(16)
                    if header[:4] != b'Cr24':
                        return {'error': 'Invalid CRX header'}
                    
                    version = int.from_bytes(header[4:8], 'little')
                    if version == 2:
                        pubkey_len = int.from_bytes(header[8:12], 'little')
                        sig_len = int.from_bytes(header[12:16], 'little')
                        f.seek(16 + pubkey_len + sig_len)
                    elif version == 3:
                        header_size = int.from_bytes(header[8:12], 'little')
                        f.seek(12 + header_size)
                    else:
                        return {'error': f'Unsupported CRX version: {version}'}
                    
                    zip_data = f.read()
                    with zipfile.ZipFile(io.BytesIO(zip_data)) as zip_ref:
                        return self._extract_manifest_from_zip(zip_ref)
            
            else:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    return self._extract_manifest_from_zip(zip_ref)
        
        except Exception as e:
            return {'error': f'Manifest extraction failed: {str(e)}'}

    def _extract_manifest_from_zip(self, zip_ref: zipfile.ZipFile) -> Dict[str, Any]:
        """Helper to extract manifest from ZipFile object"""
        try:
            manifest_files = [f for f in zip_ref.namelist() 
                            if f.lower().endswith('manifest.json')]
            
            if not manifest_files:
                return {'error': 'No manifest.json found'}
            
            manifest_content = zip_ref.read(manifest_files[0]).decode('utf-8')
            return json.loads(manifest_content)
        except Exception as e:
            return {'error': f'Manifest parsing failed: {str(e)}'}

    def _analyze_manifest(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze manifest.json for security issues"""
        analysis = {
            'manifest_version': manifest.get('manifest_version', 'unknown'),
            'permissions': manifest.get('permissions', []),
            'host_permissions': manifest.get('host_permissions', []),
            'content_scripts': manifest.get('content_scripts', []),
            'background': manifest.get('background', {}),
            'web_accessible_resources': manifest.get('web_accessible_resources', []),
            'externally_connectable': manifest.get('externally_connectable', {}),
            'content_security_policy': manifest.get('content_security_policy', ''),
            'issues': []
        }
        
        # Check for high-risk permissions
        high_risk_perms = []
        for perm in analysis['permissions']:
            if perm in self.high_risk_permissions:
                high_risk_perms.append(perm)
        
        if high_risk_perms:
            analysis['issues'].append({
                'type': 'high_risk_permissions',
                'severity': 'high',
                'description': f'Extension requests high-risk permissions: {", ".join(high_risk_perms)}'
            })
        
        # Check for broad host permissions
        broad_hosts = []
        for host in analysis['host_permissions']:
            if host in ['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*']:
                broad_hosts.append(host)
        
        if broad_hosts:
            analysis['issues'].append({
                'type': 'broad_host_permissions',
                'severity': 'medium',
                'description': f'Extension requests broad host permissions: {", ".join(broad_hosts)}'
            })
        
        # Check for weak CSP
        if analysis['content_security_policy']:
            if "'unsafe-inline'" in analysis['content_security_policy']:
                analysis['issues'].append({
                    'type': 'weak_csp',
                    'severity': 'medium',
                    'description': 'Content Security Policy allows unsafe-inline'
                })
            if "'unsafe-eval'" in analysis['content_security_policy']:
                analysis['issues'].append({
                    'type': 'unsafe_eval',
                    'severity': 'high',
                    'description': 'CSP allows unsafe-eval'
                })
        
        return analysis

    def _analyze_all_code(self, file_path: str) -> Dict[str, Any]:
        """Unified code analysis for both CRX and ZIP files"""
        analysis = {
            'files_analyzed': 0,
            'suspicious_patterns': [],
            'issues': []
        }
        
        # Create temp directory for extraction
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Extract files based on type
                if file_path.endswith('.crx'):
                    with open(file_path, 'rb') as f:
                        header = f.read(16)
                        if header[:4] != b'Cr24':
                            return {'error': 'Invalid CRX file'}
                        
                        version = int.from_bytes(header[4:8], 'little')
                        if version == 2:
                            pubkey_len = int.from_bytes(header[8:12], 'little')
                            sig_len = int.from_bytes(header[12:16], 'little')
                            f.seek(16 + pubkey_len + sig_len)
                        elif version == 3:
                            header_size = int.from_bytes(header[8:12], 'little')
                            f.seek(12 + header_size)
                        else:
                            return {'error': f'Unsupported CRX version: {version}'}
                        
                        with zipfile.ZipFile(io.BytesIO(f.read())) as zip_ref:
                            zip_ref.extractall(temp_dir)
                
                elif file_path.endswith('.zip'):
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        zip_ref.extractall(temp_dir)
                
                else:
                    return analysis
                
                # Analyze all extracted files
                self._scan_directory(temp_dir, analysis)
                
            except Exception as e:
                analysis['error'] = f'Code analysis failed: {str(e)}'
        
        return analysis

    def _scan_directory(self, directory: str, analysis: Dict[str, Any]):
        """Recursively scan directory for JS files and archives"""
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if file.lower().endswith('.js'):
                    self._analyze_js_file(file_path, analysis)
                elif file.lower().endswith(('.zip', '.crx')):
                    self._process_archive(file_path, analysis)

    def _process_archive(self, archive_path: str, analysis: Dict[str, Any]):
        """Process nested ZIP/CRX files"""
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                if archive_path.endswith('.crx'):
                    with open(archive_path, 'rb') as f:
                        header = f.read(16)
                        if header[:4] != b'Cr24':
                            return
                        version = int.from_bytes(header[4:8], 'little')
                        if version == 2:
                            pubkey_len = int.from_bytes(header[8:12], 'little')
                            sig_len = int.from_bytes(header[12:16], 'little')
                            f.seek(16 + pubkey_len + sig_len)
                        elif version == 3:
                            header_size = int.from_bytes(header[8:12], 'little')
                            f.seek(12 + header_size)
                        else:
                            return
                        
                        with zipfile.ZipFile(io.BytesIO(f.read())) as zip_ref:
                            zip_ref.extractall(temp_dir)
                
                elif archive_path.endswith('.zip'):
                    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                        zip_ref.extractall(temp_dir)
                
                # Scan extracted content
                self._scan_directory(temp_dir, analysis)
            
            except Exception:
                pass

    def _analyze_js_file(self, file_path: str, analysis: Dict[str, Any]):
        """Analyze a single JS file with enhanced detection"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Enhanced analysis
            analysis_result = {
                'eval_count': len(re.findall(self.suspicious_patterns['eval_usage'], content)),
                'innerHTML_count': len(re.findall(self.suspicious_patterns['innerHTML_usage'], content)),
                'chrome_api_count': sum(
                    len(re.findall(pattern, content))
                    for name, pattern in self.suspicious_patterns.items()
                    if name.startswith('chrome.')
                ),
                'obfuscation_score': self._detect_obfuscation(content),
                'is_minified': self._is_minified(content),
                'dynamic_imports': len(re.findall(r'import\(.+?\)', content)),
                'fingerprinting': len(re.findall(self.suspicious_patterns['fingerprinting'], content)),
                'cryptojacking': len(re.findall(self.suspicious_patterns['cryptojacking'], content)),
                'data_exfiltration': len(re.findall(self.suspicious_patterns['data_exfiltration'], content))
            }
            
            analysis['files_analyzed'] += 1
            
            # Add issues based on analysis
            if analysis_result['eval_count'] > 0:
                analysis['issues'].append({
                    'type': 'eval_usage',
                    'severity': 'high',
                    'file': os.path.basename(file_path),
                    'count': analysis_result['eval_count']
                })
            
            if analysis_result['innerHTML_count'] > 5:
                analysis['issues'].append({
                    'type': 'innerHTML_usage',
                    'severity': 'medium',
                    'file': os.path.basename(file_path),
                    'count': analysis_result['innerHTML_count']
                })
            
            if analysis_result['obfuscation_score'] > 0.7:
                analysis['issues'].append({
                    'type': 'code_obfuscation',
                    'severity': 'high',
                    'file': os.path.basename(file_path),
                    'score': analysis_result['obfuscation_score']
                })
            
            if analysis_result['is_minified']:
                analysis['issues'].append({
                    'type': 'minified_code',
                    'severity': 'medium',
                    'file': os.path.basename(file_path)
                })
            
            if analysis_result['dynamic_imports'] > 0:
                analysis['issues'].append({
                    'type': 'dynamic_imports',
                    'severity': 'medium',
                    'file': os.path.basename(file_path),
                    'count': analysis_result['dynamic_imports']
                })
            
            # Log Chrome API usage
            if analysis_result['chrome_api_count'] > 0:
                analysis['suspicious_patterns'].append({
                    'type': 'chrome_api_usage',
                    'file': os.path.basename(file_path),
                    'count': analysis_result['chrome_api_count']
                })
        
        except Exception:
            pass

    def _detect_obfuscation(self, content: str) -> float:
        """Calculate obfuscation score (0-1)"""
        # 1. High entropy detection
        entropy = self._calculate_shannon_entropy(content)
        # 2. Suspicious string patterns
        hex_strings = len(re.findall(r'\\x[0-9a-fA-F]{2}', content))
        base64_strings = len(re.findall(r'[A-Za-z0-9+/=]{20,}', content))
        # 3. Eval/Function constructor usage
        eval_usage = 1 if re.search(r'eval\(|new Function\(', content) else 0
        
        # Weighted score calculation
        return min(1.0, (entropy * 0.4) + (hex_strings * 0.0001) + (base64_strings * 0.00005) + (eval_usage * 0.2))

    def _calculate_shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy for string"""
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy / 8  # Normalize to 0-1 range

    def _is_minified(self, content: str) -> bool:
        """Detect minified JavaScript"""
        # Check for absence of whitespace and comments
        if len(content) > 1000:
            comment_ratio = len(re.findall(r'//|/\*', content)) / len(content)
            line_lengths = [len(line) for line in content.split('\n')]
            avg_line_length = sum(line_lengths) / len(line_lengths) if line_lengths else 0
            return comment_ratio < 0.001 and avg_line_length > 100
        return False

    def _analyze_permissions(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze extension permissions for security risks"""
        permissions = manifest.get('permissions', [])
        host_permissions = manifest.get('host_permissions', [])
        
        analysis = {
            'total_permissions': len(permissions),
            'high_risk_permissions': [],
            'broad_host_permissions': [],
            'risk_score': 0,
            'issues': []
        }
        
        # Check for high-risk permissions
        for perm in permissions:
            if perm in self.high_risk_permissions:
                analysis['high_risk_permissions'].append(perm)
                analysis['risk_score'] += 10
        
        # Check for broad host permissions
        for host in host_permissions:
            if host in ['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*']:
                analysis['broad_host_permissions'].append(host)
                analysis['risk_score'] += 5
        
        # Generate issues
        if analysis['high_risk_permissions']:
            analysis['issues'].append({
                'type': 'high_risk_permissions',
                'severity': 'high',
                'description': f'Extension requests {len(analysis["high_risk_permissions"])} high-risk permissions'
            })
        
        if analysis['broad_host_permissions']:
            analysis['issues'].append({
                'type': 'broad_host_permissions',
                'severity': 'medium',
                'description': f'Extension requests access to {len(analysis["broad_host_permissions"])} broad host patterns'
            })
        
        return analysis

    def _analyze_network_behavior(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network permissions and CORS policies"""
        analysis = {
            'external_domains': [],
            'cors_policies': [],
            'issues': []
        }
        
        # Extract all domains from permissions
        for perm in manifest.get('host_permissions', []):
            if '://' in perm:
                domain = urlparse(perm).netloc
                if domain not in analysis['external_domains']:
                    analysis['external_domains'].append(domain)
        
        # Check for known malicious domains
        malicious_domains = []
        for domain in analysis['external_domains']:
            if any(sd in domain for sd in self.suspicious_domains):
                malicious_domains.append(domain)
        
        if malicious_domains:
            analysis['issues'].append({
                'type': 'malicious_domains',
                'severity': 'critical',
                'description': 'Connects to suspicious domains',
                'domains': malicious_domains
            })
        
        return analysis

    def _check_extension_reputation(self, file_hash: str) -> Dict[str, Any]:
        """Check extension against threat intelligence services"""
        reputation = {
            'virustotal': None,
            'issues': []
        }
        
        # VirusTotal API check
        if self.virustotal_api:
            try:
                params = {'apikey': self.virustotal_api, 'resource': file_hash}
                response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', 
                                        params=params, 
                                        timeout=10)
                if response.status_code == 200:
                    vt_data = response.json()
                    if vt_data.get('response_code') == 1:
                        reputation['virustotal'] = {
                            'positives': vt_data['positives'],
                            'total': vt_data['total']
                        }
                        if vt_data['positives'] > 0:
                            reputation['issues'].append({
                                'severity': 'critical',
                                'description': f'Detected by {vt_data["positives"]}/{vt_data["total"]} antivirus engines'
                            })
            except Exception:
                pass
        
        return reputation

    def _detect_malicious_behaviors(self, analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect complex malicious behavior patterns"""
        threats = []
        code_analysis = analysis_result.get('code_analysis', {})
        
        # 1. Data exfiltration patterns
        exfil_detected = any(
            issue['type'] in ['eval_usage', 'chrome_api_count'] or
            any(pattern['type'] == 'data_exfiltration' for pattern in code_analysis.get('suspicious_patterns', []))
            for issue in code_analysis.get('issues', [])
        )
        
        if exfil_detected:
            threats.append({
                'type': 'data_exfiltration',
                'severity': 'critical',
                'description': 'Potential data exfiltration capability detected'
            })
        
        # 2. Browser fingerprinting
        fingerprint_detected = any(
            issue.get('type') == 'fingerprinting' or
            any('fingerprinting' in pattern['type'] for pattern in code_analysis.get('suspicious_patterns', []))
            for issue in code_analysis.get('issues', [])
        )
        
        if fingerprint_detected:
            threats.append({
                'type': 'browser_fingerprinting',
                'severity': 'high',
                'description': 'Browser fingerprinting capabilities detected'
            })
        
        # 3. Cryptojacking detection
        crypto_detected = any(
            issue.get('type') == 'cryptojacking' or
            any('cryptojacking' in pattern['type'] for pattern in code_analysis.get('suspicious_patterns', []))
            for issue in code_analysis.get('issues', [])
        )
        
        if crypto_detected:
            threats.append({
                'type': 'cryptojacking',
                'severity': 'high',
                'description': 'Potential cryptocurrency mining detected'
            })
        
        return threats

    def _detect_threats(self, analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect specific security threats"""
        threats = []
        
        # Check for eval usage
        if any(issue['type'] == 'eval_usage' for issue in analysis_result.get('code_analysis', {}).get('issues', [])):
            threats.append({
                'type': 'code_injection',
                'severity': 'high',
                'description': 'Extension uses eval() which can execute arbitrary code',
                'recommendation': 'Avoid using eval() and use safer alternatives'
            })
        
        # Check for high-risk permissions
        high_risk_perms = analysis_result.get('permission_analysis', {}).get('high_risk_permissions', [])
        if high_risk_perms:
            threats.append({
                'type': 'excessive_permissions',
                'severity': 'medium',
                'description': f'Extension requests high-risk permissions: {", ".join(high_risk_perms)}',
                'recommendation': 'Review if all permissions are necessary for functionality'
            })
        
        # Check for broad host permissions
        broad_hosts = analysis_result.get('permission_analysis', {}).get('broad_host_permissions', [])
        if broad_hosts:
            threats.append({
                'type': 'broad_access',
                'severity': 'medium',
                'description': f'Extension requests access to all URLs: {", ".join(broad_hosts)}',
                'recommendation': 'Limit host permissions to specific domains when possible'
            })
        
        # Add network threats
        for issue in analysis_result.get('network_analysis', {}).get('issues', []):
            threats.append({
                'type': issue['type'],
                'severity': issue['severity'],
                'description': issue['description'],
                'domains': issue.get('domains', [])
            })
        
        # Add reputation threats
        for issue in analysis_result.get('reputation_analysis', {}).get('issues', []):
            threats.append({
                'type': 'reputation_issue',
                'severity': issue['severity'],
                'description': issue['description']
            })
        
        return threats

    def _calculate_security_score(self, analysis_result: Dict[str, Any]) -> int:
        """Calculate overall security score (0-100, higher is better)"""
        score = 100
        
        # Deduct points for issues
        for issue in analysis_result.get('manifest_analysis', {}).get('issues', []):
            if issue['severity'] == 'critical': score -= 30
            elif issue['severity'] == 'high': score -= 20
            elif issue['severity'] == 'medium': score -= 10
            elif issue['severity'] == 'low': score -= 5
        
        for issue in analysis_result.get('code_analysis', {}).get('issues', []):
            if issue['severity'] == 'critical': score -= 40
            elif issue['severity'] == 'high': score -= 25
            elif issue['severity'] == 'medium': score -= 15
            elif issue['severity'] == 'low': score -= 5
        
        # Deduct points for high-risk permissions
        high_risk_perms = analysis_result.get('permission_analysis', {}).get('high_risk_permissions', [])
        score -= len(high_risk_perms) * 5
        
        # Deduct for network risks
        for issue in analysis_result.get('network_analysis', {}).get('issues', []):
            if issue['severity'] == 'critical': score -= 30
            elif issue['severity'] == 'high': score -= 20
            elif issue['severity'] == 'medium': score -= 10
        
        # Deduct for reputation issues
        if analysis_result.get('reputation_analysis', {}).get('issues'):
            score -= 25
        
        # Deduct for behavioral threats
        for threat in analysis_result.get('behavioral_threats', []):
            if threat['severity'] == 'critical': score -= 40
            elif threat['severity'] == 'high': score -= 25
            elif threat['severity'] == 'medium': score -= 15
        
        # Ensure score is between 0 and 100
        return max(0, min(100, score))

    def _generate_recommendations(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        security_score = analysis_result.get('security_score', 0)
        
        if security_score < 50:
            recommendations.append("⚠️ HIGH RISK: This extension has significant security concerns")
        elif security_score < 75:
            recommendations.append("⚠️ MEDIUM RISK: This extension has some security concerns")
        else:
            recommendations.append("✅ LOW RISK: This extension appears to be relatively safe")
        
        # Specific recommendations based on analysis
        if any(issue['type'] == 'eval_usage' for issue in analysis_result.get('code_analysis', {}).get('issues', [])):
            recommendations.append("🔒 Remove eval() usage to prevent code injection attacks")
        
        if analysis_result.get('permission_analysis', {}).get('high_risk_permissions'):
            recommendations.append("🔒 Review and minimize requested permissions")
        
        if analysis_result.get('permission_analysis', {}).get('broad_host_permissions'):
            recommendations.append("🔒 Limit host permissions to specific domains")
        
        if not analysis_result.get('manifest_analysis', {}).get('content_security_policy'):
            recommendations.append("🔒 Implement a strong Content Security Policy")
        
        if any(issue['type'] == 'code_obfuscation' for issue in analysis_result.get('code_analysis', {}).get('issues', [])):
            recommendations.append("🔒 Review obfuscated code - may hide malicious behavior")
        
        if analysis_result.get('network_analysis', {}).get('issues'):
            recommendations.append("🔒 Restrict connections to suspicious domains")
        
        if analysis_result.get('reputation_analysis', {}).get('issues'):
            recommendations.append("🔒 This extension has been flagged by security services - avoid use")
        
        if any(threat['type'] == 'cryptojacking' for threat in analysis_result.get('behavioral_threats', [])):
            recommendations.append("🔒 Potential cryptojacking detected - monitor resource usage")
        
        return recommendations