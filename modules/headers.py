#!/usr/bin/env python3
"""Security Headers Analysis Module"""

import requests
import urllib3
urllib3.disable_warnings()


class HeaderAnalyzer:
    """Analyze HTTP security headers"""
    
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'required': True,
            'description': 'HSTS - Forces HTTPS',
            'recommendation': 'max-age=31536000; includeSubDomains'
        },
        'Content-Security-Policy': {
            'required': True,
            'description': 'CSP - Prevents XSS attacks',
            'recommendation': "default-src 'self'"
        },
        'X-Frame-Options': {
            'required': True,
            'description': 'Prevents clickjacking',
            'recommendation': 'DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'required': True,
            'description': 'Prevents MIME sniffing',
            'recommendation': 'nosniff'
        },
        'X-XSS-Protection': {
            'required': False,
            'description': 'XSS filter (deprecated)',
            'recommendation': '1; mode=block'
        },
        'Referrer-Policy': {
            'required': True,
            'description': 'Controls referrer information',
            'recommendation': 'strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'required': True,
            'description': 'Controls browser features',
            'recommendation': 'geolocation=(), microphone=()'
        },
        'Cross-Origin-Opener-Policy': {
            'required': False,
            'description': 'COOP - Isolates browsing context',
            'recommendation': 'same-origin'
        },
        'Cross-Origin-Resource-Policy': {
            'required': False,
            'description': 'CORP - Controls resource loading',
            'recommendation': 'same-origin'
        },
        'Cross-Origin-Embedder-Policy': {
            'required': False,
            'description': 'COEP - Controls embedding',
            'recommendation': 'require-corp'
        }
    }
    
    DANGEROUS_HEADERS = [
        'Server', 'X-Powered-By', 'X-AspNet-Version', 
        'X-AspNetMvc-Version', 'X-Runtime'
    ]
    
    def __init__(self, target, timeout=10):
        self.target = self.normalize_url(target)
        self.timeout = timeout
    
    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        return url
    
    def analyze(self):
        """Analyze security headers"""
        try:
            response = requests.get(
                self.target, 
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            headers = response.headers
            
            # Check for required security headers
            for header, info in self.SECURITY_HEADERS.items():
                if header in headers:
                    yield (header, headers[header], "secure")
                elif info['required']:
                    yield (header, f"MISSING - {info['description']}", "missing")
            
            # Check for information disclosure
            for header in self.DANGEROUS_HEADERS:
                if header in headers:
                    yield (header, f"EXPOSED: {headers[header]}", "warning")
            
            # Cookie analysis
            yield from self.analyze_cookies(response)
            
            # CORS analysis
            yield from self.analyze_cors(headers)
            
        except Exception as e:
            yield ("Error", str(e), "error")
    
    def analyze_cookies(self, response):
        """Analyze cookie security"""
        for cookie in response.cookies:
            issues = []
            
            if not cookie.secure:
                issues.append("Missing Secure flag")
            if 'httponly' not in str(cookie).lower():
                issues.append("Missing HttpOnly flag")
            if 'samesite' not in str(cookie).lower():
                issues.append("Missing SameSite attribute")
            
            if issues:
                yield (f"Cookie: {cookie.name}", ", ".join(issues), "warning")
            else:
                yield (f"Cookie: {cookie.name}", "Properly secured", "secure")
    
    def analyze_cors(self, headers):
        """Analyze CORS configuration"""
        if 'Access-Control-Allow-Origin' in headers:
            value = headers['Access-Control-Allow-Origin']
            if value == '*':
                yield ("CORS", "Wildcard origin allowed - potential vulnerability", "warning")
            else:
                yield ("CORS", f"Allowed origin: {value}", "info")
        
        if 'Access-Control-Allow-Credentials' in headers:
            if headers['Access-Control-Allow-Credentials'].lower() == 'true':
                yield ("CORS Credentials", "Credentials allowed", "info")
