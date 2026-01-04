#!/usr/bin/env python3
"""Basic Vulnerability Scanner Module"""

import requests
import re
import ssl
import socket
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings()


class VulnScanner:
    """Basic web vulnerability scanner"""
    
    def __init__(self, target, timeout=10):
        self.target = self.normalize_url(target)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
    
    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        return url
    
    def scan(self):
        """Run all vulnerability checks"""
        yield from self.check_ssl_vulnerabilities()
        yield from self.check_security_misconfigs()
        yield from self.check_sensitive_files()
        yield from self.check_cors_misconfig()
        yield from self.check_open_redirect()
        yield from self.check_clickjacking()
        yield from self.check_information_disclosure()
    
    def check_ssl_vulnerabilities(self):
        """Check SSL/TLS vulnerabilities"""
        try:
            hostname = self.target.replace('https://', '').replace('http://', '').split('/')[0]
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    
                    # Check protocol version
                    if 'TLSv1.0' in protocol or 'TLSv1.1' in protocol:
                        yield ("Weak TLS Version", f"Using {protocol}", "high")
                    
                    # Check certificate expiry
                    import datetime
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        exp_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (exp_date - datetime.datetime.now()).days
                        if days_left < 30:
                            yield ("Certificate Expiring", f"Expires in {days_left} days", "medium")
                        elif days_left < 0:
                            yield ("Certificate Expired", "SSL certificate has expired", "high")
        except:
            pass
    
    def check_security_misconfigs(self):
        """Check for security misconfigurations"""
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            
            # Check for directory listing
            patterns = [
                r'Index of /',
                r'Directory Listing',
                r'Parent Directory'
            ]
            for pattern in patterns:
                if re.search(pattern, response.text, re.I):
                    yield ("Directory Listing", "Directory listing is enabled", "medium")
                    break
            
            # Check for debug mode
            debug_patterns = [
                r'DEBUG\s*=\s*True',
                r'DJANGO_DEBUG',
                r'Flask Debug',
                r'Development Server'
            ]
            for pattern in debug_patterns:
                if re.search(pattern, response.text, re.I):
                    yield ("Debug Mode", "Application running in debug mode", "high")
                    break
            
            # Check for exposed error messages
            error_patterns = [
                r'Fatal error:',
                r'Parse error:',
                r'SQL syntax',
                r'mysql_fetch',
                r'Warning:.*\(\)',
                r'Stack trace:',
                r'Exception in'
            ]
            for pattern in error_patterns:
                if re.search(pattern, response.text, re.I):
                    yield ("Error Disclosure", "Detailed error messages exposed", "medium")
                    break
        except:
            pass
    
    def check_sensitive_files(self):
        """Check for sensitive files"""
        sensitive_paths = [
            '/.git/config',
            '/.git/HEAD',
            '/.svn/entries',
            '/.env',
            '/wp-config.php.bak',
            '/config.php.bak',
            '/.htaccess',
            '/web.config',
            '/phpinfo.php',
            '/server-status',
            '/server-info',
            '/.DS_Store',
            '/backup.zip',
            '/backup.sql',
            '/database.sql',
            '/debug.log',
            '/error.log',
            '/access.log',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml',
            '/.well-known/security.txt',
            '/robots.txt',
            '/sitemap.xml'
        ]
        
        for path in sensitive_paths:
            try:
                url = urljoin(self.target, path)
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code == 200:
                    # Verify it's not a custom 404
                    if len(response.content) > 0:
                        if 'not found' not in response.text.lower()[:500]:
                            severity = "high" if any(x in path for x in ['.git', '.env', 'config', 'backup', '.sql']) else "medium"
                            yield ("Sensitive File", f"Found: {path}", severity)
            except:
                pass
    
    def check_cors_misconfig(self):
        """Check for CORS misconfiguration"""
        try:
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(self.target, headers=headers, timeout=self.timeout)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*':
                yield ("CORS Misconfiguration", "Wildcard origin allowed", "medium")
            elif acao == 'https://evil.com':
                if acac.lower() == 'true':
                    yield ("CORS Misconfiguration", "Origin reflection with credentials", "high")
                else:
                    yield ("CORS Misconfiguration", "Origin reflection detected", "medium")
        except:
            pass
    
    def check_open_redirect(self):
        """Check for open redirect vulnerability"""
        payloads = [
            '//evil.com',
            '/\\evil.com',
            '//evil.com/%2f..',
        ]
        
        params = ['url', 'redirect', 'next', 'return', 'goto', 'link', 'target', 'dest', 'destination', 'rurl', 'redirect_uri', 'redirect_url']
        
        for param in params:
            for payload in payloads:
                try:
                    test_url = f"{self.target}?{param}={payload}"
                    response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                    
                    location = response.headers.get('Location', '')
                    if 'evil.com' in location:
                        yield ("Open Redirect", f"Parameter: {param}", "medium")
                        break
                except:
                    pass
    
    def check_clickjacking(self):
        """Check for clickjacking vulnerability"""
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            
            x_frame = response.headers.get('X-Frame-Options', '')
            csp = response.headers.get('Content-Security-Policy', '')
            
            if not x_frame and 'frame-ancestors' not in csp:
                yield ("Clickjacking", "Missing X-Frame-Options and CSP frame-ancestors", "medium")
        except:
            pass
    
    def check_information_disclosure(self):
        """Check for information disclosure"""
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            
            # Check for exposed emails
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text)
            if emails:
                yield ("Email Disclosure", f"Found: {emails[0]}", "low")
            
            # Check for exposed IPs
            ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', response.text)
            internal_ips = [ip for ip in ips if ip.startswith(('10.', '172.', '192.168.'))]
            if internal_ips:
                yield ("Internal IP Disclosure", f"Found: {internal_ips[0]}", "low")
            
            # Check for exposed paths
            paths = re.findall(r'[C-Z]:\\[^\s<>"\']+|/var/www/[^\s<>"\']+|/home/[^\s<>"\']+', response.text)
            if paths:
                yield ("Path Disclosure", f"Found: {paths[0][:50]}", "low")
            
            # Check headers for version info
            server = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')
            
            if server and any(char.isdigit() for char in server):
                yield ("Server Version Disclosure", server, "low")
            if powered_by:
                yield ("Technology Disclosure", powered_by, "low")
        except:
            pass
