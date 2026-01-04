#!/usr/bin/env python3
"""Directory Bruteforce Module"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
urllib3.disable_warnings()


class DirectoryBruter:
    """Web directory/file bruteforcer"""
    
    def __init__(self, target, wordlist=None, threads=10, timeout=5, 
                 extensions=None, follow_redirects=False):
        self.target = self.normalize_url(target)
        self.wordlist = wordlist or "wordlists/directories.txt"
        self.threads = threads
        self.timeout = timeout
        self.extensions = extensions or ['', '.php', '.html', '.js', '.txt', '.bak']
        self.follow_redirects = follow_redirects
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Status codes to report
        self.interesting_codes = [200, 201, 204, 301, 302, 307, 401, 403, 405, 500]
    
    def normalize_url(self, url):
        """Normalize target URL"""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        return url.rstrip('/')
    
    def brute(self):
        """Run directory bruteforce"""
        try:
            with open(self.wordlist, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            words = ['admin', 'login', 'wp-admin', 'administrator', 'backup',
                    'config', 'api', 'v1', 'v2', 'console', 'dashboard',
                    'uploads', 'images', 'js', 'css', 'assets', 'includes',
                    'phpinfo', 'robots.txt', 'sitemap.xml', '.git', '.env',
                    'wp-config.php.bak', 'web.config', '.htaccess']
        
        # Generate URLs with extensions
        urls = []
        for word in words:
            for ext in self.extensions:
                urls.append(f"{self.target}/{word}{ext}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.check_path, url): url 
                for url in urls
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    yield result
    
    def check_path(self, url):
        """Check if path exists"""
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects
            )
            
            if response.status_code in self.interesting_codes:
                # Filter out generic 404 pages
                if response.status_code == 200:
                    if 'not found' in response.text.lower()[:500]:
                        return None
                
                path = url.replace(self.target, '')
                size = len(response.content)
                return (path, response.status_code, size)
        except:
            pass
        return None
