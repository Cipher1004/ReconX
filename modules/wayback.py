#!/usr/bin/env python3
"""Wayback Machine Integration Module"""

import requests
import json
from urllib.parse import urlparse


class WaybackMachine:
    """Fetch historical URLs from Wayback Machine"""
    
    def __init__(self, domain, timeout=30):
        self.domain = domain
        self.timeout = timeout
        self.api_url = "http://web.archive.org/cdx/search/cdx"
    
    def get_urls(self):
        """Get all archived URLs for domain"""
        params = {
            'url': f"*.{self.domain}/*",
            'output': 'json',
            'collapse': 'urlkey',
            'fl': 'original,timestamp,statuscode,mimetype'
        }
        
        try:
            response = requests.get(
                self.api_url,
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Skip header row
                seen_urls = set()
                for row in data[1:]:
                    url = row[0]
                    if url not in seen_urls:
                        seen_urls.add(url)
                        yield url
        except:
            pass
    
    def get_interesting_urls(self):
        """Filter for interesting/sensitive URLs"""
        interesting_patterns = [
            '.php', '.asp', '.jsp', '.json', '.xml', '.sql', '.bak',
            '.config', '.env', '.git', '.svn', 'admin', 'login',
            'api/', 'v1/', 'v2/', 'backup', 'debug', 'test',
            'phpinfo', '.log', '.txt', 'password', 'secret'
        ]
        
        for url in self.get_urls():
            url_lower = url.lower()
            for pattern in interesting_patterns:
                if pattern in url_lower:
                    yield url
                    break
    
    def get_js_files(self):
        """Get JavaScript files"""
        for url in self.get_urls():
            if url.endswith('.js') or '/js/' in url:
                yield url
    
    def get_api_endpoints(self):
        """Get API endpoints"""
        api_patterns = ['api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/']
        
        for url in self.get_urls():
            for pattern in api_patterns:
                if pattern in url.lower():
                    yield url
                    break
