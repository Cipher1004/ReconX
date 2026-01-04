#!/usr/bin/env python3
"""Subdomain Enumeration Module"""

import socket
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver


class SubdomainEnumerator:
    """Advanced subdomain enumeration using multiple techniques"""
    
    def __init__(self, domain, wordlist=None, threads=10, timeout=5):
        self.domain = domain
        self.wordlist = wordlist or "wordlists/subdomains.txt"
        self.threads = threads
        self.timeout = timeout
        self.found_subdomains = set()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def enumerate(self):
        """Main enumeration method using multiple techniques"""
        
        # Technique 1: Wordlist bruteforce
        yield from self.bruteforce_subdomains()
        
        # Technique 2: Certificate Transparency
        yield from self.crt_sh_lookup()
        
        # Technique 3: DNS zone transfer attempt
        yield from self.zone_transfer()
    
    def bruteforce_subdomains(self):
        """Bruteforce subdomains using wordlist"""
        try:
            with open(self.wordlist, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            words = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'api', 
                    'staging', 'test', 'beta', 'app', 'cdn', 'shop', 'store',
                    'portal', 'm', 'mobile', 'secure', 'vpn', 'remote']
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.check_subdomain, word): word 
                for word in words
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result and result not in self.found_subdomains:
                    self.found_subdomains.add(result)
                    yield result
    
    def check_subdomain(self, word):
        """Check if subdomain exists"""
        subdomain = f"{word}.{self.domain}"
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            if answers:
                return subdomain
        except:
            pass
        return None
    
    def crt_sh_lookup(self):
        """Query crt.sh for certificate transparency logs"""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain.endswith(self.domain) and subdomain not in self.found_subdomains:
                            if '*' not in subdomain:
                                self.found_subdomains.add(subdomain)
                                yield subdomain
        except:
            pass
    
    def zone_transfer(self):
        """Attempt DNS zone transfer"""
        try:
            ns_records = self.resolver.resolve(self.domain, 'NS')
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(str(ns), self.domain)
                    )
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{self.domain}"
                        if subdomain not in self.found_subdomains:
                            self.found_subdomains.add(subdomain)
                            yield subdomain
                except:
                    pass
        except:
            pass
