#!/usr/bin/env python3
"""DNS Enumeration Module"""

import dns.resolver
import dns.zone
import dns.query


class DNSEnumerator:
    """DNS record enumeration"""
    
    RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'CAA']
    
    def __init__(self, domain, nameserver=None, timeout=5):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        if nameserver:
            self.resolver.nameservers = [nameserver]
    
    def enumerate(self):
        """Enumerate all DNS records"""
        for record_type in self.RECORD_TYPES:
            try:
                answers = self.resolver.resolve(self.domain, record_type)
                for rdata in answers:
                    yield (record_type, str(rdata))
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                yield ("ERROR", f"Domain {self.domain} does not exist")
                return
            except Exception as e:
                pass
        
        # Additional enumeration
        yield from self.get_nameservers()
        yield from self.check_dnssec()
        yield from self.reverse_lookup()
    
    def get_nameservers(self):
        """Get all nameservers"""
        try:
            ns_records = self.resolver.resolve(self.domain, 'NS')
            for ns in ns_records:
                # Get IP of nameserver
                try:
                    ns_ip = self.resolver.resolve(str(ns), 'A')
                    for ip in ns_ip:
                        yield ("NS-IP", f"{ns} -> {ip}")
                except:
                    pass
        except:
            pass
    
    def check_dnssec(self):
        """Check for DNSSEC"""
        try:
            answers = self.resolver.resolve(self.domain, 'DNSKEY')
            yield ("DNSSEC", "Enabled")
        except:
            yield ("DNSSEC", "Not configured")
    
    def reverse_lookup(self):
        """Perform reverse DNS lookup"""
        try:
            answers = self.resolver.resolve(self.domain, 'A')
            for ip in answers:
                try:
                    reverse = dns.reversename.from_address(str(ip))
                    ptr = self.resolver.resolve(reverse, 'PTR')
                    for record in ptr:
                        yield ("PTR", f"{ip} -> {record}")
                except:
                    pass
        except:
            pass
