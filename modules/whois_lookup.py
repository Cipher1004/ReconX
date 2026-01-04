#!/usr/bin/env python3
"""WHOIS Lookup Module"""

import whois
import socket


class WhoisLookup:
    """Domain WHOIS information lookup"""
    
    def __init__(self, domain):
        self.domain = domain
    
    def lookup(self):
        """Perform WHOIS lookup"""
        try:
            w = whois.whois(self.domain)
            
            fields = [
                ('Domain Name', w.domain_name),
                ('Registrar', w.registrar),
                ('Creation Date', w.creation_date),
                ('Expiration Date', w.expiration_date),
                ('Updated Date', w.updated_date),
                ('Name Servers', w.name_servers),
                ('Status', w.status),
                ('Registrant', w.registrant),
                ('Admin Email', w.emails),
                ('Organization', w.org),
                ('Country', w.country),
                ('State', w.state),
                ('City', w.city),
                ('DNSSEC', w.dnssec)
            ]
            
            for name, value in fields:
                if value:
                    if isinstance(value, list):
                        value = ', '.join(str(v) for v in value[:3])
                    yield (name, str(value)[:100])
            
            # Additional IP info
            try:
                ip = socket.gethostbyname(self.domain)
                yield ('IP Address', ip)
                
                # Reverse DNS
                try:
                    hostname = socket.gethostbyaddr(ip)
                    yield ('Reverse DNS', hostname[0])
                except:
                    pass
            except:
                pass
                
        except Exception as e:
            yield ('Error', str(e))
