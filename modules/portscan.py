#!/usr/bin/env python3
"""Port Scanning Module"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


class PortScanner:
    """TCP/UDP Port Scanner"""
    
    COMMON_SERVICES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
        27017: "MongoDB", 9200: "Elasticsearch"
    }
    
    def __init__(self, target, port_range="1-1000", threads=100, timeout=1):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.parse_port_range(port_range)
    
    def parse_port_range(self, port_range):
        """Parse port range string"""
        if '-' in port_range:
            start, end = port_range.split('-')
            self.ports = range(int(start), int(end) + 1)
        elif ',' in port_range:
            self.ports = [int(p) for p in port_range.split(',')]
        else:
            self.ports = [int(port_range)]
    
    def scan(self):
        """Scan ports"""
        # Resolve hostname
        try:
            ip = socket.gethostbyname(self.target)
        except socket.gaierror:
            return
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.scan_port, ip, port): port 
                for port in self.ports
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    yield result
    
    def scan_port(self, ip, port):
        """Scan individual port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                service = self.get_service(port)
                banner = self.grab_banner(ip, port)
                return (port, f"{service} {banner}".strip())
        except:
            pass
        return None
    
    def get_service(self, port):
        """Get service name for port"""
        return self.COMMON_SERVICES.get(port, "Unknown")
    
    def grab_banner(self, ip, port):
        """Attempt to grab service banner"""
        try:
            sock = socket.socket()
            sock.settimeout(2)
            sock.connect((ip, port))
            
            # Send probe for HTTP
            if port in [80, 8080, 8000, 8888]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return f"| {banner[:50]}" if banner else ""
        except:
            return ""
