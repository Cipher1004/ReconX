#!/usr/bin/env python3
"""Technology Detection Module"""

import requests
import re
import json
import urllib3  # This import was missing!

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TechDetector:
    """Detect web technologies and frameworks"""
    
    # Technology signatures
    SIGNATURES = {
        # CMS
        'WordPress': {
            'headers': {'X-Powered-By': 'wordpress'},
            'html': ['wp-content', 'wp-includes', '/wp-json/', 'wordpress'],
            'cookies': ['wordpress_logged_in', 'wp-settings']
        },
        'Drupal': {
            'headers': {'X-Generator': 'drupal'},
            'html': ['Drupal.settings', 'sites/all/', 'sites/default/', 'drupal.js'],
            'cookies': ['Drupal.visitor', 'SSESS']
        },
        'Joomla': {
            'headers': {},
            'html': ['/media/jui/', '/components/com_', 'joomla'],
            'cookies': ['joomla_user_state']
        },
        'Magento': {
            'headers': {},
            'html': ['mage/', 'magento', 'Mage.Cookies'],
            'cookies': ['frontend', 'adminhtml']
        },
        'Shopify': {
            'headers': {'X-ShopId': ''},
            'html': ['cdn.shopify.com', 'shopify'],
            'cookies': ['_shopify']
        },
        
        # Frameworks
        'React': {
            'headers': {},
            'html': ['react-root', '__NEXT_DATA__', 'data-reactroot', '_reactRootContainer'],
            'cookies': []
        },
        'Angular': {
            'headers': {},
            'html': ['ng-app', 'ng-controller', 'angular.min.js', 'ng-version'],
            'cookies': []
        },
        'Vue.js': {
            'headers': {},
            'html': ['vue.js', 'vue.min.js', 'v-cloak', 'data-v-', '__VUE__'],
            'cookies': []
        },
        'jQuery': {
            'headers': {},
            'html': ['jquery.min.js', 'jquery.js', 'jquery-'],
            'cookies': []
        },
        'Bootstrap': {
            'headers': {},
            'html': ['bootstrap.min.css', 'bootstrap.min.js', 'bootstrap.css'],
            'cookies': []
        },
        'Laravel': {
            'headers': {},
            'html': ['laravel'],
            'cookies': ['laravel_session', 'XSRF-TOKEN']
        },
        'Django': {
            'headers': {},
            'html': ['csrfmiddlewaretoken', '__admin_media_prefix__'],
            'cookies': ['csrftoken', 'sessionid']
        },
        'Express.js': {
            'headers': {'X-Powered-By': 'express'},
            'html': [],
            'cookies': ['connect.sid']
        },
        'Ruby on Rails': {
            'headers': {'X-Powered-By': 'phusion'},
            'html': ['rails', 'csrf-token'],
            'cookies': ['_session_id']
        },
        'Next.js': {
            'headers': {'X-Powered-By': 'next.js'},
            'html': ['__NEXT_DATA__', '_next/static'],
            'cookies': []
        },
        'Nuxt.js': {
            'headers': {},
            'html': ['__NUXT__', '_nuxt/'],
            'cookies': []
        },
        
        # Servers
        'Nginx': {
            'headers': {'Server': 'nginx'},
            'html': [],
            'cookies': []
        },
        'Apache': {
            'headers': {'Server': 'apache'},
            'html': [],
            'cookies': []
        },
        'IIS': {
            'headers': {'Server': 'microsoft-iis'},
            'html': [],
            'cookies': []
        },
        'LiteSpeed': {
            'headers': {'Server': 'litespeed'},
            'html': [],
            'cookies': []
        },
        
        # Languages
        'PHP': {
            'headers': {'X-Powered-By': 'php'},
            'html': ['.php'],
            'cookies': ['PHPSESSID']
        },
        'ASP.NET': {
            'headers': {'X-AspNet-Version': '', 'X-Powered-By': 'asp.net'},
            'html': ['__VIEWSTATE', '__EVENTVALIDATION', 'aspnetForm'],
            'cookies': ['ASP.NET_SessionId', '.ASPXAUTH']
        },
        'Java': {
            'headers': {'X-Powered-By': 'jsp', 'X-Powered-By': 'servlet'},
            'html': ['.jsp', '.jsf'],
            'cookies': ['JSESSIONID']
        },
        'Python': {
            'headers': {'X-Powered-By': 'python'},
            'html': [],
            'cookies': []
        },
        
        # Cloud/CDN
        'Cloudflare': {
            'headers': {'cf-ray': '', 'Server': 'cloudflare'},
            'html': [],
            'cookies': ['__cfduid', '__cf_bm']
        },
        'AWS CloudFront': {
            'headers': {'X-Amz-Cf-Id': '', 'Via': 'cloudfront'},
            'html': [],
            'cookies': []
        },
        'Akamai': {
            'headers': {'X-Akamai': ''},
            'html': [],
            'cookies': ['akamai']
        },
        'Fastly': {
            'headers': {'X-Served-By': 'cache', 'Via': 'varnish'},
            'html': [],
            'cookies': []
        },
        'Google Cloud': {
            'headers': {'Via': 'google'},
            'html': [],
            'cookies': []
        },
        
        # Security
        'ModSecurity': {
            'headers': {'Server': 'mod_security'},
            'html': [],
            'cookies': []
        },
        'Sucuri': {
            'headers': {'X-Sucuri': ''},
            'html': ['sucuri'],
            'cookies': ['sucuri']
        },
        'Wordfence': {
            'headers': {},
            'html': ['wordfence'],
            'cookies': ['wfvt_']
        },
        
        # Analytics
        'Google Analytics': {
            'headers': {},
            'html': ['google-analytics.com', 'gtag', 'UA-', 'G-'],
            'cookies': ['_ga', '_gid']
        },
        'Google Tag Manager': {
            'headers': {},
            'html': ['googletagmanager.com', 'GTM-'],
            'cookies': []
        },
        'Facebook Pixel': {
            'headers': {},
            'html': ['facebook.com/tr', 'fbq('],
            'cookies': ['_fbp']
        },
        
        # Others
        'Varnish': {
            'headers': {'Via': 'varnish', 'X-Varnish': ''},
            'html': [],
            'cookies': []
        },
        'Redis': {
            'headers': {},
            'html': [],
            'cookies': ['redis']
        }
    }
    
    def __init__(self, target, timeout=10):
        self.target = self.normalize_url(target)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
    
    def normalize_url(self, url):
        """Normalize URL to include protocol"""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        return url.rstrip('/')
    
    def detect(self):
        """Detect technologies used by the target"""
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            
            # Normalize data for comparison
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            html = response.text.lower()
            cookies = {c.name.lower(): c.value for c in response.cookies}
            
            detected = set()
            
            # Check against signatures
            for tech, signatures in self.SIGNATURES.items():
                if tech not in detected:
                    if self.match_signatures(signatures, headers, html, cookies):
                        version = self.extract_version(tech, headers, html, str(response.headers))
                        category = self.get_category(tech)
                        detected.add(tech)
                        yield (tech, version, category)
            
            # Additional checks
            for result in self.check_meta_tags(html):
                if result[0] not in detected:
                    detected.add(result[0])
                    yield result
            
            for result in self.check_headers(response.headers):
                if result[0] not in detected:
                    yield result
            
            for result in self.check_scripts(html):
                if result[0] not in detected:
                    detected.add(result[0])
                    yield result
            
        except requests.exceptions.SSLError:
            # Try HTTP if HTTPS fails
            try:
                http_target = self.target.replace('https://', 'http://')
                response = self.session.get(http_target, timeout=self.timeout)
                yield ("HTTP Only", "HTTPS not available", "Security Issue")
            except Exception as e:
                yield ("Connection Error", str(e)[:50], "Error")
        except requests.exceptions.ConnectionError as e:
            yield ("Connection Error", "Could not connect to target", "Error")
        except requests.exceptions.Timeout:
            yield ("Timeout", "Request timed out", "Error")
        except Exception as e:
            yield ("Error", str(e)[:50], "Error")
    
    def match_signatures(self, signatures, headers, html, cookies):
        """Check if any signatures match"""
        # Check headers
        header_sigs = signatures.get('headers', {})
        if header_sigs:
            for header_name, pattern in header_sigs.items():
                header_name_lower = header_name.lower()
                for h, v in headers.items():
                    if header_name_lower in h:
                        if not pattern or pattern.lower() in v:
                            return True
        
        # Check HTML content
        html_sigs = signatures.get('html', [])
        for pattern in html_sigs:
            if pattern.lower() in html:
                return True
        
        # Check cookies
        cookie_sigs = signatures.get('cookies', [])
        for pattern in cookie_sigs:
            pattern_lower = pattern.lower()
            for cookie_name in cookies.keys():
                if pattern_lower in cookie_name:
                    return True
        
        return False
    
    def extract_version(self, tech, headers, html, raw_headers):
        """Try to extract version number for detected technology"""
        patterns = {
            'WordPress': [
                r'wordpress[/-]?v?(\d+\.\d+\.?\d*)',
                r'wp-includes/version[^"]*?ver=(\d+\.\d+\.?\d*)',
                r'"wordpress":"(\d+\.\d+\.?\d*)"'
            ],
            'jQuery': [
                r'jquery[/-]v?(\d+\.\d+\.?\d*)',
                r'jquery\.min\.js\?ver=(\d+\.\d+\.?\d*)',
                r'jQuery v(\d+\.\d+\.?\d*)'
            ],
            'PHP': [
                r'php[/-]?(\d+\.\d+\.?\d*)',
                r'X-Powered-By: PHP/(\d+\.\d+\.?\d*)'
            ],
            'Nginx': [
                r'nginx[/-]?(\d+\.\d+\.?\d*)'
            ],
            'Apache': [
                r'apache[/-]?(\d+\.\d+\.?\d*)',
                r'Server: Apache/(\d+\.\d+\.?\d*)'
            ],
            'Bootstrap': [
                r'bootstrap[/-]v?(\d+\.\d+\.?\d*)',
                r'bootstrap\.min\.css\?ver=(\d+\.\d+\.?\d*)'
            ],
            'Angular': [
                r'angular[/-]?v?(\d+\.\d+\.?\d*)',
                r'ng-version="(\d+\.\d+\.?\d*)"'
            ],
            'Vue.js': [
                r'vue[/-]?v?(\d+\.\d+\.?\d*)',
                r'Vue\.js v(\d+\.\d+\.?\d*)'
            ],
            'React': [
                r'react[/-]?v?(\d+\.\d+\.?\d*)',
                r'react\.production\.min\.js.*?(\d+\.\d+\.?\d*)'
            ],
            'Next.js': [
                r'next[/-]?v?(\d+\.\d+\.?\d*)'
            ],
            'Laravel': [
                r'laravel[/-]?v?(\d+\.\d+\.?\d*)'
            ]
        }
        
        tech_patterns = patterns.get(tech, [])
        sources = [html, raw_headers.lower()]
        
        for pattern in tech_patterns:
            for source in sources:
                match = re.search(pattern, source, re.I)
                if match:
                    return match.group(1)
        
        return ""
    
    def get_category(self, tech):
        """Get category for a technology"""
        categories = {
            # CMS
            'WordPress': 'CMS',
            'Drupal': 'CMS',
            'Joomla': 'CMS',
            'Magento': 'CMS/E-commerce',
            'Shopify': 'E-commerce',
            
            # Frameworks
            'React': 'JavaScript Framework',
            'Angular': 'JavaScript Framework',
            'Vue.js': 'JavaScript Framework',
            'Next.js': 'JavaScript Framework',
            'Nuxt.js': 'JavaScript Framework',
            'jQuery': 'JavaScript Library',
            'Bootstrap': 'CSS Framework',
            'Laravel': 'PHP Framework',
            'Django': 'Python Framework',
            'Express.js': 'Node.js Framework',
            'Ruby on Rails': 'Ruby Framework',
            
            # Servers
            'Nginx': 'Web Server',
            'Apache': 'Web Server',
            'IIS': 'Web Server',
            'LiteSpeed': 'Web Server',
            
            # Languages
            'PHP': 'Programming Language',
            'ASP.NET': 'Programming Language',
            'Java': 'Programming Language',
            'Python': 'Programming Language',
            
            # CDN/Cloud
            'Cloudflare': 'CDN/Security',
            'AWS CloudFront': 'CDN',
            'Akamai': 'CDN',
            'Fastly': 'CDN',
            'Google Cloud': 'Cloud Provider',
            
            # Security
            'ModSecurity': 'WAF',
            'Sucuri': 'Security/WAF',
            'Wordfence': 'Security Plugin',
            
            # Analytics
            'Google Analytics': 'Analytics',
            'Google Tag Manager': 'Tag Manager',
            'Facebook Pixel': 'Analytics/Marketing',
            
            # Cache
            'Varnish': 'Cache',
            'Redis': 'Cache/Database'
        }
        return categories.get(tech, 'Other')
    
    def check_meta_tags(self, html):
        """Check meta tags for generator/framework info"""
        # Generator meta tag
        generator_patterns = [
            r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
            r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']'
        ]
        
        for pattern in generator_patterns:
            matches = re.findall(pattern, html, re.I)
            for match in matches:
                tech_name = match.split()[0] if match.split() else match
                version = match.split()[-1] if len(match.split()) > 1 else ""
                if tech_name:
                    yield (tech_name, version, "CMS/Generator")
        
        # Application name
        app_pattern = r'<meta[^>]*name=["\']application-name["\'][^>]*content=["\']([^"\']+)["\']'
        matches = re.findall(app_pattern, html, re.I)
        for match in matches:
            yield (match, "", "Application")
    
    def check_headers(self, headers):
        """Check response headers for technology info"""
        interesting_headers = {
            'X-Powered-By': 'Runtime/Framework',
            'X-Generator': 'Generator',
            'X-AspNet-Version': 'ASP.NET Version',
            'X-AspNetMvc-Version': 'ASP.NET MVC Version',
            'X-Runtime': 'Runtime',
            'X-Backend-Server': 'Backend Server',
            'X-Drupal-Cache': 'Drupal Cache',
            'X-Drupal-Dynamic-Cache': 'Drupal Dynamic Cache',
            'X-Pingback': 'Pingback (WordPress)',
            'X-Redirect-By': 'Redirect Handler',
            'X-Litespeed-Cache': 'LiteSpeed Cache',
            'X-Cache-Engine': 'Cache Engine'
        }
        
        for header, category in interesting_headers.items():
            if header in headers:
                value = headers[header]
                yield (f"{header}", value, category)
    
    def check_scripts(self, html):
        """Check for JavaScript libraries and frameworks"""
        script_patterns = {
            'Lodash': r'lodash[./-]',
            'Moment.js': r'moment[./-]',
            'Axios': r'axios[./-]',
            'Chart.js': r'chart[./-]',
            'D3.js': r'd3[./-]',
            'Three.js': r'three[./-]',
            'Socket.io': r'socket\.io',
            'Underscore.js': r'underscore[./-]',
            'Backbone.js': r'backbone[./-]',
            'Ember.js': r'ember[./-]',
            'Handlebars': r'handlebars[./-]',
            'Modernizr': r'modernizr[./-]',
            'Require.js': r'require[./-]',
            'Webpack': r'webpack',
            'Babel': r'babel',
            'TypeScript': r'typescript',
            'Tailwind CSS': r'tailwind',
            'Font Awesome': r'font-?awesome',
            'Material UI': r'material-ui',
            'Ant Design': r'antd',
            'Semantic UI': r'semantic-ui',
            'Foundation': r'foundation[./-]'
        }
        
        for tech, pattern in script_patterns.items():
            if re.search(pattern, html, re.I):
                yield (tech, "", "JavaScript Library")


# Test the module independently
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python techdetect.py <target>")
        print("Example: python techdetect.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"\n{'='*60}")
    print(f" Technology Detection: {target}")
    print(f"{'='*60}\n")
    
    detector = TechDetector(target)
    
    results = list(detector.detect())
    
    if results:
        # Group by category
        categories = {}
        for tech, version, category in results:
            if category not in categories:
                categories[category] = []
            version_str = f" v{version}" if version else ""
            categories[category].append(f"{tech}{version_str}")
        
        for category, techs in sorted(categories.items()):
            print(f"\n[{category}]")
            for tech in techs:
                print(f"  ✓ {tech}")
    else:
        print("No technologies detected.")
    
    print(f"\n{'='*60}\n")
