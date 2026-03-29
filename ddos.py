#!/usr/bin/env python3
"""
WebsiteGrandMaster Pro - Advanced A-to-Z Website Scanner
Features: subdomain enumeration, directory brute, vulnerability checks, credential extraction, CMS detection, and more.
"""

import requests
import whois
import socket
import ssl
import json
import re
import sys
import os
import time
import argparse
import concurrent.futures
import urllib.parse
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse, urljoin

# Optional imports
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import builtwith
    BUILTWITH_AVAILABLE = True
except ImportError:
    BUILTWITH_AVAILABLE = False

try:
    from Wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except ImportError:
    WAPPALYZER_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

class WebsiteGrandMasterPro:
    def __init__(self, target, timeout=5, threads=10, wordlist=None, output_json=None):
        # Normalize target
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        self.parsed = urlparse(target)
        self.domain = self.parsed.netloc
        self.base_url = f"{self.parsed.scheme}://{self.domain}"
        self.timeout = timeout
        self.threads = threads
        self.output_json = output_json
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.results = {
            'target': self.domain,
            'scan_time': datetime.now().isoformat(),
            'info': [],
            'vulns': [],
            'credentials': [],
            'admin_panels': [],
            'subdomains': [],
            'directories': [],
            'emails': [],
            'technologies': [],
            'ports': []
        }

        # Enhanced common subdomains
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
            'web', 'media', 'email', 'images', 'img', 'download', 'mssql', 'mail1',
            'panel', 'server', 'staging', 'my', 'api', 'app', 'portal', 'stats',
            'backup', 'dns', 'store', 'help', 'crm', 'office', 'info', 'bbs', 'sip',
            'vps', 'gw', 'live', 'remote', 'video', 'sms', 'exchange', 'cloud',
            'auth', 'account', 'accounts', 'ad', 'adm', 'administrator', 'affiliate',
            'analytics', 'api2', 'api3', 'app2', 'apps', 'backup', 'beta2', 'blog2',
            'business', 'cache', 'cdn', 'chat', 'client', 'clients', 'cloudmail',
            'cms', 'code', 'community', 'company', 'config', 'contact', 'corp',
            'cp', 'cpanel2', 'css', 'dashboard', 'data', 'db', 'default', 'devel',
            'dev2', 'direct', 'dl', 'downloads', 'email', 'en', 'es', 'events',
            'extranet', 'faq', 'files', 'ftp2', 'ftp3', 'games', 'git', 'helpdesk',
            'home', 'host', 'hosting', 'imap', 'img', 'info2', 'intranet', 'investor',
            'ipv4', 'ipv6', 'js', 'lab', 'legacy', 'links', 'list', 'lists', 'local',
            'login', 'logs', 'm', 'mail2', 'mail3', 'manager', 'marketing', 'master',
            'media', 'member', 'members', 'mobile', 'mssql', 'my', 'mysql2', 'news2',
            'newtest', 'old', 'online', 'partner', 'partners', 'pay', 'payment',
            'photos', 'pictures', 'pop3', 'portal2', 'preview', 'private', 'prod',
            'production', 'profiles', 'project', 'public', 'qa', 'redirect', 'register',
            'relay', 'reports', 'resources', 'review', 'secure2', 'server', 'service',
            'services', 'shop2', 'source', 'sql', 'stage', 'static2', 'store2',
            'support2', 'svn', 'sys', 'system', 'test2', 'testing', 'tools', 'upload',
            'uploads', 'user', 'users', 'video', 'vip', 'web2', 'webmail2', 'webmaster'
        ]

        # Enhanced common directories and files (A-Z)
        self.common_paths = [
            '/admin', '/login', '/wp-admin', '/administrator', '/phpmyadmin', '/mysql',
            '/backup', '/backups', '/.env', '/.git/config', '/.svn/entries', '/robots.txt',
            '/sitemap.xml', '/crossdomain.xml', '/server-status', '/phpinfo.php', '/test.php',
            '/config.php', '/wp-config.php', '/config.inc.php', '/.htaccess', '/.htpasswd',
            '/web.config', '/backup.zip', '/backup.tar.gz', '/backup.sql', '/dump.sql',
            '/old', '/old_site', '/temp', '/tmp', '/uploads', '/download', '/files',
            '/css', '/js', '/images', '/img', '/assets', '/static', '/media', '/wp-content/uploads',
            '/wp-config.php.bak', '/wp-config.php.save', '/wp-config.old', '/config.php.bak',
            '/config.inc.php.bak', '/database.php', '/db.php', '/settings.php', '/local.xml',
            '/app/etc/local.xml', '/configuration.php', '/includes/configure.php', '/includes/config.php',
            '/include/config.php', '/inc/config.php', '/conf/config.php', '/config/database.php',
            '/protected/config/database.php', '/application/config/database.php', '/system/config/database.php',
            '/api', '/v1', '/v2', '/api/v1', '/api/v2', '/rest', '/graphql', '/swagger', '/swagger-ui',
            '/adminer.php', '/adminer', '/admin/index.php', '/admin/login', '/administrator/index.php',
            '/dashboard', '/controlpanel', '/cp', '/cpanel', '/panel', '/manage', '/manager',
            '/console', '/setup', '/install', '/maint', '/maintenance', '/debug', '/info', '/status',
            '/health', '/metrics', '/actuator', '/actuator/health', '/actuator/info', '/actuator/env',
            '/env', '/.env.backup', '/.env.old', '/.env.save', '/.env.production', '/.env.local',
            '/.gitignore', '/.dockerignore', '/.travis.yml', '/composer.json', '/composer.lock',
            '/package.json', '/package-lock.json', '/yarn.lock', '/Gemfile', '/Gemfile.lock',
            '/requirements.txt', '/Pipfile', '/Pipfile.lock', '/Dockerfile', '/docker-compose.yml',
            '/Vagrantfile', '/Jenkinsfile', '/.circleci/config.yml', '/.github/workflows'
        ]

        # Additional backup and sensitive extensions
        self.backup_extensions = ['.sql', '.tar', '.tar.gz', '.tgz', '.zip', '.7z', '.rar', '.gz', '.bak', '.old', '.save', '.backup', '.swp', '.swo', '.~', '.log', '.txt', '.conf', '.ini', '.env', '.json', '.xml', '.yaml', '.yml', '.pem', '.key', '.crt', '.p12', '.pfx']
        
        # Build backup paths with extensions
        for ext in self.backup_extensions:
            self.common_paths.append(f'/backup{ext}')
            self.common_paths.append(f'/db{ext}')
            self.common_paths.append(f'/database{ext}')
            self.common_paths.append(f'/dump{ext}')
            self.common_paths.append(f'/data{ext}')
            self.common_paths.append(f'/config{ext}')

        # Ports to scan
        self.ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS', 587: 'SMTP (submission)', 993: 'IMAPS',
            995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB', 6379: 'Redis',
            11211: 'Memcached', 9200: 'Elasticsearch', 27018: 'MongoDB', 27019: 'MongoDB'
        }

        # Custom wordlist if provided
        self.custom_paths = []
        if wordlist and os.path.isfile(wordlist):
            try:
                with open(wordlist, 'r') as f:
                    self.custom_paths = [line.strip() for line in f if line.strip()]
            except:
                print(f"[-] Could not load wordlist from {wordlist}")

        # For progress bar
        self.pbar = None

    def log(self, message, category='info'):
        """Print and store result."""
        print(message)
        if category in self.results:
            self.results[category].append(message)

    def run_scan(self):
        """Main entry point."""
        self.log(f"\n{'='*80}")
        self.log(f"  [!] INITIATING ADVANCED A-Z RECONNAISSANCE: {self.domain.upper()}")
        self.log(f"  [!] SCAN TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log(f"{'='*80}\n")

        # Run modules
        self.get_domain_hosting_intel()
        self.get_dns_records()
        self.get_geo_location()
        self.get_ssl_certificate()
        self.get_http_headers_security()
        self.detect_cms()
        self.get_backend_tech()
        self.scan_ports()
        self.enumerate_subdomains()
        self.enumerate_directories_files()
        self.crawl_links()
        self.extract_emails()
        self.check_sensitive_files()
        self.check_admin_panels()
        self.check_exposed_credentials()
        self.check_vulnerabilities()  # XSS, SQLi, Open Redirect, etc.
        self.enumerate_http_methods()
        self.detect_api_endpoints()

        self.log(f"\n{'='*80}")
        self.log("  SCAN COMPLETED: ALL DATA EXTRACTED NIKHUTLY (PERFECTLY)")
        self.log(f"{'='*80}\n")

        # Save JSON if requested
        if self.output_json:
            try:
                with open(self.output_json, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=2, default=str)
                print(f"[+] Results saved to {self.output_json}")
            except Exception as e:
                print(f"[-] Failed to save JSON: {e}")

    def get_domain_hosting_intel(self):
        self.log("\n[1. DOMAIN, REGISTRAR & CONTACT INFO]")
        try:
            w = whois.whois(self.domain)
            self.log(f"  [+] Registrar        : {w.registrar}")
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            self.log(f"  [+] Creation Date    : {creation}")
            expiry = w.expiration_date
            if isinstance(expiry, list):
                expiry = expiry[0]
            self.log(f"  [+] Expiry Date      : {expiry}")
            self.log(f"  [+] Admin Email      : {w.emails if w.emails else 'Private/Not Found'}")
            self.log(f"  [+] Name Servers     : {w.name_servers}")
        except Exception as e:
            self.log(f"  [-] Domain Intel failed: {e}")

    def get_dns_records(self):
        self.log("\n[2. DNS RECORDS]")
        if not DNS_AVAILABLE:
            self.log("  [-] DNS module not installed. Skipping.")
            return
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
        for rec in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, rec)
                self.log(f"  [+] {rec} Records    : {', '.join(str(r) for r in answers)}")
            except:
                pass

    def get_geo_location(self):
        self.log("\n[3. SERVER IP & GEOGRAPHIC DETAILS]")
        try:
            ip = socket.gethostbyname(self.domain)
            self.log(f"  [+] Server IP        : {ip}")
            try:
                geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=self.timeout).json()
                if geo.get('status') == 'success':
                    self.log(f"  [+] Country          : {geo.get('country')} ({geo.get('countryCode')})")
                    self.log(f"  [+] Region/City      : {geo.get('regionName')}, {geo.get('city')}")
                    self.log(f"  [+] ISP/Hosting      : {geo.get('isp')}")
                    self.log(f"  [+] Latitude/Longitude: {geo.get('lat')}, {geo.get('lon')}")
                    self.log(f"  [+] ASN/Organization : {geo.get('as')}")
                else:
                    self.log("  [-] Geolocation API failed.")
            except:
                self.log("  [-] Geolocation lookup failed.")
        except Exception as e:
            self.log(f"  [-] IP resolution failed: {e}")

    def get_ssl_certificate(self):
        self.log("\n[4. SSL/TLS CERTIFICATE DETAILS]")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
            issuer = dict(x[0] for x in cert['issuer'])
            subject = dict(x[0] for x in cert['subject'])
            self.log(f"  [+] Issuer           : {issuer.get('organizationName', 'N/A')} ({issuer.get('commonName', 'N/A')})")
            self.log(f"  [+] Subject          : {subject.get('commonName', 'N/A')}")
            self.log(f"  [+] Valid From       : {cert['notBefore']}")
            self.log(f"  [+] Valid To         : {cert['notAfter']}")
            self.log(f"  [+] SAN              : {cert.get('subjectAltName', 'N/A')}")
            # Check expiry
            expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            if expire_date < datetime.now():
                self.log(f"  [!] Certificate EXPIRED!")
            else:
                days_left = (expire_date - datetime.now()).days
                self.log(f"  [+] Days left        : {days_left} days")
        except Exception as e:
            self.log(f"  [-] SSL certificate fetch failed: {e}")

    def get_http_headers_security(self):
        self.log("\n[5. HTTP SECURITY HEADERS ANALYSIS]")
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout, allow_redirects=True)
            headers = resp.headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'X-XSS-Protection': 'XSS filter',
                'Referrer-Policy': 'Referrer policy',
                'Permissions-Policy': 'Permissions policy'
            }
            for header, desc in security_headers.items():
                value = headers.get(header)
                if value:
                    self.log(f"  [+] {desc:<25}: {value}")
                else:
                    self.log(f"  [-] {desc:<25}: Not set")
            server = headers.get('Server')
            if server:
                self.log(f"  [+] Server Software  : {server}")
            # Cookies
            cookies = resp.cookies
            if cookies:
                self.log("  [+] Cookies:")
                for cookie in cookies:
                    flags = []
                    if cookie.secure:
                        flags.append('Secure')
                    if cookie.has_nonstandard_attr('HttpOnly'):
                        flags.append('HttpOnly')
                    if cookie.has_nonstandard_attr('SameSite'):
                        flags.append(f"SameSite={cookie.get_nonstandard_attr('SameSite')}")
                    self.log(f"      - {cookie.name}: {' '.join(flags) if flags else 'no flags'}")
        except Exception as e:
            self.log(f"  [-] Failed to fetch headers: {e}")

    def detect_cms(self):
        self.log("\n[6. CMS DETECTION (with version)]")
        cms_indicators = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-json', 'wp-login.php', '/wp-admin'],
            'Joomla': ['joomla', 'media/jui', 'components/com_content', 'administrator'],
            'Drupal': ['drupal', 'sites/default', 'core/misc', 'drupal.js'],
            'Magento': ['magento', 'skin/frontend', 'Mage_Core', 'Mage_Cookies'],
            'PrestaShop': ['prestashop', 'modules/blockcart', 'js/jquery/plugins'],
            'OpenCart': ['catalog/view/theme', 'index.php?route=common/home'],
            'Shopify': ['cdn.shopify.com', 'shopify'],
            'Wix': ['wix.com', 'static.wixstatic.com'],
            'Weebly': ['weebly.com', 'weebly-static'],
            'Squarespace': ['squarespace.com', 'static.squarespace'],
            'Ghost': ['ghost.org', 'ghost.js'],
            'Typo3': ['typo3', 'typo3temp'],
            'Concrete5': ['concrete5', 'concrete/js'],
            'SilverStripe': ['silverstripe', 'framework'],
            'CraftCMS': ['craftcms', 'craft/config']
        }
        detected = []
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            html = resp.text.lower()
            for cms, indicators in cms_indicators.items():
                for ind in indicators:
                    if ind in html:
                        detected.append(cms)
                        break
            if detected:
                self.log(f"  [+] Possible CMS(s): {', '.join(set(detected))}")
            else:
                self.log("  [-] No common CMS detected.")
        except Exception as e:
            self.log(f"  [-] CMS detection failed: {e}")

    def get_backend_tech(self):
        self.log("\n[7. BACKEND & FRONTEND TECHNOLOGIES]")
        if BUILTWITH_AVAILABLE:
            try:
                tech = builtwith.parse(self.base_url)
                for cat, apps in tech.items():
                    self.log(f"  [+] {cat.title()}: {', '.join(apps)}")
                    self.results['technologies'].extend(apps)
            except Exception as e:
                self.log(f"  [-] BuiltWith failed: {e}")
        else:
            self.log("  [-] BuiltWith not installed. Install with: pip install builtwith")

        if WAPPALYZER_AVAILABLE:
            try:
                webpage = WebPage.new_from_url(self.base_url, verify=False)
                wapp = Wappalyzer.latest()
                detected = wapp.analyze(webpage)
                if detected:
                    self.log("  [+] Wappalyzer Analysis:")
                    for tech in detected:
                        self.log(f"      - {tech}")
                        self.results['technologies'].append(tech)
                else:
                    self.log("  [+] Wappalyzer found no technologies.")
            except Exception as e:
                self.log(f"  [-] Wappalyzer failed: {e}")
        else:
            self.log("  [-] Wappalyzer not installed. Install with: pip install python-wappalyzer")

    def scan_ports(self):
        self.log("\n[8. PORT SCANNING]")
        try:
            ip = socket.gethostbyname(self.domain)
        except:
            self.log("  [-] Could not resolve IP for port scan.")
            return
        open_ports = []
        for port, service in self.ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                self.log(f"  [+] Port {port:<5} ({service:<15}): OPEN")
                open_ports.append(f"{port}:{service}")
            sock.close()
        self.results['ports'] = open_ports

    def enumerate_subdomains(self):
        self.log("\n[9. SUBDOMAIN ENUMERATION]")
        # First try crt.sh API for more subdomains
        try:
            crt_url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            resp = requests.get(crt_url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                subdomains = set()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        for sub in name.split('\n'):
                            if sub.endswith(f".{self.domain}"):
                                subdomains.add(sub.rstrip('.'))
                if subdomains:
                    self.log(f"  [+] Found {len(subdomains)} subdomains from crt.sh")
                    for sub in list(subdomains)[:30]:
                        self.log(f"      {sub}")
                        self.results['subdomains'].append(sub)
        except Exception as e:
            self.log(f"  [-] crt.sh API failed: {e}")

        # Then brute-force common subdomains
        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_sub = {executor.submit(self._check_subdomain, sub): sub for sub in self.common_subdomains}
            for future in concurrent.futures.as_completed(future_to_sub):
                result = future.result()
                if result:
                    found.append(result)
        if found:
            for sub in found:
                self.log(f"  [+] Found (brute): {sub}.{self.domain}")
                self.results['subdomains'].append(f"{sub}.{self.domain}")
        else:
            self.log("  [-] No additional subdomains found via brute.")

    def _check_subdomain(self, sub):
        try:
            socket.gethostbyname(f"{sub}.{self.domain}")
            return sub
        except:
            return None

    def enumerate_directories_files(self):
        self.log("\n[10. DIRECTORY & FILE ENUMERATION (with progress)]")
        paths_to_check = list(set(self.common_paths + self.custom_paths))
        found = []
        total = len(paths_to_check)
        if TQDM_AVAILABLE:
            pbar = tqdm(total=total, desc="Enumerating paths", unit="path")
        else:
            pbar = None

        def check(path):
            url = urljoin(self.base_url, path)
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in [200, 301, 302, 403]:
                    return (path, resp.status_code)
            except:
                pass
            return (path, None)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check, path): path for path in paths_to_check}
            for future in concurrent.futures.as_completed(futures):
                path, status = future.result()
                if status:
                    found.append((path, status))
                if pbar:
                    pbar.update(1)
        if pbar:
            pbar.close()

        if found:
            for path, status in found:
                self.log(f"  [!] Found: {self.base_url}{path} (HTTP {status})")
                self.results['directories'].append(f"{path} ({status})")
        else:
            self.log("  [-] No common directories/files found.")

    def crawl_links(self):
        if not BS4_AVAILABLE:
            self.log("\n[11. LINK CRAWLING]")
            self.log("  [-] BeautifulSoup not installed. Skipping.")
            return
        self.log("\n[11. LINK CRAWLING]")
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, 'html.parser')
            links = set()
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe']):
                src = tag.get('href') or tag.get('src')
                if src:
                    absolute = urljoin(self.base_url, src)
                    parsed = urlparse(absolute)
                    if parsed.netloc == self.domain or parsed.netloc == '':
                        links.add(absolute)
            if links:
                self.log(f"  [+] Found {len(links)} internal links (first 20 shown):")
                for i, link in enumerate(list(links)[:20]):
                    self.log(f"      {link}")
            else:
                self.log("  [-] No internal links found.")
        except Exception as e:
            self.log(f"  [-] Crawling failed: {e}")

    def extract_emails(self):
        self.log("\n[12. EMAIL EXTRACTION]")
        emails = set()
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            emails.update(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text))
            # Also crawl some pages to get more emails
            # For simplicity, we'll just use homepage and maybe sitemap
            sitemap_url = urljoin(self.base_url, '/sitemap.xml')
            try:
                sitemap_resp = self.session.get(sitemap_url, timeout=self.timeout)
                if sitemap_resp.status_code == 200:
                    emails.update(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', sitemap_resp.text))
            except:
                pass
            if emails:
                self.log(f"  [+] Found {len(emails)} unique email(s):")
                for email in emails:
                    self.log(f"      {email}")
                    self.results['emails'].append(email)
            else:
                self.log("  [-] No emails found.")
        except Exception as e:
            self.log(f"  [-] Email extraction failed: {e}")

    def check_sensitive_files(self):
        self.log("\n[13. SENSITIVE FILE CHECKS]")
        sensitive = [
            '/.env', '/.git/config', '/.svn/entries', '/wp-config.php.bak',
            '/config.php.bak', '/.htpasswd', '/.htaccess', '/web.config',
            '/backup.sql', '/dump.sql', '/error_log', '/debug.log',
            '/config.php', '/wp-config.php', '/configuration.php', '/settings.php',
            '/db.php', '/database.php', '/composer.json', '/composer.lock',
            '/package.json', '/package-lock.json', '/requirements.txt'
        ]
        found = []
        for path in sensitive:
            url = urljoin(self.base_url, path)
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    content = resp.text.lower()
                    if any(kw in content for kw in ['mysql', 'password', 'secret', 'api_key', 'database', 'dbuser', 'dbpass']):
                        found.append(f"{url} (contains sensitive data)")
                    else:
                        found.append(url)
            except:
                pass
        if found:
            for item in found:
                self.log(f"  [!] Potential sensitive file: {item}")
                self.results['vulns'].append(f"Sensitive file: {item}")
        else:
            self.log("  [-] No known sensitive files exposed.")

    def check_admin_panels(self):
        self.log("\n[14. ADMIN PANEL DETECTION]")
        admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/admin.php', '/login',
            '/admin/login', '/admin/index.php', '/backend', '/cp', '/cpanel',
            '/dashboard', '/manager', '/control', '/user', '/auth', '/signin',
            '/admincp', '/adminarea', '/admin_panel', '/adminpanel', '/manage',
            '/system', '/console', '/operator', '/moderator', '/staff', '/adm'
        ]
        found = []
        for path in admin_paths:
            url = urljoin(self.base_url, path)
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code in [200, 403, 401]:
                    found.append(f"{url} (HTTP {resp.status_code})")
            except:
                pass
        if found:
            self.log("  [+] Admin panels found:")
            for item in found:
                self.log(f"      {item}")
                self.results['admin_panels'].append(item)
        else:
            self.log("  [-] No admin panels detected.")

    def check_exposed_credentials(self):
        self.log("\n[15. CREDENTIALS IN EXPOSED FILES]")
        patterns = [
            (r'(?:DB_PASSWORD|DB_PASS|DB_PWD|PASSWORD|PASS|SECRET_KEY|API_KEY)\s*=\s*[\'"]([^\'"]+)[\'"]', 'database'),
            (r'(?:mysql|database)\.connect\(\s*[\'"]([^\'"]+)[\'"]', 'database'),
            (r'password\s*:\s*[\'"]([^\'"]+)[\'"]', 'JSON'),
            (r'\$db_password\s*=\s*[\'"]([^\'"]+)[\'"]', 'PHP'),
            (r'PASSWORD\s*=\s*([^\s]+)', 'INI'),
            (r'<password>([^<]+)</password>', 'XML'),
            (r'api_key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'API Key'),
            (r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Secret')
        ]
        credential_files = [
            '/.env', '/wp-config.php', '/config.php', '/configuration.php',
            '/app/etc/local.xml', '/includes/configure.php', '/settings.php',
            '/db.php', '/database.php', '/.env.local', '/.env.production'
        ]
        found_creds = []
        for f in credential_files:
            url = urljoin(self.base_url, f)
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    content = resp.text
                    for pattern, source in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            for match in matches:
                                cred_str = f"{url} -> {source}: {match}"
                                found_creds.append(cred_str)
                                self.results['credentials'].append(cred_str)
            except:
                pass
        if found_creds:
            self.log("  [!] Possible credentials found:")
            for cred in found_creds:
                self.log(f"      {cred}")
        else:
            self.log("  [-] No obvious credentials found in exposed files.")

    def check_vulnerabilities(self):
        self.log("\n[16. VULNERABILITY SCANNING (Basic)]")
        # Test for XSS
        xss_payload = "<script>alert('XSS')</script>"
        try:
            # Try to inject into URL parameters if any
            parsed = urlparse(self.base_url)
            if parsed.query:
                # Add xss payload to each parameter
                params = urllib.parse.parse_qs(parsed.query)
                for key in params:
                    test_url = f"{self.base_url}?{key}={xss_payload}"
                    resp = self.session.get(test_url, timeout=self.timeout)
                    if xss_payload in resp.text:
                        self.log(f"  [!] Possible XSS at {test_url}")
                        self.results['vulns'].append(f"XSS at {test_url}")
        except:
            pass

        # Test for SQL injection (simple)
        sqli_payloads = ["'", "\"", "1' OR '1'='1", "1 AND 1=1", "1 AND 1=2"]
        try:
            for payload in sqli_payloads:
                test_url = f"{self.base_url}?id={payload}"
                resp = self.session.get(test_url, timeout=self.timeout)
                if "mysql" in resp.text.lower() or "sql" in resp.text.lower() or "syntax" in resp.text.lower():
                    self.log(f"  [!] Possible SQLi at {test_url} (error message)")
                    self.results['vulns'].append(f"SQLi at {test_url}")
        except:
            pass

        # Open redirect detection
        redirect_url = "https://evil.com"
        test_url = f"{self.base_url}?redirect={redirect_url}"
        try:
            resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
            if resp.status_code in [301, 302] and redirect_url in resp.headers.get('Location', ''):
                self.log(f"  [!] Open redirect at {test_url}")
                self.results['vulns'].append(f"Open redirect at {test_url}")
        except:
            pass

        # Missing security headers already checked earlier
        # Could add more vulnerability checks (e.g., CORS misconfiguration, etc.)
        self.log("  [+] Vulnerability scan completed.")

    def enumerate_http_methods(self):
        self.log("\n[17. HTTP METHODS ENUMERATION]")
        methods = ['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
        allowed = []
        try:
            # Use OPTIONS request
            resp = self.session.options(self.base_url, timeout=self.timeout)
            if 'Allow' in resp.headers:
                allow_header = resp.headers['Allow']
                allowed = [m.strip() for m in allow_header.split(',')]
                self.log(f"  [+] Allowed methods (from OPTIONS): {', '.join(allowed)}")
            else:
                # Test each method individually
                for method in methods:
                    req = requests.Request(method, self.base_url)
                    prepared = req.prepare()
                    try:
                        resp = self.session.send(prepared, timeout=self.timeout)
                        if resp.status_code not in [405, 501]:
                            allowed.append(method)
                    except:
                        pass
                if allowed:
                    self.log(f"  [+] Allowed methods (trial): {', '.join(allowed)}")
                else:
                    self.log("  [-] No extra methods detected.")
        except Exception as e:
            self.log(f"  [-] HTTP methods enumeration failed: {e}")

    def detect_api_endpoints(self):
        self.log("\n[18. API ENDPOINT DETECTION]")
        api_paths = [
            '/api', '/v1', '/v2', '/api/v1', '/api/v2', '/api/v3', '/rest', '/graphql',
            '/swagger', '/swagger-ui', '/docs', '/api-docs', '/api/documentation', '/openapi',
            '/json', '/xml', '/rpc', '/soap', '/wsdl', '/odata', '/odata/v1', '/odata/v2'
        ]
        found = []
        for path in api_paths:
            url = urljoin(self.base_url, path)
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    found.append(url)
            except:
                pass
        if found:
            self.log("  [+] API endpoints found:")
            for endpoint in found:
                self.log(f"      {endpoint}")
        else:
            self.log("  [-] No obvious API endpoints found.")

def main():
    parser = argparse.ArgumentParser(description='WebsiteGrandMaster Pro - Advanced A-to-Z Website Scanner')
    parser.add_argument('-t', '--target', help='Target domain or URL (optional, will prompt if not given)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist for directory brute-forcing')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads for concurrent tasks (default: 10)')
    parser.add_argument('-o', '--output', help='Output file to save results (text)')
    parser.add_argument('--json', help='Output file to save JSON results')
    args = parser.parse_args()

    target = args.target
    if not target:
        target = input("ওয়েবসাইটের লিঙ্ক দিন (যেমন example.com): ").strip()
        if not target:
            print("No target provided. Exiting.")
            sys.exit(1)

    scanner = WebsiteGrandMasterPro(target, timeout=args.timeout, threads=args.threads,
                                    wordlist=args.wordlist, output_json=args.json)
    scanner.run_scan()

if __name__ == "__main__":
    main()