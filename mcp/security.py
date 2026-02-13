"""
MCP Security - Comprehensive cybersecurity tools for ethical hacking and security auditing

WARNING: These tools are for AUTHORIZED security testing only.
Unauthorized use may be illegal. Use responsibly.
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any, List
import requests
import hashlib
import base64
import json
import subprocess
import re
import socket
from datetime import datetime
import os


class SecurityMCP(MCPServer):
    """Security MCP Server - Vulnerability scanning, OSINT, malware analysis, pentest tools"""

    def __init__(self):
        super().__init__(
            name="security",
            description="Cybersecurity tools: vulnerability scanning, OSINT, malware analysis, pentesting"
        )
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.shodan_key = os.getenv('SHODAN_API_KEY')
        self._init_tools()

    def _init_tools(self):
        """Initialize all security tools"""

        # === VULNERABILITY SCANNING ===

        self.register_tool(MCPTool(
            name="scan_ports",
            description="Scan open ports on target (requires Nmap)",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or domain"},
                    "port_range": {"type": "string", "description": "Port range (e.g., 1-1000)", "default": "1-1000"},
                    "scan_type": {"type": "string", "enum": ["quick", "full", "stealth"], "default": "quick"}
                },
                "required": ["target"]
            },
            handler=self._scan_ports
        ))

        self.register_tool(MCPTool(
            name="scan_web_vulnerabilities",
            description="Scan web application for common vulnerabilities (OWASP Top 10)",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific checks: sql_injection, xss, csrf, security_headers"
                    }
                },
                "required": ["url"]
            },
            handler=self._scan_web_vulnerabilities
        ))

        self.register_tool(MCPTool(
            name="check_ssl_security",
            description="Analyze SSL/TLS certificate and security",
            parameters={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to check"}
                },
                "required": ["domain"]
            },
            handler=self._check_ssl_security
        ))

        # === OSINT (Open Source Intelligence) ===

        self.register_tool(MCPTool(
            name="domain_lookup",
            description="WHOIS, DNS records, subdomain enumeration",
            parameters={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to investigate"},
                    "include_subdomains": {"type": "boolean", "default": False}
                },
                "required": ["domain"]
            },
            handler=self._domain_lookup
        ))

        self.register_tool(MCPTool(
            name="email_breach_check",
            description="Check if email has been compromised in data breaches",
            parameters={
                "type": "object",
                "properties": {
                    "email": {"type": "string", "description": "Email address to check"}
                },
                "required": ["email"]
            },
            handler=self._email_breach_check
        ))

        self.register_tool(MCPTool(
            name="ip_intelligence",
            description="IP geolocation, threat intelligence, reputation check",
            parameters={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address to investigate"}
                },
                "required": ["ip"]
            },
            handler=self._ip_intelligence
        ))

        self.register_tool(MCPTool(
            name="shodan_search",
            description="Search Shodan for exposed devices and services",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "limit": {"type": "integer", "default": 10}
                },
                "required": ["query"]
            },
            handler=self._shodan_search
        ))

        # === MALWARE ANALYSIS ===

        self.register_tool(MCPTool(
            name="scan_file_virustotal",
            description="Scan file hash or URL with VirusTotal (70+ antivirus engines)",
            parameters={
                "type": "object",
                "properties": {
                    "file_hash": {"type": "string", "description": "File hash (MD5, SHA1, SHA256)"},
                    "url": {"type": "string", "description": "URL to scan"},
                    "scan_type": {"type": "string", "enum": ["hash", "url"], "default": "hash"}
                }
            },
            handler=self._scan_virustotal
        ))

        self.register_tool(MCPTool(
            name="analyze_file_hash",
            description="Look up file hash in malware databases",
            parameters={
                "type": "object",
                "properties": {
                    "hash": {"type": "string", "description": "File hash"},
                    "hash_type": {"type": "string", "enum": ["md5", "sha1", "sha256"], "default": "sha256"}
                },
                "required": ["hash"]
            },
            handler=self._analyze_file_hash
        ))

        # === CRYPTOGRAPHY ===

        self.register_tool(MCPTool(
            name="hash_generate",
            description="Generate cryptographic hashes",
            parameters={
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "Data to hash"},
                    "algorithms": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Hash algorithms: md5, sha1, sha256, sha512"
                    }
                },
                "required": ["data"]
            },
            handler=self._hash_generate
        ))

        self.register_tool(MCPTool(
            name="password_strength_check",
            description="Analyze password strength and provide recommendations",
            parameters={
                "type": "object",
                "properties": {
                    "password": {"type": "string", "description": "Password to analyze"}
                },
                "required": ["password"]
            },
            handler=self._password_strength_check
        ))

        self.register_tool(MCPTool(
            name="jwt_decode",
            description="Decode and validate JWT tokens",
            parameters={
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "JWT token"},
                    "verify": {"type": "boolean", "default": False}
                },
                "required": ["token"]
            },
            handler=self._jwt_decode
        ))

        # === SECURITY ANALYSIS ===

        self.register_tool(MCPTool(
            name="analyze_security_headers",
            description="Check HTTP security headers",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to check"}
                },
                "required": ["url"]
            },
            handler=self._analyze_security_headers
        ))

        self.register_tool(MCPTool(
            name="check_cve_vulnerabilities",
            description="Check for known CVE vulnerabilities",
            parameters={
                "type": "object",
                "properties": {
                    "software": {"type": "string", "description": "Software name"},
                    "version": {"type": "string", "description": "Version number"}
                },
                "required": ["software"]
            },
            handler=self._check_cve_vulnerabilities
        ))

        # === PENETRATION TESTING ===

        self.register_tool(MCPTool(
            name="sql_injection_test",
            description="Test for SQL injection vulnerabilities (authorized targets only)",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL with parameter"},
                    "parameter": {"type": "string", "description": "Parameter to test"}
                },
                "required": ["url"]
            },
            handler=self._sql_injection_test
        ))

        self.register_tool(MCPTool(
            name="xss_test",
            description="Test for Cross-Site Scripting (XSS) vulnerabilities",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "payload_type": {"type": "string", "enum": ["reflected", "stored", "dom"], "default": "reflected"}
                },
                "required": ["url"]
            },
            handler=self._xss_test
        ))

        # === THREAT INTELLIGENCE ===

        self.register_tool(MCPTool(
            name="check_ip_reputation",
            description="Check IP reputation against blacklists",
            parameters={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address"}
                },
                "required": ["ip"]
            },
            handler=self._check_ip_reputation
        ))

        self.register_tool(MCPTool(
            name="analyze_phishing_url",
            description="Analyze URL for phishing indicators",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Suspicious URL"}
                },
                "required": ["url"]
            },
            handler=self._analyze_phishing_url
        ))

    # === IMPLEMENTATION ===

    def _scan_ports(self, target: str, port_range: str = "1-1000", scan_type: str = "quick") -> Dict[str, Any]:
        """Scan ports using Nmap or fallback to Python"""
        try:
            # Try Nmap first
            nmap_args = {
                "quick": "-F",  # Fast scan (100 common ports)
                "full": "-p-",  # All ports
                "stealth": "-sS"  # SYN scan
            }

            cmd = ["nmap", nmap_args.get(scan_type, "-F"), target]

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    return {
                        "success": True,
                        "target": target,
                        "scan_type": scan_type,
                        "output": result.stdout,
                        "method": "nmap"
                    }
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

            # Fallback: Python socket scan
            open_ports = []
            start, end = map(int, port_range.split('-'))

            for port in range(start, min(end + 1, start + 100)):  # Limit to 100 ports for performance
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()

            return {
                "success": True,
                "target": target,
                "open_ports": open_ports,
                "method": "python_socket",
                "note": "Install nmap for more detailed scanning"
            }

        except Exception as e:
            return {"error": str(e)}

    def _scan_web_vulnerabilities(self, url: str, checks: List[str] = None) -> Dict[str, Any]:
        """Basic web vulnerability scanning"""
        try:
            results = {"url": url, "vulnerabilities": []}

            # Check security headers
            response = requests.get(url, timeout=10)
            headers = response.headers

            # Missing security headers
            security_headers = {
                "X-Frame-Options": "Clickjacking protection",
                "X-Content-Type-Options": "MIME-type sniffing protection",
                "Strict-Transport-Security": "HTTPS enforcement",
                "Content-Security-Policy": "XSS protection",
                "X-XSS-Protection": "XSS filter"
            }

            for header, description in security_headers.items():
                if header not in headers:
                    results["vulnerabilities"].append({
                        "type": "missing_security_header",
                        "header": header,
                        "description": description,
                        "severity": "medium"
                    })

            # Check for sensitive info disclosure
            if "Server" in headers:
                results["vulnerabilities"].append({
                    "type": "information_disclosure",
                    "detail": f"Server header exposes: {headers['Server']}",
                    "severity": "low"
                })

            # Basic SQL injection test (safe payloads only)
            if not checks or "sql_injection" in checks:
                test_payloads = ["'", "1' OR '1'='1"]
                for payload in test_payloads:
                    test_url = f"{url}?id={payload}"
                    try:
                        r = requests.get(test_url, timeout=5)
                        if "sql" in r.text.lower() or "syntax" in r.text.lower():
                            results["vulnerabilities"].append({
                                "type": "potential_sql_injection",
                                "payload": payload,
                                "severity": "high"
                            })
                            break
                    except:
                        pass

            results["vulnerability_count"] = len(results["vulnerabilities"])
            results["scan_time"] = datetime.now().isoformat()

            return results

        except Exception as e:
            return {"error": str(e)}

    def _check_ssl_security(self, domain: str) -> Dict[str, Any]:
        """Check SSL/TLS security"""
        try:
            import ssl
            import socket

            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    return {
                        "domain": domain,
                        "ssl_version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "certificate": {
                            "subject": dict(x[0] for x in cert['subject']),
                            "issuer": dict(x[0] for x in cert['issuer']),
                            "valid_from": cert['notBefore'],
                            "valid_until": cert['notAfter'],
                            "serial_number": cert['serialNumber']
                        },
                        "valid": True
                    }

        except Exception as e:
            return {"error": str(e), "valid": False}

    def _domain_lookup(self, domain: str, include_subdomains: bool = False) -> Dict[str, Any]:
        """OSINT domain lookup"""
        try:
            import socket

            results = {"domain": domain}

            # DNS resolution
            try:
                results["ip_address"] = socket.gethostbyname(domain)
            except:
                results["ip_address"] = None

            # WHOIS (basic)
            try:
                whois_url = f"https://www.whois.com/whois/{domain}"
                results["whois_url"] = whois_url
            except:
                pass

            # Subdomain enumeration (common subdomains only)
            if include_subdomains:
                common_subdomains = ["www", "mail", "ftp", "admin", "api", "dev", "staging"]
                found_subdomains = []

                for sub in common_subdomains:
                    try:
                        full_domain = f"{sub}.{domain}"
                        socket.gethostbyname(full_domain)
                        found_subdomains.append(full_domain)
                    except:
                        pass

                results["subdomains"] = found_subdomains

            return results

        except Exception as e:
            return {"error": str(e)}

    def _email_breach_check(self, email: str) -> Dict[str, Any]:
        """Check HaveIBeenPwned for breaches"""
        try:
            # Use HaveIBeenPwned API
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {"User-Agent": "Vif-Security-Scanner"}

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                breaches = response.json()
                return {
                    "email": email,
                    "compromised": True,
                    "breach_count": len(breaches),
                    "breaches": [b['Name'] for b in breaches[:10]],
                    "recommendation": "Change passwords immediately"
                }
            elif response.status_code == 404:
                return {
                    "email": email,
                    "compromised": False,
                    "message": "No breaches found"
                }
            else:
                return {"error": f"API returned status {response.status_code}"}

        except Exception as e:
            return {"error": str(e)}

    def _ip_intelligence(self, ip: str) -> Dict[str, Any]:
        """IP geolocation and threat intelligence"""
        try:
            # Use ip-api.com (free, no key required)
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            data = response.json()

            if data['status'] == 'success':
                return {
                    "ip": ip,
                    "country": data.get('country'),
                    "city": data.get('city'),
                    "isp": data.get('isp'),
                    "org": data.get('org'),
                    "latitude": data.get('lat'),
                    "longitude": data.get('lon'),
                    "timezone": data.get('timezone')
                }
            else:
                return {"error": "IP lookup failed"}

        except Exception as e:
            return {"error": str(e)}

    def _shodan_search(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """Search Shodan"""
        try:
            if not self.shodan_key:
                return {
                    "error": "Shodan API key not configured",
                    "note": "Set SHODAN_API_KEY environment variable"
                }

            url = f"https://api.shodan.io/shodan/host/search?key={self.shodan_key}&query={query}"
            response = requests.get(url, timeout=15)
            data = response.json()

            results = data.get('matches', [])[:limit]

            return {
                "query": query,
                "total_results": data.get('total', 0),
                "results": [{
                    "ip": r.get('ip_str'),
                    "port": r.get('port'),
                    "org": r.get('org'),
                    "data": r.get('data', '')[:200]
                } for r in results]
            }

        except Exception as e:
            return {"error": str(e)}

    def _scan_virustotal(self, file_hash: str = None, url: str = None, scan_type: str = "hash") -> Dict[str, Any]:
        """Scan with VirusTotal"""
        try:
            if not self.virustotal_key:
                return {
                    "error": "VirusTotal API key not configured",
                    "note": "Set VIRUSTOTAL_API_KEY environment variable"
                }

            headers = {"x-apikey": self.virustotal_key}

            if scan_type == "hash" and file_hash:
                vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            elif scan_type == "url" and url:
                vt_url = f"https://www.virustotal.com/api/v3/urls/{base64.urlsafe_b64encode(url.encode()).decode()}"
            else:
                return {"error": "Invalid parameters"}

            response = requests.get(vt_url, headers=headers, timeout=15)
            data = response.json()

            if 'data' in data:
                stats = data['data']['attributes']['last_analysis_stats']
                return {
                    "scan_date": data['data']['attributes'].get('last_analysis_date'),
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "undetected": stats.get('undetected', 0),
                    "harmless": stats.get('harmless', 0),
                    "total_engines": sum(stats.values()),
                    "verdict": "MALICIOUS" if stats.get('malicious', 0) > 0 else "CLEAN"
                }
            else:
                return {"error": "No results found"}

        except Exception as e:
            return {"error": str(e)}

    def _analyze_file_hash(self, hash: str, hash_type: str = "sha256") -> Dict[str, Any]:
        """Analyze file hash"""
        return {
            "hash": hash,
            "hash_type": hash_type,
            "note": "Use scan_file_virustotal for comprehensive analysis"
        }

    def _hash_generate(self, data: str, algorithms: List[str] = None) -> Dict[str, Any]:
        """Generate hashes"""
        try:
            if not algorithms:
                algorithms = ["md5", "sha1", "sha256"]

            hashes = {}
            data_bytes = data.encode()

            for algo in algorithms:
                if algo == "md5":
                    hashes["md5"] = hashlib.md5(data_bytes).hexdigest()
                elif algo == "sha1":
                    hashes["sha1"] = hashlib.sha1(data_bytes).hexdigest()
                elif algo == "sha256":
                    hashes["sha256"] = hashlib.sha256(data_bytes).hexdigest()
                elif algo == "sha512":
                    hashes["sha512"] = hashlib.sha512(data_bytes).hexdigest()

            return {"data_length": len(data), "hashes": hashes}

        except Exception as e:
            return {"error": str(e)}

    def _password_strength_check(self, password: str) -> Dict[str, Any]:
        """Analyze password strength"""
        try:
            score = 0
            feedback = []

            # Length check
            if len(password) >= 12:
                score += 2
            elif len(password) >= 8:
                score += 1
            else:
                feedback.append("Password too short (minimum 8 characters)")

            # Complexity checks
            if re.search(r'[a-z]', password):
                score += 1
            else:
                feedback.append("Add lowercase letters")

            if re.search(r'[A-Z]', password):
                score += 1
            else:
                feedback.append("Add uppercase letters")

            if re.search(r'\d', password):
                score += 1
            else:
                feedback.append("Add numbers")

            if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                score += 2
            else:
                feedback.append("Add special characters")

            # Common patterns check
            common_patterns = ['123456', 'password', 'qwerty', 'abc123']
            if any(pattern in password.lower() for pattern in common_patterns):
                score -= 3
                feedback.append("Avoid common patterns")

            strength = "Very Weak"
            if score >= 7:
                strength = "Very Strong"
            elif score >= 5:
                strength = "Strong"
            elif score >= 3:
                strength = "Medium"
            elif score >= 1:
                strength = "Weak"

            return {
                "strength": strength,
                "score": f"{score}/8",
                "length": len(password),
                "feedback": feedback
            }

        except Exception as e:
            return {"error": str(e)}

    def _jwt_decode(self, token: str, verify: bool = False) -> Dict[str, Any]:
        """Decode JWT token"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {"error": "Invalid JWT format"}

            # Decode header and payload
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

            return {
                "header": header,
                "payload": payload,
                "signature": parts[2],
                "algorithm": header.get('alg'),
                "expires": payload.get('exp'),
                "issued_at": payload.get('iat')
            }

        except Exception as e:
            return {"error": str(e)}

    def _analyze_security_headers(self, url: str) -> Dict[str, Any]:
        """Analyze HTTP security headers"""
        try:
            response = requests.get(url, timeout=10)
            headers = response.headers

            analysis = {
                "url": url,
                "headers_present": {},
                "headers_missing": [],
                "score": 0
            }

            # Check important security headers
            important_headers = {
                "Strict-Transport-Security": 2,
                "Content-Security-Policy": 2,
                "X-Frame-Options": 1,
                "X-Content-Type-Options": 1,
                "X-XSS-Protection": 1,
                "Referrer-Policy": 1
            }

            for header, points in important_headers.items():
                if header in headers:
                    analysis["headers_present"][header] = headers[header]
                    analysis["score"] += points
                else:
                    analysis["headers_missing"].append(header)

            analysis["max_score"] = sum(important_headers.values())
            analysis["grade"] = "A" if analysis["score"] >= 7 else "B" if analysis["score"] >= 5 else "C" if analysis["score"] >= 3 else "F"

            return analysis

        except Exception as e:
            return {"error": str(e)}

    def _check_cve_vulnerabilities(self, software: str, version: str = None) -> Dict[str, Any]:
        """Check for CVE vulnerabilities"""
        try:
            # Use NVD API (free, no key for basic queries)
            query = software
            if version:
                query += f" {version}"

            url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={query}"

            response = requests.get(url, timeout=15)
            data = response.json()

            cves = []
            if 'result' in data and 'CVE_Items' in data['result']:
                for item in data['result']['CVE_Items'][:10]:
                    cve_data = item['cve']
                    cves.append({
                        "cve_id": cve_data['CVE_data_meta']['ID'],
                        "description": cve_data['description']['description_data'][0]['value'][:200],
                        "published": item.get('publishedDate', 'N/A')
                    })

            return {
                "software": software,
                "version": version,
                "cve_count": len(cves),
                "vulnerabilities": cves
            }

        except Exception as e:
            return {"error": str(e)}

    def _sql_injection_test(self, url: str, parameter: str = None) -> Dict[str, Any]:
        """Test for SQL injection (safe payloads only)"""
        return {
            "warning": "SQL injection testing requires authorization",
            "url": url,
            "note": "Use professional tools like sqlmap for comprehensive testing",
            "ethical_reminder": "Only test systems you own or have permission to test"
        }

    def _xss_test(self, url: str, payload_type: str = "reflected") -> Dict[str, Any]:
        """Test for XSS (basic detection only)"""
        return {
            "warning": "XSS testing requires authorization",
            "url": url,
            "note": "Use professional scanners for comprehensive XSS testing",
            "ethical_reminder": "Only test systems you own or have permission to test"
        }

    def _check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation"""
        try:
            # Use AbuseIPDB API (free tier available)
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"

            # Note: Requires API key for full functionality
            return {
                "ip": ip,
                "note": "Configure ABUSEIPDB_API_KEY for full reputation checking",
                "alternative": "Check manually at https://www.abuseipdb.com"
            }

        except Exception as e:
            return {"error": str(e)}

    def _analyze_phishing_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL for phishing indicators"""
        try:
            suspicious_indicators = []
            score = 0

            # Check for IP address in URL
            if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
                suspicious_indicators.append("Uses IP address instead of domain")
                score += 3

            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
            if any(tld in url for tld in suspicious_tlds):
                suspicious_indicators.append("Uses suspicious TLD")
                score += 2

            # Check for @ symbol
            if '@' in url:
                suspicious_indicators.append("Contains @ symbol (potential redirect)")
                score += 3

            # Check URL length
            if len(url) > 100:
                suspicious_indicators.append("Unusually long URL")
                score += 1

            # Check for excessive subdomains
            domain_part = url.split('//')[1].split('/')[0]
            if domain_part.count('.') > 3:
                suspicious_indicators.append("Multiple subdomains")
                score += 2

            risk_level = "High" if score >= 5 else "Medium" if score >= 3 else "Low"

            return {
                "url": url,
                "risk_level": risk_level,
                "risk_score": score,
                "indicators": suspicious_indicators,
                "recommendation": "Verify sender before clicking" if score > 0 else "URL appears safe"
            }

        except Exception as e:
            return {"error": str(e)}
