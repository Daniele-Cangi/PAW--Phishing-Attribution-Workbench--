import socket
import requests
from typing import Dict, List

class InfrastructureMapper:
    """Mappa avanzata dell'infrastruttura criminale"""
    
    def __init__(self):
        self.session = requests.Session()
    
    def comprehensive_map(self, domain: str, ips: List[str]) -> Dict:
        """Mappa completa dell'infrastruttura"""
        return {
            'network_analysis': self._analyze_network(ips),
            'service_detection': self._detect_services(ips),
            'cdn_detection': self._detect_cdn(domain, ips),
            'infrastructure_timeline': self._build_timeline(domain)
        }
    
    def _analyze_network(self, ips: List[str]) -> Dict:
        """Analisi della rete criminale"""
        network_data = {}
        for ip in ips:
            # WHOIS information
            whois_data = self._get_whois_info(ip)
            # Port scanning (limitato)
            open_ports = self._quick_port_scan(ip)
            
            network_data[ip] = {
                'whois': whois_data,
                'open_ports': open_ports,
                'network_range': self._find_network_range(ip)
            }
        return network_data
    
    def _detect_services(self, ips: List[str]) -> Dict:
        """Rileva servizi in esecuzione"""
        common_ports = [80, 443, 21, 22, 25, 53, 110, 143, 993, 995]
        services = {}
        
        for ip in ips:
            services[ip] = []
            for port in common_ports:
                if self._check_port(ip, port):
                    service = self._identify_service(ip, port)
                    services[ip].append({
                        'port': port,
                        'service': service,
                        'banner': self._get_banner(ip, port)
                    })
        return services
    
    def _detect_cdn(self, domain: str, ips: List[str]) -> bool:
        """Rileva se sta usando CDN (Cloudflare, Akamai, etc.)"""
        cdn_ips = [
            '104.16.0.0/12',  # Cloudflare
            '173.245.48.0/20', # Cloudflare
            '188.114.96.0/20', # Cloudflare
            '131.0.72.0/22',   # Akamai
            '184.24.0.0/13'    # Akamai
        ]
        
        for ip in ips:
            for cdn_range in cdn_ips:
                if self._ip_in_range(ip, cdn_range):
                    return True
        return False
    
    def _build_timeline(self, domain: str) -> List[Dict]:
        """Build real infrastructure timeline from multiple sources"""
        timeline = []

        # 1. Get domain registration date from WHOIS
        whois_data = self._get_whois_info(domain)
        if whois_data.get('creation_date'):
            timeline.append({
                'date': whois_data['creation_date'],
                'event': 'Domain registered',
                'source': 'WHOIS'
            })

        # 2. Get SSL certificate history from Certificate Transparency logs
        ct_events = self._query_certificate_transparency(domain)
        timeline.extend(ct_events)

        # 3. Add current analysis timestamp
        from datetime import datetime
        timeline.append({
            'date': datetime.now().isoformat(),
            'event': 'Infrastructure analysis performed',
            'source': 'PAW Analysis'
        })

        # Sort by date
        timeline.sort(key=lambda x: x.get('date', ''), reverse=False)

        return timeline

    def _query_certificate_transparency(self, domain: str) -> List[Dict]:
        """Query Certificate Transparency logs for SSL certificate history"""
        try:
            import requests
            import json

            # Use crt.sh API (public CT log aggregator)
            url = f"https://crt.sh/?q={domain}&output=json"

            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                return []

            certs = response.json()
            events = []

            # Process certificate data
            seen_dates = set()
            for cert in certs[:10]:  # Limit to 10 most recent
                entry_timestamp = cert.get('entry_timestamp')
                if entry_timestamp and entry_timestamp not in seen_dates:
                    seen_dates.add(entry_timestamp)
                    events.append({
                        'date': entry_timestamp,
                        'event': f"SSL certificate issued (Issuer: {cert.get('issuer_name', 'Unknown')})",
                        'source': 'Certificate Transparency',
                        'common_name': cert.get('common_name', domain),
                        'serial_number': cert.get('serial_number', 'Unknown')
                    })

            return events

        except ImportError:
            # requests not available
            return []
        except Exception as e:
            return [{'date': 'Unknown', 'event': f'CT query failed: {str(e)}', 'source': 'Error'}]
    
    def _get_whois_info(self, ip: str) -> Dict:
        """Real WHOIS lookup for IP address"""
        try:
            import whois
            w = whois.whois(ip)

            return {
                'registrar': w.registrar if hasattr(w, 'registrar') else None,
                'organization': w.org if hasattr(w, 'org') else None,
                'creation_date': str(w.creation_date) if hasattr(w, 'creation_date') else None,
                'expiration_date': str(w.expiration_date) if hasattr(w, 'expiration_date') else None,
                'updated_date': str(w.updated_date) if hasattr(w, 'updated_date') else None,
                'name_servers': w.name_servers if hasattr(w, 'name_servers') else [],
                'emails': w.emails if hasattr(w, 'emails') else [],
                'address': w.address if hasattr(w, 'address') else None,
                'city': w.city if hasattr(w, 'city') else None,
                'state': w.state if hasattr(w, 'state') else None,
                'country': w.country if hasattr(w, 'country') else None,
            }
        except ImportError:
            # Fallback to raw socket WHOIS
            return self._get_whois_info_raw(ip)
        except Exception as e:
            return {'error': str(e), 'status': 'failed'}

    def _get_whois_info_raw(self, ip: str) -> Dict:
        """Fallback raw WHOIS via socket"""
        try:
            import socket
            whois_server = 'whois.iana.org'

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)
                sock.connect((whois_server, 43))
                sock.send(f"{ip}\r\n".encode())

                response = b''
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk

                text = response.decode('utf-8', errors='ignore')

                # Parse key fields
                parsed = {'raw': text}
                for line in text.splitlines():
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip().lower().replace(' ', '_')
                        value = value.strip()
                        if key in ['organization', 'org', 'country', 'netname', 'abuse']:
                            parsed[key] = value

                return parsed
        except Exception as e:
            return {'error': str(e), 'status': 'failed'}
    
    def _quick_port_scan(self, ip: str) -> List[int]:
        """Scansione porte veloce"""
        open_ports = []
        ports_to_check = [80, 443, 21, 22, 25]
        
        for port in ports_to_check:
            if self._check_port(ip, port):
                open_ports.append(port)
        
        return open_ports
    
    def _check_port(self, ip: str, port: int, timeout: float = 2.0) -> bool:
        """Controlla se una porta è aperta"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                return result == 0
        except:
            return False
    
    def _identify_service(self, ip: str, port: int) -> str:
        """Identifica servizio sulla porta"""
        service_map = {
            80: 'HTTP',
            443: 'HTTPS', 
            21: 'FTP',
            22: 'SSH',
            25: 'SMTP',
            53: 'DNS'
        }
        return service_map.get(port, 'Unknown')
    
    def _get_banner(self, ip: str, port: int) -> str:
        """Prova a ottenere banner del servizio"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                sock.connect((ip, port))
                if port in [80, 443]:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner[:500]  # Limita lunghezza
        except:
            return "No banner"
    
    def _find_network_range(self, ip: str) -> str:
        """Stima il range di rete"""
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    
    def _ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Controlla se IP è in un range specifico"""
        # Implementazione semplificata
        base_ip = ip_range.split('/')[0]
        return ip.startswith('.'.join(base_ip.split('.')[:2]))
