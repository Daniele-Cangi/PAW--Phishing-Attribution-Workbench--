import json
import re
import socket
import ssl
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAST = ROOT / 'intelligence' / 'last_hunt.json'


def safe_getcert(host, port=443, max_retries=3, backoff=1.0, initial_timeout=5, timeout_increment=2):
    for attempt in range(max_retries):
        timeout = initial_timeout + attempt * timeout_increment
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    return cert
        except Exception as e:
            if attempt < max_retries - 1:
                sleep_time = backoff * (2 ** attempt)  # exponential backoff
                time.sleep(sleep_time)
            else:
                return {'error': str(e)}


def grab_banner(ip, port, timeout=2):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8080, 8000, 8008):
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                except Exception:
                    pass
            try:
                data = s.recv(1024)
                return data.decode('utf-8', errors='replace')
            except Exception as e:
                return '{"recv_error":"%s"}' % e
    except Exception as e:
        return '{"connect_error":"%s"}' % e


def reverse_dns(ip):
    try:
        name = socket.gethostbyaddr(ip)
        return {'ptr': name[0], 'aliases': name[1], 'addrs': name[2]}
    except Exception as e:
        return {'error': str(e)}


def whois_lookup(domain, timeout=5):
    try:
        # For .com domains, use Verisign WHOIS
        server = 'whois.verisign-grs.com'
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.sendall((domain + '\r\n').encode())
            response = b''
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
        text = response.decode('utf-8', errors='replace')
        # Parse key fields
        registrar = re.search(r'Registrar:\s*(.+)', text, re.I)
        org = re.search(r'Registrant Organization:\s*(.+)', text, re.I) or re.search(r'Organization:\s*(.+)', text, re.I)
        created = re.search(r'Creation Date:\s*(.+)', text, re.I)
        return {
            'registrar': registrar.group(1).strip() if registrar else None,
            'organization': org.group(1).strip() if org else None,
            'creation_date': created.group(1).strip() if created else None,
            'raw': text[:500]  # limit raw for brevity
        }
    except Exception as e:
        return {'error': str(e)}


def asn_lookup(ip, timeout=5):
    try:
        server = 'whois.cymru.com'
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.sendall(('-v ' + ip + '\r\n').encode())
            response = b''
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
        text = response.decode('utf-8', errors='replace')
        lines = text.strip().split('\n')
        if len(lines) > 1:
            parts = lines[1].split('|')
            if len(parts) >= 5:
                return {
                    'asn': parts[0].strip(),
                    'prefix': parts[2].strip(),
                    'country': parts[3].strip(),
                    'registry': parts[4].strip(),
                    'allocated': parts[5].strip() if len(parts) > 5 else None
                }
        return {'error': 'No ASN data found'}
    except Exception as e:
        return {'error': str(e)}


def main():
    if not LAST.exists():
        print('last_hunt.json not found at', LAST)
        return

    data = json.loads(LAST.read_text(encoding='utf-8'))
    
    # Handle both single hunt and multi-hunt formats
    if 'hunts' in data:
        # Multi-hunt format
        for domain, hunt_data in data['hunts'].items():
            print(f'Enriching {domain}...')
            enrichment = enrich_single_hunt(hunt_data)
            hunt_data['enrichment'] = enrichment
    else:
        # Single hunt format (backward compatibility)
        enrichment = enrich_single_hunt(data)
        data['enrichment'] = enrichment

    LAST.write_text(json.dumps(data, indent=2), encoding='utf-8')
    print('Enrichment written to', LAST)


def enrich_single_hunt(hunt_data):
    enrichment = {}
    ips = [r.get('ip') for r in hunt_data.get('real_ips', []) if r.get('ip')]

    for ip in ips:
        info = {}
        # reverse DNS
        info['reverse_dns'] = reverse_dns(ip)

        # try SSL cert against domain if available
        host = hunt_data.get('target_domain')
        cert = safe_getcert(host, 443, max_retries=3, backoff=1.0, initial_timeout=5, timeout_increment=2)
        info['ssl_cert_host'] = cert

        # gather banners on a few common ports
        ports = set(hunt_data.get('infrastructure', {}).get('open_ports', []) + [22, 80, 443, 8080])
        port_info = {}
        for p in sorted(ports):
            port_info[p] = grab_banner(ip, p)
        info['port_banners'] = port_info

        # WHOIS lookup for domain
        info['whois'] = whois_lookup(hunt_data.get('target_domain'))

        # ASN lookup for IP
        info['asn'] = asn_lookup(ip)

        # Rate limiting
        time.sleep(1)

        enrichment[ip] = info
    
    return enrichment


if __name__ == '__main__':
    main()
