import os, sys, json, re
from urllib.parse import urlparse
from paw.core import parser_mail
from paw.intelligence.criminal_hunter import CriminalHunter
from bs4 import BeautifulSoup
import requests

EML_PATH = os.path.join('inbox', 'Ultimo tentativo per dacangs@hotmail.it, il tuo kit di emergenza per auto GRATUITO ti aspetta....eml')
OUT_PATH = os.path.join('paw', 'intelligence', 'last_hunt_multi.json')

if not os.path.exists(EML_PATH):
    print('EML file not found:', EML_PATH)
    sys.exit(1)

print('Parsing:', EML_PATH)
parsed = parser_mail.parse_mail(EML_PATH)

# Extract HTML part manually
from email import policy
from email.parser import BytesParser
with open(EML_PATH, 'rb') as f:
    msg = BytesParser(policy=policy.default).parsebytes(f.read())

html = None
for part in msg.walk():
    ctype = part.get_content_type()
    if ctype == 'text/html':
        try:
            html = part.get_content()
        except Exception:
            html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
        break

urls = set()
if html:
    soup = BeautifulSoup(html, 'html.parser')
    # extract href and src
    for tag in soup.find_all(['a','img','iframe','script','link','input']):
        for attr in ('href','src','action','data-src'):
            v = tag.get(attr)
            if v:
                urls.add(v)
    # also catch short urls in plaintext
    for m in re.finditer(r'https?://[^\s"\'<>]+', html):
        urls.add(m.group(0))

# fallback: also search plaintext parts
if not urls:
    for part in msg.walk():
        if part.get_content_type() == 'text/plain':
            txt = part.get_content()
            for m in re.finditer(r'https?://[^\s"\'<>]+', str(txt)):
                urls.add(m.group(0))

print('Found URLs:', len(urls))
for u in urls:
    print(' -', u)

# Resolve redirects (HEAD) and collect hostnames
resolved_hosts = set()
MAX_URLS = 12
count = 0
for u in urls:
    if count >= MAX_URLS:
        break
    try:
        # Some links are javascript or data: ignore
        if u.startswith('javascript:') or u.startswith('data:'):
            continue
        # If relative path, skip
        if u.startswith('/'):
            continue
        # Normalize
        if not u.startswith('http'):
            u = 'http://' + u
        parsed_u = urlparse(u)
        host = parsed_u.hostname
        # If the host looks like a known shortener, attempt to follow redirect; otherwise only collect hostname
        shorteners = ('bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'shorturl.at')
        final = u
        if host and host.lower() in shorteners:
            try:
                r = requests.head(u, allow_redirects=True, timeout=6, verify=False)
                final = r.url
            except Exception:
                try:
                    r = requests.get(u, allow_redirects=True, timeout=8, verify=False)
                    final = r.url
                except Exception as e:
                    print('Redirect follow failed for', u, '->', e)
                    final = u
        parsed_final = urlparse(final)
        final_host = parsed_final.hostname
        if final_host:
            resolved_hosts.add(final_host.lower())
        else:
            if host:
                resolved_hosts.add(host.lower())
        count += 1
    except Exception as e:
        print('Resolve error for', u, '->', e)

print('Resolved hosts:', resolved_hosts)

hunter = CriminalHunter()
results = {}
for host in sorted(resolved_hosts):
    try:
        print('\n---- Hunting:', host)
        r = hunter.hunt_from_domain(host)
        results[host] = r
    except Exception as e:
        print('Hunter error for', host, e)
        results[host] = {'error': str(e)}

with open(OUT_PATH, 'w', encoding='utf-8') as f:
    json.dump({'eml_parsed_headers': parsed, 'found_urls': list(urls), 'resolved_hosts': list(resolved_hosts), 'hunts': results}, f, indent=2)

print('\nWrote results to', OUT_PATH)
