import json
from ipwhois import IPWhois
p='cases/case-2025-10-28T105745Z-32e9/origin.json'
with open(p,'r',encoding='utf-8') as f:
    orig=json.load(f)
ip=orig.get('ip')
res={}
try:
    # First, try lookup_whois() for ASN
    r_asn = IPWhois(ip).lookup_whois()
    asn_raw = r_asn.get('asn')
    try:
        asn = int(asn_raw) if asn_raw and str(asn_raw).isdigit() else None
    except Exception:
        asn = None
    
    asn_org = None
    cc = None
    abuse = []
    
    # Use nets for org and abuse if ASN is NA
    nets = r_asn.get('nets', [])
    if nets:
        net = nets[0]
        if not asn_org:
            asn_org = net.get('name') or net.get('description')
        if not abuse:
            emails = net.get('emails', [])
            for e in emails:
                if e and '@' in e:
                    abuse.append({'type': 'email', 'value': e})
    
    # Then, RDAP for additional org/cc/abuse
    r = IPWhois(ip).lookup_rdap(asn_methods=['whois','http'])
    asn_org_desc = r.get('asn_description')
    if not asn_org:
        asn_org = asn_org_desc if asn_org_desc and asn_org_desc != 'NA' else (r.get('network') or {}).get('name') or None
    if not cc:
        cc = (r.get('asn_country_code') or (r.get('network') or {}).get('country') or '')
        cc = cc.upper() if cc else None
    # abuse from RDAP if not already set
    if not abuse:
        for ent in (r.get('entities') or []):
            obj = (r.get('objects') or {}).get(ent, {})
            roles = obj.get('roles', [])
            contact = obj.get('contact', {})
            emails = contact.get('email') or []
            if 'abuse' in roles or 'security' in roles:
                for e in emails:
                    if isinstance(e, dict) and e.get('value'):
                        abuse.append({'type': 'email', 'value': e['value']})
                    elif isinstance(e, str):
                        abuse.append({'type': 'email', 'value': e})
    res = {'asn': asn, 'asn_org': asn_org, 'cc': cc, 'abuse': abuse}
except Exception as e:
    res = {'error': str(e)}
# merge into orig and write back
orig.update({'asn': res.get('asn'),'org': res.get('asn_org'),'cc': res.get('cc'),'abuse': res.get('abuse') or []})
with open(p,'w',encoding='utf-8') as f:
    json.dump(orig,f,indent=2)
print(json.dumps(orig,indent=2))
