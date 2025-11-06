
import re, dns.resolver

def infer_alignment(headers: dict, from_addr: str, return_path: str):
    auth_results = headers.get("auth_results", {})
    arc = headers.get("arc", {})
    received_spf = headers.get("received_spf", [])
    
    spf = (auth_results or {}).get("spf")
    dkim_list = (auth_results or {}).get("dkim") or []
    dmarc = (auth_results or {}).get("dmarc")
    
    # Parse ARC chain
    arc_chain = parse_arc_chain(headers)
    arc_cv = arc_chain.get("cv")
    
    # Parse ARC-Authentication-Results for additional results
    arc_spf, arc_dkim_list, arc_dmarc = None, [], None
    for ar in arc.get("auth_results", []):
        ar_lower = ar.lower()
        m_spf = re.search(r"spf=(pass|fail|softfail|neutral|temperror|permerror)", ar_lower)
        if m_spf: arc_spf = m_spf.group(1)
        for m in re.finditer(r"dkim=(pass|fail|none)[^;]*;[^d]*d=([^;\s]+)", ar_lower):
            arc_dkim_list.append({"result": m.group(1), "d": m.group(2)})
        m_dmarc = re.search(r"dmarc=(pass|fail|temperror|permerror)", ar_lower)
        if m_dmarc: arc_dmarc = m_dmarc.group(1)
    
    # Parse Received-SPF - get the first result (most recent)
    received_spf_result = None
    if received_spf and len(received_spf) > 0 and received_spf[0].get("result"):
        received_spf_result = received_spf[0]["result"]
    
    from_domain = _extract_domain(from_addr)
    rp_domain = _extract_domain(return_path)
    dkim_domains = [d.get("d") for d in dkim_list if d.get("d")]
    arc_dkim_domains = [d.get("d") for d in arc_dkim_list if d.get("d")]
    aligned = any(d == from_domain for d in dkim_domains)
    arc_aligned = any(d == from_domain for d in arc_dkim_domains)
    
    # Fetch DMARC policy
    dmarc_policy = fetch_dmarc_policy(from_domain)
    
    # Determine DMARC alignment (simplified: strict if adkim/aspf = s, relaxed if r)
    spf_aligned = rp_domain == from_domain  # Simplified SPF alignment
    dkim_aligned = aligned
    dmarc_pass = False
    if dmarc_policy:
        dmarc_pass = ((dmarc_policy.get("adkim", "r") == "s" and dkim_aligned) or 
                      (dmarc_policy.get("adkim", "r") == "r" and any(d.endswith(from_domain) for d in dkim_domains))) and \
                     ((dmarc_policy.get("aspf", "r") == "s" and spf_aligned) or 
                      (dmarc_policy.get("aspf", "r") == "r" and rp_domain.endswith(from_domain)))
    
    result = {
        "spf": {"result": spf, "mailfrom": rp_domain},
        "dkim": {"present": bool(dkim_list), "aligned": aligned, "d_list": dkim_domains},
        "dmarc": {"inferred_result": dmarc, "policy": dmarc_policy, "aligned": dmarc_pass},
        "arc": {
            "spf": {"result": arc_spf},
            "dkim": {"present": bool(arc_dkim_list), "aligned": arc_aligned, "d_list": arc_dkim_domains},
            "dmarc": {"result": arc_dmarc},
            "cv": arc_cv
        },
        "received_spf_result": received_spf_result
    }
    return result

def _extract_domain(addr: str):
    if not addr: return ""
    m = re.search(r"<([^>]+)>", addr)
    email_ = m.group(1) if m else addr
    m2 = re.search(r"@([^>]+)$", email_.strip())
    return (m2.group(1) if m2 else "").strip().lower()

def parse_arc_chain(headers) -> dict:
    """Extract ARC-Authentication-Results, ARC-Seal, cv=(pass|fail|none) from last set."""
    arc = headers.get("arc", {})
    auth_results = arc.get("auth_results", [])
    seals = arc.get("seals", [])
    
    # Find the highest ARC set number
    max_set = 0
    for seal in seals:
        m = re.search(r'i=(\d+)', seal.lower())
        if m:
            set_num = int(m.group(1))
            max_set = max(max_set, set_num)
    
    # Extract from the last (highest) set
    last_auth_result = None
    last_cv = None
    
    for ar in auth_results:
        m_set = re.search(r'arc=(\d+)', ar.lower())
        if m_set and int(m_set.group(1)) == max_set:
            last_auth_result = ar
            break
    
    # Extract cv from ARC-Seal
    for seal in seals:
        m_set = re.search(r'i=(\d+)', seal.lower())
        m_cv = re.search(r'cv=(pass|fail|none)', seal.lower())
        if m_set and m_cv and int(m_set.group(1)) == max_set:
            last_cv = m_cv.group(1)
            break
    
    return {
        "last_auth_result": last_auth_result,
        "cv": last_cv,
        "max_set": max_set
    }

def fetch_dmarc_policy(from_domain) -> dict:
    """Fetch DMARC policy from _dmarc.domain TXT record."""
    if not from_domain:
        return {"policy": "none"}
    try:
        answers = dns.resolver.resolve(f"_dmarc.{from_domain}", "TXT")
        for rdata in answers:
            txt = "".join(str(s) for s in rdata.strings)
            # Parse DMARC record for policy
            parts = [p.strip() for p in txt.split(";") if p.strip()]
            policy = "none"
            for part in parts:
                if part.lower().startswith("p="):
                    p_value = part.split("=", 1)[1].strip().lower()
                    if p_value in ["none", "quarantine", "reject"]:
                        policy = p_value
                    break
            return {"policy": policy}
    except Exception:
        pass
    return {"policy": "none"}
