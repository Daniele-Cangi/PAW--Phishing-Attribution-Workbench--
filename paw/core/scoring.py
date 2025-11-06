
import re

def brand_label(domain: str):
    # Leftmost label
    if not domain: return ""
    return domain.split(".")[0].lower()

def levenshtein(a: str, b: str):
    if a == b: return 0
    if len(a) == 0: return len(b)
    if len(b) == 0: return len(a)
    v0 = list(range(len(b)+1))
    v1 = [0]*(len(b)+1)
    for i in range(len(a)):
        v1[0] = i+1
        for j in range(len(b)):
            cost = 0 if a[i]==b[j] else 1
            v1[j+1] = min(v1[j]+1, v0[j+1]+1, v0[j]+cost)
        v0, v1 = v1, v0
    return v0[len(b)]

def bk_similarity(label: str, brand: str):
    if not label or not brand: return 0.0
    L = max(len(label), len(brand))
    if L == 0: return 0.0
    d = levenshtein(label, brand)
    return max(0.0, 1.0 - (d / L))

def is_mixed_script(domain: str):
    # Simple heuristic: presence of non-ASCII letters suggests potential mixed script (not perfect)
    try:
        domain.encode('ascii')
        return False
    except Exception:
        return True

def extract_display_name(from_header: str):
    """Extract display name from From header."""
    if not from_header:
        return ""
    # Match "Display Name" <email> or just email
    m = re.match(r'^\s*"([^"]+)"\s*<[^>]+>|\s*([^<\s]+)\s*<[^>]+>|^([^@\s]+)@', from_header)
    if m:
        return (m.group(1) or m.group(2) or m.group(3) or "").strip()
    return ""

def risky_tlds():
    """Return set of risky TLDs."""
    return {".click", ".icu", ".cfd", ".rest", ".tk", ".gq", ".ml", ".ga", ".cf"}

def _extract_domain(addr: str):
    """Extract domain from email address."""
    if not addr: return ""
    m = re.search(r"<([^>]+)>", addr)
    email_ = m.group(1) if m else addr
    m2 = re.search(r"@([^>]+)$", email_.strip())
    return (m2.group(1) if m2 else "").strip().lower()

def score_case(hop_diag: dict, auth: dict, dominfo: dict, brand_seeds=None, suspicious_asn=False, ns_mx_recurrent=False, profile="default", headers=None, detonation_endpoints=None, canary_ips=None, det_summary=None, origin_domain="", deobfuscation_weight: float = 0.30):
    brand_seeds = brand_seeds or ["apple","google","microsoft","paypal"]
    
    # Apply profile adjustments
    profile_modifier = 0.0
    if profile == "strict":
        profile_modifier = 0.05
    elif profile == "conservative":
        profile_modifier = -0.05
    
    # Header integrity
    header_score = 0.0
    if hop_diag.get("skew_s", 0) > 600: header_score += 0.2
    if not hop_diag.get("helo_ptr_match", True): header_score += 0.1
    if not hop_diag.get("fqdn_ok", True): header_score += 0.1
    # Auth
    spf_res = (auth.get("spf") or {}).get("result")
    if spf_res == "fail": header_score += 0.4
    dkim = auth.get("dkim") or {}
    if not dkim.get("present"): header_score += 0.2
    else:
        # if present but not aligned strictly, small bump
        if not dkim.get("aligned"): header_score += 0.1
    
    # Received-SPF scoring
    received_spf_result = auth.get("received_spf_result")
    if received_spf_result in ["fail", "softfail"]:
        header_score += 0.30
    
    # ARC cv scoring
    arc_cv = (auth.get("arc") or {}).get("cv")
    if arc_cv == "fail":
        header_score += 0.25
    elif arc_cv == "none" and spf_res == "pass" and not dkim.get("present"):
        header_score += 0.15
    
    dmarc = (auth.get("dmarc") or {}).get("inferred_result")
    if dmarc and dmarc != "pass": header_score += 0.2
    
    # DMARC policy scoring
    dmarc_policy = (auth.get("dmarc") or {}).get("policy", {}).get("policy")
    dmarc_aligned = (auth.get("dmarc") or {}).get("aligned", False)
    if dmarc_policy in ["reject", "quarantine"] and not dmarc_aligned:
        header_score += 0.25
    # Domain signals
    domain_score = 0.0
    nrd = dominfo.get("nrd_days")
    if nrd is not None and nrd < 30: domain_score += 0.15
    if nrd is not None and nrd < 7: domain_score += 0.20
    if suspicious_asn: domain_score += 0.3
    if ns_mx_recurrent: domain_score += 0.2
    
    # Brand & Identity heuristics
    from_domain = dominfo.get("domain", "")
    label = brand_label(from_domain)
    bk = max(bk_similarity(label, b) for b in brand_seeds) if label else 0.0
    if bk >= 0.7: domain_score += 0.2
    
    # Display-Name lookalike
    if headers:
        display_name = extract_display_name(headers.get("from", ""))
        if display_name and label:
            display_brand = brand_label(display_name.lower().replace(" ", ""))
            if display_brand and display_brand != label:
                # Check if display name contains known brand
                for brand in brand_seeds:
                    if brand in display_name.lower() and bk_similarity(display_brand, brand) >= 0.8:
                        domain_score += 0.20
                        break
        
        # Reply-To mismatch
        reply_to = headers.get("reply_to", "")
        if reply_to:
            reply_domain = _extract_domain(reply_to)
            if reply_domain and reply_domain != from_domain:
                # Check if it's not a punycode variant or subdomain
                if not (reply_domain.endswith("." + from_domain) or from_domain.endswith("." + reply_domain)):
                    domain_score += 0.15
    
    # TLD risk
    if from_domain:
        tld = "." + from_domain.split(".")[-1] if "." in from_domain else ""
        if tld in risky_tlds():
            domain_score += 0.10
    
    if is_mixed_script(dominfo.get("domain","")): domain_score += 0.2

    # Integrate deobfuscation analysis (if available) to penalize heavy obfuscation
    # headers["deobfuscation_analysis"] is expected to be a dict (or a JSON string) with
    # keys like 'deobfuscated_artifacts' containing 'text','html','urls' each having a
    # 'suspicion_score' in [0.0, 1.0]. We compute a small weighted aggregate and add
    # it to domain_score multiplied by deobfuscation_weight (configurable).
    if headers:
        try:
            deob = headers.get("deobfuscation_analysis")
            if deob and isinstance(deob, str):
                import json as _json
                deob = _json.loads(deob)
            if deob and isinstance(deob, dict):
                da = deob.get("deobfuscated_artifacts", {})
                # weights for parts (tunable)
                w_text, w_urls, w_html = 0.6, 0.25, 0.15
                text_s = (da.get("text") or {}).get("suspicion_score", 0.0) or 0.0
                html_s = (da.get("html") or {}).get("suspicion_score", 0.0) or 0.0
                urls = da.get("urls") or []
                urls_s = 0.0
                if isinstance(urls, list) and urls:
                    # use max url suspicion as representative
                    try:
                        urls_s = max((u.get("suspicion_score", 0.0) or 0.0) for u in urls)
                    except Exception:
                        urls_s = 0.0

                deob_score = (w_text * float(text_s) + w_urls * float(urls_s) + w_html * float(html_s))
                # clamp
                if deob_score < 0.0: deob_score = 0.0
                if deob_score > 1.0: deob_score = 1.0
                # apply into domain score
                domain_score += deob_score * float(deobfuscation_weight)
        except Exception:
            # fail silently on any malformed deob structure
            pass
    
    # Detonation/Canary bonuses
    campaign_score = 0.0
    # Downloads bonus
    if det_summary and det_summary.get("downloads"):
        campaign_score += 0.15
    # External endpoints bonus
    if detonation_endpoints:
        for ep in detonation_endpoints:
            host = ep.get("host", "")
            if host and origin_domain and not host.endswith("." + origin_domain) and host != origin_domain:
                campaign_score += 0.10
                break  # one time bonus
    # Canary public IPs bonus
    if canary_ips:
        # Simple check: if any IP is not private (basic heuristic)
        for ip in canary_ips:
            if not ip.startswith(("192.168.", "10.", "172.")) and not (ip.startswith("127.") or ip == "localhost"):
                campaign_score += 0.20
                break  # one time bonus

    # Enrichment bonuses for advanced attribution
    enrichment_score = 0.0
    if det_summary and det_summary.get("enrichment"):
        enrichment_data = det_summary["enrichment"]

        # Tracker analysis bonus
        if enrichment_data.get("enrichment_files", {}).get("trackers"):
            enrichment_score += 0.08  # Bonus for tracker extraction

        # TLS fingerprinting bonus
        if enrichment_data.get("enrichment_files", {}).get("tls_fingerprints"):
            enrichment_score += 0.10  # Bonus for certificate analysis

        # DNS enrichment bonus
        if enrichment_data.get("enrichment_files", {}).get("dns_enrichment"):
            enrichment_score += 0.08  # Bonus for DNS analysis

        # Redirect chain analysis bonus
        if enrichment_data.get("enrichment_files", {}).get("redirect_chains"):
            enrichment_score += 0.06  # Bonus for redirect analysis

        # JA3 fingerprinting bonus
        if enrichment_data.get("enrichment_files", {}).get("ja3_fingerprints"):
            enrichment_score += 0.12  # Bonus for JA3 analysis (higher weight)

        # Form analysis bonus
        if enrichment_data.get("enrichment_files", {}).get("form_analysis"):
            enrichment_score += 0.08  # Bonus for form analysis

        # Attribution matrix bonus (highest weight)
        if enrichment_data.get("enrichment_files", {}).get("attribution_matrix"):
            enrichment_score += 0.15  # Bonus for complete attribution analysis

        # Additional bonuses based on enrichment quality
        try:
            # Load attribution matrix for quality assessment
            import os
            case_dir = os.path.dirname(os.path.dirname(det_summary.get("pcap", ""))) if det_summary.get("pcap") else ""
            if case_dir:
                matrix_file = os.path.join(case_dir, "detonation", "attribution_matrix.json")
                if os.path.exists(matrix_file):
                    import json
                    with open(matrix_file, 'r') as f:
                        matrix_data = json.load(f)

                    # Bonus for high confidence hypotheses
                    hypotheses = matrix_data.get("hypotheses", [])
                    if hypotheses:
                        top_confidence = hypotheses[0].get("confidence_score", 0)
                        if top_confidence > 0.8:
                            enrichment_score += 0.10  # High confidence attribution
                        elif top_confidence > 0.6:
                            enrichment_score += 0.05  # Medium confidence attribution

                    # Bonus for multiple evidence types
                    evidence_summary = matrix_data.get("evidence_summary", {})
                    evidence_types = evidence_summary.get("evidence_by_category", {})
                    if len(evidence_types) >= 4:
                        enrichment_score += 0.08  # Broad evidence coverage
                    elif len(evidence_types) >= 2:
                        enrichment_score += 0.04  # Moderate evidence coverage

        except Exception:
            # Silently ignore enrichment quality assessment errors
            pass
    
    total = header_score + domain_score + profile_modifier + campaign_score + enrichment_score
    decision = "Inconclusive"
    
    # Apply profile-adjusted thresholds
    malicious_threshold = 0.72
    suspicious_threshold = 0.55
    
    if profile == "strict":
        malicious_threshold = 0.68
        suspicious_threshold = 0.52
    elif profile == "conservative":
        malicious_threshold = 0.76
        suspicious_threshold = 0.58
    
    if total >= malicious_threshold: decision = "Likely malicious infrastructure"
    elif total >= suspicious_threshold: decision = "Suspicious or compromised account"
    return {"score": round(total,2), "decision": decision, "bk_score": round(bk,2), "mixed_flag": is_mixed_script(dominfo.get("domain",""))}
