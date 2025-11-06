
def attribution_graph(hops, origin_idx, from_domain_info):
    lines = ["graph TD", "  Email[Email]"]
    prev = "Email"
    for i,h in enumerate(hops, start=1):
        label = f"{h.get('ip','?')} / {h.get('by','')}"
        # Add MX-internal marking
        if h.get("role") == "recipient_mx_internal":
            label += " [MX-internal]"
        node = f"Hop{i}"
        # Add origin badge
        if i == origin_idx:
            node += '["<<ORIGIN>>"]'
        lines.append(f"  {prev} --> {node}[{label}]")
        prev = node
    fd = from_domain_info or {}
    dom_label = f"{fd.get('domain','?')} | Reg: {fd.get('registrar','?')} | Created: {fd.get('created','?')}"
    lines.append(f"  Email --> FromDomain[{dom_label}]")
    return "\n".join(lines)

def domain_graph(dominfo):
    ns = ", ".join(dominfo.get("ns", [])) or "-"
    mx = ", ".join(dominfo.get("mx", [])) or "-"
    created = dominfo.get("created","?")
    reg = dominfo.get("registrar","?")
    d = dominfo.get("domain","?")
    lines = ["graph LR"]
    lines.append(f"  D[{d}] --> R[Registrar: {reg}]")
    lines.append(f"  D --> C[Created: {created}]")
    lines.append(f"  D --> NS[NS: {ns}]")
    lines.append(f"  D --> MX[MX: {mx}]")
    return "\n".join(lines)

def detonation_box(det_sum: dict) -> str:
    if not det_sum: return ""
    lines = ["## Detonation (observe-only)"]
    for ep in det_sum.get("endpoints", [])[:12]:
        lines.append(f"- {ep['host']} → {', '.join(ep.get('ips',[])[:3])} [{ep['count']} req]")
    if det_sum.get("downloads"):
        lines.append(f"- Downloads: {len(det_sum['downloads'])}")
    return "\n".join(lines)

def canary_box(canary_ips: list[str], canary_visitors: list[dict] = None) -> str:
    if not canary_ips: return ""
    lines = ["## Canary"]
    for ip in canary_ips[:12]:
        visitor_info = ""
        if canary_visitors:
            # Find visitor details for this IP
            for visitor in canary_visitors:
                if visitor.get("ip") == ip:
                    rep = visitor.get("reputation", {})
                    score = rep.get("score", 0)
                    category = rep.get("category", "unknown")
                    risk_level = "🔴 High" if score >= 7 else "🟡 Medium" if score >= 4 else "🟢 Low" if score >= 1 else "⚪ Unknown"
                    visitor_info = f" ({risk_level} risk - {category})"
                    break
        lines.append(f"- Visitor IP: {ip}{visitor_info}")
    return "\n".join(lines)
