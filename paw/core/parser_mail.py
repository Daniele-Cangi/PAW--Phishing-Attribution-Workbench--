
import email, re, os
from email import policy
from email.parser import BytesParser

def parse_eml_bytes(b: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(b)
    return _parse_msg_obj(msg)

def parse_msg_bytes(b: bytes):
    try:
        import extract_msg
        msg = extract_msg.Message(b)
        return _parse_msg_obj(msg)
    except ImportError:
        raise RuntimeError("extract-msg not installed for MSG support")
    except Exception as e:
        raise RuntimeError(f"Failed to parse MSG: {e}")

def parse_mail(path: str):
    """Dispatch based on file extension."""
    ext = os.path.splitext(path)[1].lower()
    with open(path, "rb") as f:
        b = f.read()
    
    if ext == ".msg":
        result = parse_msg_bytes(b)
        # Store msg object for attachment processing
        result["_msg_obj"] = parse_msg_bytes(b)["_msg_obj"] if "extract_msg" in globals() else None
        return result
    else:
        return parse_eml_bytes(b)

def _parse_msg_obj(msg):
    """Parse email.Message or extract_msg.Message object."""
    # Handle extract_msg.Message
    if hasattr(msg, 'sender'):
        # extract_msg object
        def get(h):
            # Map common headers
            header_map = {
                "From": getattr(msg, 'sender', ''),
                "Reply-To": getattr(msg, 'reply_to', ''),
                "Return-Path": getattr(msg, 'return_path', ''),
                "Message-ID": getattr(msg, 'message_id', ''),
                "Date": getattr(msg, 'date', ''),
                "Subject": getattr(msg, 'subject', ''),
            }
            return header_map.get(h, "")
        
        # Get received headers from transport_headers if available
        received = []
        if hasattr(msg, 'transport_headers') and msg.transport_headers:
            for header_line in msg.transport_headers:
                if header_line.lower().startswith('received:'):
                    received.append(header_line[9:].strip())
        
        headers = {
            "from": get("From"),
            "reply_to": get("Reply-To") or "",
            "return_path": get("Return-Path") or "",
            "message_id": get("Message-ID") or "",
            "date": str(get("Date")) if get("Date") else "",
            "subject": get("Subject") or "",
            "received": received,
            "_msg_obj": msg  # Store for attachment processing
        }
        
        # Parse authentication results from headers
        auth_res = []
        if hasattr(msg, 'transport_headers'):
            for header in msg.transport_headers:
                if header.lower().startswith('authentication-results:'):
                    auth_res.append(header[23:].strip())
        
        spf, dkim_list, dmarc = None, [], None
        for ar in auth_res:
            ar_lower = ar.lower()
            m_spf = re.search(r"spf=(pass|fail|softfail|neutral|temperror|permerror)", ar_lower)
            if m_spf: spf = m_spf.group(1)
            for m in re.finditer(r"dkim=(pass|fail|none)[^;]*;[^d]*d=([^;\s]+)", ar_lower):
                dkim_list.append({"result": m.group(1), "d": m.group(2)})
            m_dmarc = re.search(r"dmarc=(pass|fail|temperror|permerror)", ar_lower)
            if m_dmarc: dmarc = m_dmarc.group(1)
        
        headers["auth_results"] = {"spf": spf, "dkim": dkim_list, "dmarc": dmarc}
        
        # ARC headers (if present in transport_headers)
        arc_seals, arc_msgsigs, arc_authres = [], [], []
        if hasattr(msg, 'transport_headers'):
            for header in msg.transport_headers:
                header_lower = header.lower()
                if header_lower.startswith('arc-seal:'):
                    arc_seals.append(header[9:].strip())
                elif header_lower.startswith('arc-message-signature:'):
                    arc_msgsigs.append(header[21:].strip())
                elif header_lower.startswith('arc-authentication-results:'):
                    arc_authres.append(header[26:].strip())
        
        headers["arc"] = {
            "seals": arc_seals,
            "message_signatures": arc_msgsigs,
            "auth_results": arc_authres
        }
        
        # Received-SPF (if present)
        received_spf_raw = []
        if hasattr(msg, 'transport_headers'):
            for header in msg.transport_headers:
                if header.lower().startswith('received-spf:'):
                    received_spf_raw.append(header[13:].strip())
        
        # Parse Received-SPF components
        received_spf_parsed = []
        for rspf in received_spf_raw:
            parsed = {"result": None, "helo": None, "client_ip": None}
            # Extract result
            m_result = re.search(r'(pass|fail|softfail|neutral|permerror|temperror)', rspf.lower())
            if m_result:
                parsed["result"] = m_result.group(1)
            # Extract client-ip
            m_client_ip = re.search(r'client-ip=([^\s;]+)', rspf.lower())
            if m_client_ip:
                parsed["client_ip"] = m_client_ip.group(1)
            # Extract helo
            m_helo = re.search(r'helo=([^\s;]+)', rspf.lower())
            if m_helo:
                parsed["helo"] = m_helo.group(1)
            received_spf_parsed.append(parsed)
        
        headers["received_spf"] = received_spf_parsed
        
        return headers
    
    else:
        # Standard email.Message object
        hdr = msg._headers if hasattr(msg, "_headers") else list(msg.items())
        def get(h): 
            v = msg.get(h)
            return v if v is not None else ""
        headers = {
            "from": get("From"),
            "reply_to": get("Reply-To") or "",
            "return_path": get("Return-Path") or "",
            "message_id": get("Message-ID") or "",
            "date": get("Date") or "",
            "subject": get("Subject") or ""
        }
        # Collect Authentication-Results (may have multiple)
        auth_res = msg.get_all("Authentication-Results") or []
        spf, dkim_list, dmarc = None, [], None
        for ar in auth_res:
            # crude parsing, but effective in practice
            ar_lower = ar.lower()
            m_spf = re.search(r"spf=(pass|fail|softfail|neutral|temperror|permerror)", ar_lower)
            if m_spf: spf = m_spf.group(1)
            for m in re.finditer(r"dkim=(pass|fail|none)[^;]*;[^d]*d=([^;\s]+)", ar_lower):
                dkim_list.append({"result": m.group(1), "d": m.group(2)})
            m_dmarc = re.search(r"dmarc=(pass|fail|temperror|permerror)", ar_lower)
            if m_dmarc: dmarc = m_dmarc.group(1)
        headers["auth_results"] = {"spf": spf, "dkim": dkim_list, "dmarc": dmarc}
        
        # Parse ARC headers
        arc_seals = msg.get_all("ARC-Seal") or []
        arc_msgsigs = msg.get_all("ARC-Message-Signature") or []
        arc_authres = msg.get_all("ARC-Authentication-Results") or []
        headers["arc"] = {
            "seals": arc_seals,
            "message_signatures": arc_msgsigs,
            "auth_results": arc_authres
        }
        
        # Parse Received-SPF
        received_spf_raw = msg.get_all("Received-SPF") or []
        
        # Parse Received-SPF components
        received_spf_parsed = []
        for rspf in received_spf_raw:
            parsed = {"result": None, "helo": None, "client_ip": None}
            # Extract result
            m_result = re.search(r'(pass|fail|softfail|neutral|permerror|temperror)', rspf.lower())
            if m_result:
                parsed["result"] = m_result.group(1)
            # Extract client-ip
            m_client_ip = re.search(r'client-ip=([^\s;]+)', rspf.lower())
            if m_client_ip:
                parsed["client_ip"] = m_client_ip.group(1)
            # Extract helo
            m_helo = re.search(r'helo=([^\s;]+)', rspf.lower())
            if m_helo:
                parsed["helo"] = m_helo.group(1)
            received_spf_parsed.append(parsed)
        
        headers["received_spf"] = received_spf_parsed
        
        # Received lines (preserve order as in message - topmost is last hop)
        received = msg.get_all("Received") or []
        headers["received"] = received
        return headers
