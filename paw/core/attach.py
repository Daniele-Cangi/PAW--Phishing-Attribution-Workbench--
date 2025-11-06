import os
import hashlib
import magic
import re
import struct
import math

def scan_attachments(msg_obj):
    """Scan attachments from email message object with advanced malware analysis."""
    attachments = []
    
    if hasattr(msg_obj, 'attachments') and msg_obj.attachments:
        # extract_msg.Message attachments
        for att in msg_obj.attachments:
            try:
                att_data = att.data if hasattr(att, 'data') else att
                if isinstance(att_data, bytes):
                    attachment_info = _analyze_attachment(att_data, getattr(att, 'filename', getattr(att, 'name', 'unknown')))
                    attachments.append(attachment_info)
            except Exception as e:
                # Skip problematic attachments
                continue
    
    elif hasattr(msg_obj, 'get_payload'):
        # Standard email.Message attachments
        for part in msg_obj.walk():
            if part.get_content_disposition() == 'attachment':
                try:
                    att_data = part.get_payload(decode=True)
                    if att_data:
                        filename = part.get_filename() or 'unknown'
                        attachment_info = _analyze_attachment(att_data, filename)
                        attachments.append(attachment_info)
                except Exception as e:
                    continue
    
    return attachments

def _analyze_attachment(att_data, filename):
    """Perform comprehensive analysis of attachment data."""
    size = len(att_data)
    
    # Calculate hashes
    sha256 = hashlib.sha256(att_data).hexdigest()
    blake3_hash = hashlib.blake3(att_data).hexdigest() if hasattr(hashlib, 'blake3') else sha256
    
    # Detect MIME type
    mime_type = magic.from_buffer(att_data, mime=True) if 'magic' in globals() else 'application/octet-stream'
    
    # Advanced malware analysis
    analysis = {
        "filename": filename,
        "size": size,
        "sha256": sha256,
        "blake3": blake3_hash,
        "mime": mime_type,
        "risk_score": 0,
        "malware_indicators": [],
        "suspicious_patterns": [],
        "entropy": _calculate_entropy(att_data),
        "file_type_anomalies": []
    }
    
    # Check for OLE macros (enhanced)
    if mime_type in ['application/vnd.ms-excel', 'application/vnd.ms-powerpoint', 'application/msword']:
        ole_analysis = _analyze_ole_file(att_data)
        analysis.update(ole_analysis)
    
    # Check for executable content
    if _is_executable_content(att_data, mime_type):
        exe_analysis = _analyze_executable_content(att_data)
        analysis.update(exe_analysis)
    
    # Check for shellcode patterns
    shellcode_patterns = _detect_shellcode(att_data)
    if shellcode_patterns:
        analysis["malware_indicators"].extend(shellcode_patterns)
        analysis["risk_score"] += len(shellcode_patterns) * 3
    
    # Check for obfuscated content
    obfuscation_score = _detect_obfuscation(att_data)
    analysis["obfuscation_score"] = obfuscation_score
    analysis["risk_score"] += obfuscation_score
    
    # Check for exploit patterns
    exploit_patterns = _detect_exploit_patterns(att_data)
    if exploit_patterns:
        analysis["malware_indicators"].extend(exploit_patterns)
        analysis["risk_score"] += len(exploit_patterns) * 2
    
    # Filename analysis
    filename_risk = _analyze_filename_risks(filename)
    analysis["filename_risk"] = filename_risk
    analysis["risk_score"] += filename_risk
    
    # Determine risk level
    if analysis["risk_score"] >= 10:
        analysis["risk_level"] = "high"
    elif analysis["risk_score"] >= 5:
        analysis["risk_level"] = "medium"
    elif analysis["risk_score"] > 0:
        analysis["risk_level"] = "low"
    else:
        analysis["risk_level"] = "clean"
    
    return analysis

def _analyze_ole_file(att_data):
    """Analyze OLE files for macro malware."""
    analysis = {"ole_macro": False, "vba_macros": [], "suspicious_ole": []}
    
    # Check for OLE signatures
    if b'\x00Attribut' in att_data or b'macros' in att_data.lower():
        analysis["ole_macro"] = True
        analysis["risk_score"] = analysis.get("risk_score", 0) + 3
    
    # Look for VBA macro signatures
    vba_signatures = [
        b'VBA', b'Project', b'Module', b'Class',
        b'AutoExec', b'AutoOpen', b'AutoClose', b'Document_Open'
    ]
    
    for sig in vba_signatures:
        if sig in att_data:
            analysis["vba_macros"].append(sig.decode('utf-8', errors='ignore'))
            analysis["risk_score"] = analysis.get("risk_score", 0) + 2
    
    # Check for suspicious OLE structures
    suspicious_patterns = [
        b'powershell', b'cmd.exe', b'wscript', b'cscript',
        b'bitsadmin', b'certutil', b'mshta'
    ]
    
    for pattern in suspicious_patterns:
        if pattern in att_data.lower():
            analysis["suspicious_ole"].append(pattern.decode('utf-8', errors='ignore'))
            analysis["risk_score"] = analysis.get("risk_score", 0) + 2
    
    return analysis

def _is_executable_content(att_data, mime_type):
    """Check if content appears to be executable."""
    executable_mimes = [
        'application/x-executable', 'application/x-sharedlib',
        'application/x-msdownload', 'application/vnd.microsoft.portable-executable'
    ]
    
    if mime_type in executable_mimes:
        return True
    
    # Check for PE signatures
    if att_data.startswith(b'MZ'):
        return True
    
    # Check for ELF signatures
    if att_data.startswith(b'\x7fELF'):
        return True
    
    return False

def _analyze_executable_content(att_data):
    """Analyze executable file content."""
    analysis = {"executable_type": "unknown", "suspicious_imports": []}
    
    # PE file analysis
    if att_data.startswith(b'MZ'):
        analysis["executable_type"] = "PE"
        
        # Look for suspicious DLL imports (simplified)
        suspicious_dlls = [
            b'kernel32.dll', b'user32.dll', b'advapi32.dll',
            b'ws2_32.dll', b'wininet.dll', b'shell32.dll'
        ]
        
        for dll in suspicious_dlls:
            if dll in att_data.lower():
                analysis["suspicious_imports"].append(dll.decode('utf-8', errors='ignore'))
    
    # ELF file analysis
    elif att_data.startswith(b'\x7fELF'):
        analysis["executable_type"] = "ELF"
        
        # Check for suspicious system calls
        suspicious_syscalls = [
            b'execve', b'system', b'popen', b'fork'
        ]
        
        for syscall in suspicious_syscalls:
            if syscall in att_data:
                analysis["suspicious_imports"].append(syscall.decode('utf-8', errors='ignore'))
    
    return analysis

def _detect_shellcode(att_data):
    """Detect potential shellcode patterns."""
    patterns = []
    
    # Common shellcode patterns
    shellcode_signatures = [
        # NOP sled
        b'\x90' * 4,
        # INT 3 (debugger breakpoint)
        b'\xCC',
        # Shellcode prologues
        b'\x31\xC0\x50\x68',  # XOR EAX,EAX; PUSH EAX; PUSH
        b'\x8B\xFF\x55\x8B',  # MOV EDI,EDI; PUSH EBP; MOV EBP,ESP
    ]
    
    for sig in shellcode_signatures:
        if sig in att_data:
            patterns.append(f"shellcode_signature_{sig.hex()}")
    
    # Check for polymorphic code patterns
    if _has_polymorphic_patterns(att_data):
        patterns.append("polymorphic_code")
    
    return patterns

def _detect_obfuscation(att_data):
    """Detect obfuscation techniques."""
    score = 0
    
    # High entropy (potential encryption/packing)
    entropy = _calculate_entropy(att_data)
    if entropy > 7.5:
        score += 2
    
    # Unusual character distribution
    if _has_unusual_char_distribution(att_data):
        score += 1
    
    # Repeated patterns (potential encoding)
    if _has_repeated_patterns(att_data):
        score += 1
    
    return score

def _detect_exploit_patterns(att_data):
    """Detect common exploit patterns."""
    patterns = []
    
    # Buffer overflow patterns
    if b'A' * 100 in att_data or b'\x41' * 50 in att_data:
        patterns.append("buffer_overflow_pattern")
    
    # Format string vulnerabilities
    format_specifiers = [b'%s', b'%x', b'%n', b'%p']
    for spec in format_specifiers:
        if spec in att_data:
            patterns.append("format_string_specifier")
    
    # SQL injection patterns
    sql_patterns = [b'UNION SELECT', b'OR 1=1', b'DROP TABLE']
    for pattern in sql_patterns:
        if pattern in att_data:
            patterns.append("sql_injection_pattern")
    
    return patterns

def _analyze_filename_risks(filename):
    """Analyze filename for suspicious patterns."""
    score = 0
    filename_lower = filename.lower()
    
    # Double extensions (dangerous)
    if filename_lower.count('.') > 1:
        # Check for executable extensions hidden behind document extensions
        dangerous_combos = [
            ('.exe', '.doc'), ('.exe', '.pdf'), ('.exe', '.txt'),
            ('.scr', '.jpg'), ('.pif', '.gif'), ('.com', '.png')
        ]
        for exe_ext, doc_ext in dangerous_combos:
            if exe_ext in filename_lower and doc_ext in filename_lower:
                score += 3
                break
    
    # Suspicious keywords
    suspicious_keywords = [
        'invoice', 'payment', 'urgent', 'important', 'confidential',
        'password', 'login', 'account', 'verify', 'update', 'patch'
    ]
    
    for keyword in suspicious_keywords:
        if keyword in filename_lower:
            score += 1
    
    return score

def _calculate_entropy(data):
    """Calculate Shannon entropy of data."""
    if not data:
        return 0
    
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    
    return entropy

def _has_polymorphic_patterns(data):
    """Check for polymorphic code patterns."""
    # Look for code that changes form but maintains function
    # This is a simplified check
    return len(set(data[i:i+4] for i in range(0, min(len(data), 1000), 4))) > 100

def _has_unusual_char_distribution(data):
    """Check for unusual character distribution."""
    if len(data) < 100:
        return False
    
    # Check if distribution is too uniform (potential encryption)
    byte_counts = [data.count(i) for i in range(256)]
    avg_count = sum(byte_counts) / 256
    variance = sum((count - avg_count) ** 2 for count in byte_counts) / 256
    
    return variance < 50  # Too uniform

def _has_repeated_patterns(data):
    """Check for repeated patterns that might indicate encoding."""
    if len(data) < 50:
        return False
    
    # Look for repeated sequences
    for length in [4, 8, 16]:
        if len(data) < length * 3:
            continue
        
        sequences = [data[i:i+length] for i in range(0, len(data) - length, length)]
        if len(sequences) != len(set(sequences)):  # Has duplicates
            return True
    
    return False