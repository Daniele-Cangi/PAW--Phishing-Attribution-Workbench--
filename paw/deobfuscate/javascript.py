#!/usr/bin/env python3
"""
PAW - JavaScript Deobfuscation Module
Deoffusca codice JavaScript offuscato nei phishing
"""

import re
import base64
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

class JavaScriptDeobfuscator:
    """Deoffuscatore specializzato per JavaScript"""

    def __init__(self):
        self.max_iterations = 10  # Massimo iterazioni per evitare loop infiniti
        self.safe_execution_enabled = False  # Per default disabilitato per sicurezza

    def deobfuscate_javascript(self, js_code: str) -> Dict[str, Any]:
        """
        Deoffusca codice JavaScript applicando multiple tecniche

        Args:
            js_code: Codice JavaScript potenzialmente offuscato

        Returns:
            Dizionario con codice finale e trasformazioni applicate
        """
        transformations = []
        current_code = js_code
        iteration = 0

        # Pattern di offuscamento comuni
        deobfuscation_patterns = [
            (r'String\.fromCharCode\(([^)]+)\)', self._decode_fromcharcode),
            (r'atob\(["\']([^"\']+)["\']', self._decode_base64),
            (r'decodeURIComponent\(["\']([^"\']+)["\']', self._decode_uri_component),
            (r'\\x([0-9a-fA-F]{2})', self._decode_hex_escape),
            (r'\\u([0-9a-fA-F]{4})', self._decode_unicode_escape),
            (r'eval\(["\']([^"\']+)["\']', self._decode_eval_string),
        ]

        while iteration < self.max_iterations:
            found_transformation = False

            for pattern, decoder_func in deobfuscation_patterns:
                matches = re.finditer(pattern, current_code, re.IGNORECASE)
                for match in matches:
                    try:
                        original = match.group(0)
                        decoded = decoder_func(match)

                        if decoded and decoded != original:
                            # Sostituisci nel codice
                            current_code = current_code.replace(original, f"/*DECODED:*/ {repr(decoded)}")
                            transformations.append({
                                'iteration': iteration,
                                'technique': decoder_func.__name__.replace('_decode_', ''),
                                'original': original,
                                'decoded': decoded,
                                'pattern': pattern
                            })
                            found_transformation = True

                    except Exception as e:
                        logger.warning(f"Errore nella decodifica {pattern}: {e}")
                        continue

            # Se non abbiamo trovato trasformazioni in questa iterazione, fermiamoci
            if not found_transformation:
                break

            iteration += 1

        # Analizza il codice finale
        analysis = self._analyze_final_code(current_code)

        return {
            'original_code': js_code,
            'final_code': current_code,
            'transformations': transformations,
            'iterations_performed': iteration,
            'analysis': analysis,
            'complexity_score': len(transformations) / max(1, len(js_code) / 1000),  # Trasformazioni per KB
            'suspicion_score': self._calculate_js_suspicion(transformations, analysis)
        }

    def _decode_fromcharcode(self, match) -> Optional[str]:
        """Decodifica String.fromCharCode(...)"""
        try:
            char_codes = match.group(1)
            # Estrai numeri separati da virgola
            numbers = re.findall(r'\d+', char_codes)
            decoded = ''.join(chr(int(code)) for code in numbers)
            return decoded
        except Exception:
            return None

    def _decode_base64(self, match) -> Optional[str]:
        """Decodifica atob(...)"""
        try:
            encoded = match.group(1)
            decoded_bytes = base64.b64decode(encoded)
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return None

    def _decode_uri_component(self, match) -> Optional[str]:
        """Decodifica decodeURIComponent(...)"""
        try:
            from urllib.parse import unquote
            encoded = match.group(1)
            return unquote(encoded)
        except Exception:
            return None

    def _decode_hex_escape(self, match) -> Optional[str]:
        """Decodifica \\xHH"""
        try:
            hex_value = match.group(1)
            return chr(int(hex_value, 16))
        except Exception:
            return None

    def _decode_unicode_escape(self, match) -> Optional[str]:
        """Decodifica \\uHHHH"""
        try:
            unicode_value = match.group(1)
            return chr(int(unicode_value, 16))
        except Exception:
            return None

    def _decode_eval_string(self, match) -> Optional[str]:
        """Decodifica eval("...") - con cautela"""
        if not self.safe_execution_enabled:
            # In modalità sicura, non eseguiamo eval
            return f"[EVAL BLOCKED] {match.group(1)}"

        # NOTA: Questa è pericolosa e dovrebbe essere usata solo in sandbox isolate
        try:
            code = match.group(1)
            # Qui si potrebbe implementare esecuzione sicura, ma per ora restituiamo il codice
            return f"[EVAL RESULT] {code}"
        except Exception:
            return None

    def _analyze_final_code(self, code: str) -> Dict[str, Any]:
        """Analizza il codice JavaScript finale per pattern sospetti"""
        analysis = {
            'suspicious_functions': [],
            'network_calls': [],
            'obfuscation_indicators': [],
            'payload_indicators': []
        }

        # Funzioni sospette
        suspicious_funcs = [
            'eval', 'Function', 'setTimeout', 'setInterval',
            'XMLHttpRequest', 'fetch', 'WebSocket', 'sendBeacon'
        ]

        for func in suspicious_funcs:
            if re.search(r'\b' + re.escape(func) + r'\b', code):
                analysis['suspicious_functions'].append(func)

        # Chiamate di rete
        network_patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'XMLHttpRequest\(\)',
            r'\.open\(["\']([^"\']+)["\']',
            r'sendBeacon\(["\']([^"\']+)["\']',
            r'WebSocket\(["\']([^"\']+)["\']'
        ]

        for pattern in network_patterns:
            matches = re.findall(pattern, code)
            analysis['network_calls'].extend(matches)

        # Indicatori di payload
        payload_indicators = [
            'document\\.location',
            'window\\.location',
            'location\\.href',
            'location\\.replace',
            'location\\.assign',
            'document\\.write',
            'document\\.writeln',
            'innerHTML',
            'outerHTML'
        ]

        for indicator in payload_indicators:
            if indicator in code:
                analysis['payload_indicators'].append(indicator)

        # Indicatori di offuscamento residuo
        obfuscation_patterns = [
            r'\\x[0-9a-fA-F]{2}',
            r'\\u[0-9a-fA-F]{4}',
            r'String\.fromCharCode',
            r'atob\(',
            r'eval\('
        ]

        for pattern in obfuscation_patterns:
            if re.search(pattern, code):
                analysis['obfuscation_indicators'].append(pattern)

        return analysis

    def _calculate_js_suspicion(self, transformations: List, analysis: Dict) -> float:
        """Calcola punteggio di sospetto per il codice JavaScript"""
        score = 0.0

        # Peso per trasformazioni
        score += len(transformations) * 0.2

        # Peso per funzioni sospette
        suspicious_funcs = analysis.get('suspicious_functions', [])
        score += len(suspicious_funcs) * 0.15

        # Peso per chiamate di rete
        network_calls = analysis.get('network_calls', [])
        score += len(network_calls) * 0.1

        # Peso per indicatori payload
        payload_indicators = analysis.get('payload_indicators', [])
        score += len(payload_indicators) * 0.2

        # Peso per offuscamento residuo
        obfuscation_indicators = analysis.get('obfuscation_indicators', [])
        score += len(obfuscation_indicators) * 0.1

        # Bonus per eval (molto sospetto)
        if 'eval' in suspicious_funcs:
            score += 0.3

        return min(1.0, score)