#!/usr/bin/env python3
"""
PAW - HTML Deobfuscation Module
Deoffusca contenuto HTML offuscato nei phishing
"""

import re
import html as html_module
import base64
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

try:
    from bs4 import BeautifulSoup
    HAS_BEAUTIFULSOUP = True
except ImportError:
    HAS_BEAUTIFULSOUP = False
    logger.warning("BeautifulSoup non disponibile, funzionalità HTML limitate")

class HTMLDeobfuscator:
    """Deoffuscatore specializzato per HTML"""

    def __init__(self):
        self.hidden_selectors = [
            '[style*="display:none"]',
            '[style*="visibility:hidden"]',
            '[style*="opacity:0"]',
            '[style*="position:absolute"][style*="left:-9999px"]',
            '[style*="position:absolute"][style*="top:-9999px"]',
            '[type="hidden"]',
            '[style*="font-size:0"]',
            '[style*="width:0"]',
            '[style*="height:0"]'
        ]

    def deobfuscate_html(self, html_content: str) -> Dict[str, Any]:
        """
        Deoffusca contenuto HTML applicando multiple tecniche

        Args:
            html_content: Contenuto HTML potenzialmente offuscato

        Returns:
            Dizionario con HTML finale e trasformazioni applicate
        """
        transformations = []
        current_html = html_content

        # 1. Decodifica entità HTML
        decoded_entities = html_module.unescape(current_html)
        if decoded_entities != current_html:
            transformations.append({
                'technique': 'html_entity_decode',
                'from': current_html,
                'to': decoded_entities,
                'description': 'Decodifica entità HTML (&amp;, &lt;, ecc.)'
            })
            current_html = decoded_entities

        # 2. Decodifica base64 in attributi
        base64_decoded = self._decode_base64_in_html(current_html)
        if base64_decoded != current_html:
            transformations.append({
                'technique': 'base64_in_html',
                'from': current_html,
                'to': base64_decoded,
                'description': 'Decodifica base64 in attributi HTML'
            })
            current_html = base64_decoded

        # 3. Analizza elementi nascosti
        hidden_analysis = self._analyze_hidden_elements(current_html)

        # 4. Analizza form offuscati
        form_analysis = self._analyze_form_obfuscation(current_html)

        # 5. Analizza iframe sospetti
        iframe_analysis = self._analyze_iframes(current_html)

        # 6. Analizza JavaScript inline offuscato
        js_analysis = self._analyze_inline_javascript(current_html)

        return {
            'original_html': html_content,
            'final_html': current_html,
            'transformations': transformations,
            'hidden_elements': hidden_analysis,
            'form_analysis': form_analysis,
            'iframe_analysis': iframe_analysis,
            'javascript_analysis': js_analysis,
            'suspicion_score': self._calculate_html_suspicion(
                transformations, hidden_analysis, form_analysis,
                iframe_analysis, js_analysis
            )
        }

    def _decode_base64_in_html(self, html_content: str) -> str:
        """Decodifica base64 negli attributi HTML"""
        if not HAS_BEAUTIFULSOUP:
            return html_content

        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            modified = False

            # Cerca base64 in attributi comuni
            attributes_to_check = ['src', 'href', 'data', 'value', 'alt']

            for tag in soup.find_all():
                for attr in attributes_to_check:
                    if tag.has_attr(attr):
                        value = tag[attr]
                        # Pattern per base64 (data:base64, o semplice base64)
                        base64_match = re.search(r'base64,([A-Za-z0-9+/]+={0,2})', value)
                        if base64_match:
                            try:
                                encoded = base64_match.group(1)
                                decoded_bytes = base64.b64decode(encoded)
                                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')

                                # Sostituisci nel valore dell'attributo
                                new_value = value.replace(base64_match.group(0), decoded_str)
                                tag[attr] = new_value
                                modified = True
                            except Exception:
                                continue

            return str(soup) if modified else html_content

        except Exception as e:
            logger.warning(f"Errore nella decodifica base64 HTML: {e}")
            return html_content

    def _analyze_hidden_elements(self, html_content: str) -> List[Dict]:
        """Analizza elementi HTML nascosti"""
        if not HAS_BEAUTIFULSOUP:
            return []

        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            hidden_elements = []

            for selector in self.hidden_selectors:
                try:
                    elements = soup.select(selector)
                    for elem in elements:
                        suspicion_score = self._rate_hidden_element_suspicion(elem)

                        hidden_elements.append({
                            'element': str(elem)[:200] + '...' if len(str(elem)) > 200 else str(elem),
                            'selector': selector,
                            'tag': elem.name,
                            'suspicion_score': suspicion_score,
                            'attributes': dict(elem.attrs) if elem.attrs else {}
                        })
                except Exception:
                    continue

            return hidden_elements

        except Exception as e:
            logger.warning(f"Errore nell'analisi elementi nascosti: {e}")
            return []

    def _analyze_form_obfuscation(self, html_content: str) -> Dict[str, Any]:
        """Analizza form potenzialmente offuscati"""
        if not HAS_BEAUTIFULSOUP:
            return {'forms': [], 'suspicious_patterns': []}

        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = soup.find_all('form')
            analysis = {
                'forms': [],
                'suspicious_patterns': []
            }

            for form in forms:
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET'),
                    'inputs': [],
                    'suspicious_indicators': []
                }

                # Analizza action URL
                action = form.get('action', '')
                if action:
                    if self._is_suspicious_url(action):
                        form_data['suspicious_indicators'].append('suspicious_action_url')
                    if 'base64' in action.lower():
                        form_data['suspicious_indicators'].append('base64_in_action')

                # Analizza input fields
                inputs = form.find_all('input')
                for input_field in inputs:
                    input_data = {
                        'type': input_field.get('type', 'text'),
                        'name': input_field.get('name', ''),
                        'value': input_field.get('value', ''),
                        'suspicious': False
                    }

                    # Controlla valori nascosti sospetti
                    if input_field.get('type') == 'hidden':
                        value = input_field.get('value', '')
                        if value and (len(value) > 100 or 'http' in value):
                            input_data['suspicious'] = True
                            form_data['suspicious_indicators'].append('suspicious_hidden_input')

                    form_data['inputs'].append(input_data)

                analysis['forms'].append(form_data)

            return analysis

        except Exception as e:
            logger.warning(f"Errore nell'analisi form: {e}")
            return {'forms': [], 'suspicious_patterns': []}

    def _analyze_iframes(self, html_content: str) -> Dict[str, Any]:
        """Analizza iframe potenzialmente malevoli"""
        if not HAS_BEAUTIFULSOUP:
            return {'iframes': [], 'suspicious_count': 0}

        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            iframes = soup.find_all('iframe')
            analysis = {
                'iframes': [],
                'suspicious_count': 0
            }

            for iframe in iframes:
                iframe_data = {
                    'src': iframe.get('src', ''),
                    'width': iframe.get('width', ''),
                    'height': iframe.get('height', ''),
                    'suspicious_indicators': []
                }

                src = iframe.get('src', '')
                if src:
                    # Iframe con dimensioni 0 o molto piccole
                    width = iframe.get('width', '0')
                    height = iframe.get('height', '0')

                    try:
                        if (int(width) <= 1 or int(height) <= 1):
                            iframe_data['suspicious_indicators'].append('invisible_iframe')
                            analysis['suspicious_count'] += 1
                    except ValueError:
                        pass

                    # Src sospetto
                    if self._is_suspicious_url(src):
                        iframe_data['suspicious_indicators'].append('suspicious_src')
                        analysis['suspicious_count'] += 1

                analysis['iframes'].append(iframe_data)

            return analysis

        except Exception as e:
            logger.warning(f"Errore nell'analisi iframe: {e}")
            return {'iframes': [], 'suspicious_count': 0}

    def _analyze_inline_javascript(self, html_content: str) -> Dict[str, Any]:
        """Analizza JavaScript inline per offuscamento"""
        analysis = {
            'inline_scripts': [],
            'suspicious_patterns': []
        }

        # Trova script inline
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, html_content, re.DOTALL | re.IGNORECASE)

        for script in scripts:
            script_data = {
                'content': script[:200] + '...' if len(script) > 200 else script,
                'length': len(script),
                'suspicious_indicators': []
            }

            # Controlla pattern sospetti
            if 'eval(' in script:
                script_data['suspicious_indicators'].append('eval_usage')
                analysis['suspicious_patterns'].append('eval_in_script')

            if 'String.fromCharCode' in script:
                script_data['suspicious_indicators'].append('fromcharcode_usage')
                analysis['suspicious_patterns'].append('fromcharcode_in_script')

            if 'atob(' in script:
                script_data['suspicious_indicators'].append('base64_decode')
                analysis['suspicious_patterns'].append('atob_in_script')

            if 'document.write' in script:
                script_data['suspicious_indicators'].append('document_write')
                analysis['suspicious_patterns'].append('document_write_in_script')

            analysis['inline_scripts'].append(script_data)

        return analysis

    def _rate_hidden_element_suspicion(self, element) -> float:
        """Valuta quanto è sospetto un elemento nascosto"""
        score = 0.3  # Base per essere nascosto

        # Bonus se contiene testo significativo
        text_content = element.get_text().strip()
        if text_content and len(text_content) > 10:
            score += 0.3

        # Bonus se ha attributi onclick o simili
        if element.has_attr('onclick') or element.has_attr('onload'):
            score += 0.4

        return min(1.0, score)

    def _is_suspicious_url(self, url: str) -> bool:
        """Verifica se un URL sembra sospetto"""
        if not url:
            return False

        suspicious_patterns = [
            r'data:text/html',
            r'javascript:',
            r'vbscript:',
            r'base64,',
            r'eval\(',
            r'\\x[0-9a-fA-F]{2}',
            r'\\u[0-9a-fA-F]{4}'
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True

        return False

    def _calculate_html_suspicion(self, transformations, hidden_elements,
                                form_analysis, iframe_analysis, js_analysis) -> float:
        """Calcola punteggio di sospetto per l'HTML"""
        score = 0.0

        # Peso per trasformazioni
        score += len(transformations) * 0.2

        # Peso per elementi nascosti
        score += len(hidden_elements) * 0.15

        # Peso per form sospetti
        for form in form_analysis.get('forms', []):
            score += len(form.get('suspicious_indicators', [])) * 0.1

        # Peso per iframe sospetti
        score += iframe_analysis.get('suspicious_count', 0) * 0.2

        # Peso per JavaScript sospetto
        suspicious_scripts = [s for s in js_analysis.get('inline_scripts', [])
                            if s.get('suspicious_indicators')]
        score += len(suspicious_scripts) * 0.25

        # Peso per pattern JavaScript sospetti
        score += len(js_analysis.get('suspicious_patterns', [])) * 0.1

        return min(1.0, score)