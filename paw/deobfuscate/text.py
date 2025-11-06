#!/usr/bin/env python3
"""
PAW - Text Deobfuscation Module
Deoffusca testo offuscato nei phishing (sostituzioni caratteri, rumore, ecc.)
"""

import re
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

class TextDeobfuscator:
    """Deoffuscatore specializzato per testo"""

    def __init__(self):
        # Mappa caratteri simili (homoglyphs)
        self.character_substitutions = {
            # Numeri che sembrano lettere
            '0': 'O', '1': 'I', '3': 'E', '4': 'A', '5': 'S',
            '6': 'G', '7': 'T', '8': 'B', '9': 'g',

            # Lettere che sembrano altre lettere
            '|': 'I', '!': 'I', 'l': 'I', 'ı': 'I',
            'ο': 'O', 'Ο': 'O', 'о': 'O', 'О': 'O',
            'а': 'A', 'А': 'A', 'α': 'A', 'Α': 'A',
            'е': 'E', 'Е': 'E', 'ε': 'E', 'Ε': 'E',
            'р': 'P', 'Р': 'P', 'ρ': 'P', 'Ρ': 'P',
            'с': 'C', 'С': 'C', 'ϲ': 'C',
            'х': 'X', 'Х': 'X', 'χ': 'X', 'Χ': 'X',
            'і': 'I', 'І': 'I', 'ϊ': 'I',
            'ј': 'J', 'Ј': 'J',
            'ӏ': 'L', 'Ӏ': 'L',

            # Simboli speciali
            '€': 'E', '£': 'L', '¥': 'Y', '¢': 'C',
            '®': 'R', '©': 'C', '™': 'T',
            '∞': 'OO', '±': '+-', 'µ': 'U',
            '¶': 'P', '·': '·', '¸': ',', '¹': '1',
            'º': 'O', '»': '"', '¼': '1/4', '½': '1/2',
            '¾': '3/4', '¿': '?', '×': 'X', '÷': '/',
            'ø': 'O', 'Ø': 'O',

            # Caratteri accentati
            'À': 'A', 'Á': 'A', 'Â': 'A', 'Ã': 'A', 'Ä': 'A', 'Å': 'A', 'Æ': 'AE',
            'Ç': 'C', 'È': 'E', 'É': 'E', 'Ê': 'E', 'Ë': 'E',
            'Ì': 'I', 'Í': 'I', 'Î': 'I', 'Ï': 'I',
            'Ð': 'D', 'Ñ': 'N', 'Ò': 'O', 'Ó': 'O', 'Ô': 'O', 'Õ': 'O', 'Ö': 'O',
            'Ù': 'U', 'Ú': 'U', 'Û': 'U', 'Ü': 'U', 'Ý': 'Y', 'Þ': 'TH',
            'ß': 'SS', 'à': 'A', 'á': 'A', 'â': 'A', 'ã': 'A', 'ä': 'A', 'å': 'A', 'æ': 'AE',
            'ç': 'C', 'è': 'E', 'é': 'E', 'ê': 'E', 'ë': 'E',
            'ì': 'I', 'í': 'I', 'î': 'I', 'ï': 'I',
            'ð': 'D', 'ñ': 'N', 'ò': 'O', 'ó': 'O', 'ô': 'O', 'õ': 'O', 'ö': 'O',
            'ù': 'U', 'ú': 'U', 'û': 'U', 'ü': 'U', 'ý': 'Y', 'þ': 'TH', 'ÿ': 'Y'
        }

    def deobfuscate_text(self, text: str) -> Dict[str, Any]:
        """
        Deoffusca testo applicando multiple tecniche

        Args:
            text: Testo potenzialmente offuscato

        Returns:
            Dizionario con testo finale e trasformazioni applicate
        """
        transformations = []
        current_text = text

        # 1. Sostituzioni di caratteri simili
        char_substituted = self._substitute_similar_characters(current_text)
        if char_substituted != current_text:
            transformations.append({
                'technique': 'character_substitution',
                'from': current_text,
                'to': char_substituted,
                'description': 'Sostituzione caratteri simili (homoglyphs)'
            })
            current_text = char_substituted

        # 2. Rimozione rumore (spazi extra, caratteri speciali inseriti)
        noise_removed = self._remove_noise(current_text)
        if noise_removed != current_text:
            transformations.append({
                'technique': 'noise_removal',
                'from': current_text,
                'to': noise_removed,
                'description': 'Rimozione rumore (spazi extra, caratteri speciali)'
            })
            current_text = noise_removed

        # 3. Correzione maiuscole/minuscole sospette
        case_corrected = self._correct_suspicious_case(current_text)
        if case_corrected != current_text:
            transformations.append({
                'technique': 'case_correction',
                'from': current_text,
                'to': case_corrected,
                'description': 'Correzione maiuscole/minuscole sospette'
            })
            current_text = case_corrected

        # 4. Espansione abbreviazioni comuni nei phishing
        expanded = self._expand_phishing_abbreviations(current_text)
        if expanded != current_text:
            transformations.append({
                'technique': 'abbreviation_expansion',
                'from': current_text,
                'to': expanded,
                'description': 'Espansione abbreviazioni phishing'
            })
            current_text = expanded

        # Analizza il testo finale
        analysis = self._analyze_final_text(current_text)

        return {
            'original_text': text,
            'final_text': current_text,
            'transformations': transformations,
            'analysis': analysis,
            'suspicion_score': self._calculate_text_suspicion(transformations, analysis),
            'readability_improvement': self._calculate_readability_improvement(text, current_text)
        }

    def _substitute_similar_characters(self, text: str) -> str:
        """Sostituisce caratteri simili con quelli ASCII standard"""
        result = text
        substitutions_made = []

        for char, replacement in self.character_substitutions.items():
            if char in result:
                result = result.replace(char, replacement)
                substitutions_made.append(f"{char}→{replacement}")

        return result

    def _remove_noise(self, text: str) -> str:
        """Rimuove rumore comune nei testi offuscati"""
        result = text

        # Rimuovi spazi multipli consecutivi
        result = re.sub(r' +', ' ', result)

        # Rimuovi caratteri di controllo non stampabili (eccetto newline/tab)
        result = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', result)

        # Rimuovi sequenze ripetute di caratteri speciali
        result = re.sub(r'([^\w\s])\1{2,}', r'\1', result)

        # Rimuovi spazi intorno a punteggiatura
        result = re.sub(r'\s+([,.!?;:])', r'\1', result)
        result = re.sub(r'([,.!?;:])\s+', r'\1 ', result)

        return result

    def _correct_suspicious_case(self, text: str) -> str:
        """Corregge maiuscole/minuscole sospette"""
        result = text

        # Parole completamente maiuscole più lunghe di 2 caratteri (eccetto acronimi comuni)
        words = re.findall(r'\b[A-Z]{3,}\b', result)
        for word in words:
            # Salta acronimi comuni
            if word not in ['CEO', 'CTO', 'CFO', 'HR', 'IT', 'URL', 'IP', 'VPN', 'SSL', 'TLS']:
                # Converte a Title Case
                corrected = word.capitalize()
                result = result.replace(word, corrected)

        # Parole che iniziano con minuscola dopo punto (inizio frase)
        sentences = re.split(r'(?<=[.!?])\s+', result)
        corrected_sentences = []
        for sentence in sentences:
            if sentence.strip():
                # Prima parola della frase dovrebbe iniziare con maiuscola
                words = sentence.split()
                if words and words[0].islower():
                    words[0] = words[0].capitalize()
                corrected_sentences.append(' '.join(words))

        result = '. '.join(corrected_sentences)

        return result

    def _expand_phishing_abbreviations(self, text: str) -> str:
        """Espande abbreviazioni comuni nei phishing"""
        expansions = {
            r'\bpls?\b': 'please',
            r'\bthx\b': 'thanks',
            r'\btx\b': 'thanks',
            r'\bu\b': 'you',
            r'\bur\b': 'your',
            r'\b2\b': 'to',
            r'\b4\b': 'for',
            r'\br\b': 'are',
            r'\bmsg\b': 'message',
            r'\bplz\b': 'please',
            r'\bthnx\b': 'thanks',
            r'\bacc\b': 'account',
            r'\bpwd\b': 'password',
            r'\bpw\b': 'password',
            r'\busr\b': 'user',
            r'\bid\b': 'identification',
            r'\bverif\b': 'verify',
            r'\bconf\b': 'confirm',
            r'\bupd\b': 'update',
            r'\bsec\b': 'security',
            r'\bsupp\b': 'support'
        }

        result = text
        for pattern, expansion in expansions.items():
            result = re.sub(pattern, expansion, result, flags=re.IGNORECASE)

        return result

    def _analyze_final_text(self, text: str) -> Dict[str, Any]:
        """Analizza il testo finale per caratteristiche"""
        analysis = {
            'word_count': len(text.split()),
            'character_count': len(text),
            'uppercase_ratio': sum(1 for c in text if c.isupper()) / max(1, len(text)),
            'digit_ratio': sum(1 for c in text if c.isdigit()) / max(1, len(text)),
            'special_char_ratio': sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(1, len(text)),
            'phishing_keywords': [],
            'suspicious_patterns': []
        }

        # Parole chiave phishing
        phishing_words = [
            'password', 'login', 'account', 'verify', 'confirm', 'update',
            'security', 'bank', 'credit', 'card', 'payment', 'transfer',
            'urgent', 'immediate', 'action', 'required', 'click', 'link'
        ]

        text_lower = text.lower()
        for word in phishing_words:
            if word in text_lower:
                analysis['phishing_keywords'].append(word)

        # Pattern sospetti
        suspicious_patterns = [
            r'\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b',  # Numero carta di credito
            r'\b\d{3}[\s-]\d{2}[\s-]\d{4}\b',  # SSN
            r'\b\d{10,15}\b',  # Numeri lunghi (possibili account)
            r'https?://[^\s]+',  # URL
            r'\b\d+\.\d+\.\d+\.\d+\b'  # IP addresses
        ]

        for pattern in suspicious_patterns:
            matches = re.findall(pattern, text)
            if matches:
                analysis['suspicious_patterns'].extend(matches[:5])  # Max 5 per pattern

        return analysis

    def _calculate_text_suspicion(self, transformations: List, analysis: Dict) -> float:
        """Calcola punteggio di sospetto per il testo"""
        score = 0.0

        # Peso per trasformazioni
        score += len(transformations) * 0.15

        # Peso per parole chiave phishing
        phishing_keywords = analysis.get('phishing_keywords', [])
        score += len(phishing_keywords) * 0.1

        # Peso per pattern sospetti
        suspicious_patterns = analysis.get('suspicious_patterns', [])
        score += len(suspicious_patterns) * 0.2

        # Peso per ratio caratteri speciali alto
        special_ratio = analysis.get('special_char_ratio', 0)
        if special_ratio > 0.1:
            score += (special_ratio - 0.1) * 2

        # Peso per ratio maiuscole alto (testo che urla)
        uppercase_ratio = analysis.get('uppercase_ratio', 0)
        if uppercase_ratio > 0.3:
            score += (uppercase_ratio - 0.3) * 1.5

        return min(1.0, score)

    def _calculate_readability_improvement(self, original: str, final: str) -> float:
        """Calcola miglioramento leggibilità (0-1, dove 1 è massima leggibilità)"""
        if not original or original == final:
            return 0.0

        # Calcola "leggibilità" basata su vari fattori
        original_score = self._calculate_readability_score(original)
        final_score = self._calculate_readability_score(final)

        improvement = final_score - original_score
        return max(0.0, min(1.0, improvement))

    def _calculate_readability_score(self, text: str) -> float:
        """Calcola punteggio leggibilità (semplificato)"""
        if not text:
            return 0.0

        score = 0.0

        # Penalità per caratteri speciali
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        score -= special_chars / len(text) * 0.5

        # Bonus per spazi (separazione parole)
        spaces = text.count(' ')
        score += min(0.3, spaces / len(text))

        # Penalità per maiuscole eccessive
        uppercase = sum(1 for c in text if c.isupper())
        uppercase_ratio = uppercase / len(text)
        if uppercase_ratio > 0.2:
            score -= (uppercase_ratio - 0.2) * 0.4

        # Bonus per lunghezza parole ragionevole
        words = text.split()
        if words:
            avg_word_length = sum(len(w) for w in words) / len(words)
            if 3 <= avg_word_length <= 8:
                score += 0.2

        return max(0.0, min(1.0, score + 0.5))  # Normalizza intorno a 0.5