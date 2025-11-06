# form_analysis.py - HTML Form Analysis for Payment and Attribution
import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

logger = logging.getLogger(__name__)

class FormAnalyzer:
    """Analyze HTML forms for payment patterns and merchant attribution"""

    def __init__(self):
        # Known payment processors and their patterns
        self.payment_processors = {
            'stripe': {
                'domains': ['js.stripe.com', 'api.stripe.com', 'checkout.stripe.com'],
                'form_patterns': ['stripe', 'pk_live_', 'pk_test_'],
                'input_names': ['stripeToken', 'stripe_key', 'stripe_publishable_key']
            },
            'paypal': {
                'domains': ['www.paypal.com', 'api.paypal.com', 'paypalobjects.com'],
                'form_patterns': ['paypal', 'paypal_button', 'bn_code'],
                'input_names': ['business', 'item_name', 'amount', 'currency_code']
            },
            'braintree': {
                'domains': ['js.braintreegateway.com', 'api.braintreegateway.com'],
                'form_patterns': ['braintree', 'dropin'],
                'input_names': ['braintree_token', 'payment_method_nonce']
            },
            'authorize_net': {
                'domains': ['js.authorize.net', 'api.authorize.net'],
                'form_patterns': ['authorize', 'authnet'],
                'input_names': ['api_login_id', 'transaction_key']
            },
            '2checkout': {
                'domains': ['www.2checkout.com', 'api.2checkout.com'],
                'form_patterns': ['2checkout', 'twocheckout'],
                'input_names': ['sid', 'cart_order_id']
            },
            'adyen': {
                'domains': ['checkoutshopper-live.adyen.com', 'checkoutshopper-test.adyen.com'],
                'form_patterns': ['adyen', 'adyen_checkout'],
                'input_names': ['adyen-encrypted-data', 'adyen-origin-key']
            },
            'square': {
                'domains': ['js.squareup.com', 'api.squareup.com'],
                'form_patterns': ['square', 'squareup'],
                'input_names': ['sq-card-number', 'sq-expiration-date', 'sq-cvv']
            },
            'shopify': {
                'domains': ['cdn.shopify.com', 'checkout.shopify.com'],
                'form_patterns': ['shopify', 'shopify-checkout'],
                'input_names': ['checkout', 'shopify_payment']
            }
        }

        # Common form field patterns
        self.field_patterns = {
            'credit_card': [
                r'card[_-]?number', r'cc[_-]?num', r'credit[_-]?card',
                r'card[_-]?no', r'cc[_-]?number'
            ],
            'expiry': [
                r'expir(?:y|ation)', r'exp[_-]?date', r'exp[_-]?month',
                r'exp[_-]?year', r'cc[_-]?exp'
            ],
            'cvv': [
                r'cvv', r'cvc', r'cvv2', r'cid', r'security[_-]?code',
                r'card[_-]?verification'
            ],
            'name': [
                r'card[_-]?name', r'name[_-]?on[_-]?card', r'holder[_-]?name',
                r'billing[_-]?name'
            ],
            'email': [
                r'email', r'e[_-]?mail', r'customer[_-]?email'
            ],
            'amount': [
                r'amount', r'price', r'total', r'cost', r'value'
            ],
            'currency': [
                r'currency', r'curr', r'iso[_-]?currency'
            ]
        }

    def analyze_forms(self, html_content: str, url: str = None) -> Dict[str, Any]:
        """Analyze HTML content for forms and payment patterns"""
        result = {
            'forms': [],
            'payment_processors': [],
            'suspicious_patterns': [],
            'attribution_hints': {},
            'form_summary': {},
            'errors': []
        }

        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = soup.find_all('form')

            for i, form in enumerate(forms):
                form_analysis = self._analyze_single_form(form, i, url)
                result['forms'].append(form_analysis)

            # Detect payment processors
            result['payment_processors'] = self._detect_payment_processors(html_content, soup)

            # Detect suspicious patterns
            result['suspicious_patterns'] = self._detect_suspicious_patterns(result['forms'])

            # Generate attribution hints
            result['attribution_hints'] = self._generate_form_attribution_hints(result)

            # Create summary
            result['form_summary'] = self._create_form_summary(result['forms'])

        except Exception as e:
            result['errors'].append(f"Form analysis failed: {str(e)}")
            logger.error(f"Form analysis failed for URL {url}: {e}")

        return result

    def _analyze_single_form(self, form, form_index: int, page_url: str = None) -> Dict[str, Any]:
        """Analyze a single HTML form"""
        form_analysis = {
            'index': form_index,
            'method': form.get('method', 'get').lower(),
            'action': form.get('action', ''),
            'enctype': form.get('enctype', ''),
            'inputs': [],
            'field_types': {},
            'payment_indicators': [],
            'suspicious_elements': []
        }

        # Resolve relative action URL
        if form_analysis['action'] and page_url:
            parsed_page = urlparse(page_url)
            if not form_analysis['action'].startswith(('http://', 'https://')):
                base_url = f"{parsed_page.scheme}://{parsed_page.netloc}"
                form_analysis['action'] = base_url + form_analysis['action']

        # Analyze input fields
        inputs = form.find_all('input')
        for input_field in inputs:
            input_analysis = self._analyze_input_field(input_field)
            form_analysis['inputs'].append(input_analysis)

            # Categorize field types
            field_type = input_analysis.get('field_type')
            if field_type:
                if field_type not in form_analysis['field_types']:
                    form_analysis['field_types'][field_type] = []
                form_analysis['field_types'][field_type].append(input_analysis)

        # Check for payment indicators
        form_analysis['payment_indicators'] = self._check_payment_indicators(form_analysis)

        # Check for suspicious elements
        form_analysis['suspicious_elements'] = self._check_suspicious_elements(form, form_analysis)

        return form_analysis

    def _analyze_input_field(self, input_field) -> Dict[str, Any]:
        """Analyze a single input field"""
        field_analysis = {
            'type': input_field.get('type', 'text'),
            'name': input_field.get('name', ''),
            'id': input_field.get('id', ''),
            'placeholder': input_field.get('placeholder', ''),
            'value': input_field.get('value', ''),
            'required': input_field.get('required') is not None,
            'field_type': None,
            'payment_relevance': 'none'
        }

        # Determine field type based on patterns
        field_name = (field_analysis['name'] + ' ' + field_analysis['id'] + ' ' + field_analysis['placeholder']).lower()

        for category, patterns in self.field_patterns.items():
            for pattern in patterns:
                if re.search(pattern, field_name, re.IGNORECASE):
                    field_analysis['field_type'] = category
                    if category in ['credit_card', 'cvv', 'expiry']:
                        field_analysis['payment_relevance'] = 'high'
                    elif category in ['amount', 'currency']:
                        field_analysis['payment_relevance'] = 'medium'
                    break

        return field_analysis

    def _check_payment_indicators(self, form_analysis: Dict) -> List[str]:
        """Check for payment-related indicators in form"""
        indicators = []

        # Check field types
        field_types = form_analysis.get('field_types', {})
        if 'credit_card' in field_types:
            indicators.append('credit_card_fields')
        if 'cvv' in field_types:
            indicators.append('cvv_fields')
        if 'expiry' in field_types:
            indicators.append('expiry_fields')
        if 'amount' in field_types:
            indicators.append('amount_fields')

        # Check for multiple payment fields
        payment_fields = ['credit_card', 'cvv', 'expiry', 'name']
        payment_field_count = sum(1 for ft in payment_fields if ft in field_types)
        if payment_field_count >= 3:
            indicators.append('complete_payment_form')

        # Check form method and enctype
        if form_analysis.get('method') == 'post':
            indicators.append('post_method')
        if form_analysis.get('enctype') == 'multipart/form-data':
            indicators.append('file_upload_capable')

        return indicators

    def _check_suspicious_elements(self, form, form_analysis: Dict) -> List[str]:
        """Check for suspicious elements in form"""
        suspicious = []

        # Check for hidden sensitive fields
        hidden_inputs = form.find_all('input', {'type': 'hidden'})
        sensitive_patterns = ['password', 'token', 'key', 'secret', 'api']
        for hidden in hidden_inputs:
            name = hidden.get('name', '').lower()
            value = hidden.get('value', '')
            for pattern in sensitive_patterns:
                if pattern in name and len(value) > 10:  # Long hidden values
                    suspicious.append(f'hidden_sensitive_field: {name}')

        # Check for obfuscated field names
        for input_field in form_analysis.get('inputs', []):
            name = input_field.get('name', '')
            if name and len(name) > 50:  # Very long field names
                suspicious.append('obfuscated_field_names')

        # Check for unusual form actions
        action = form_analysis.get('action', '')
        if action and 'javascript:' in action.lower():
            suspicious.append('javascript_form_action')

        # Check for data: URLs
        if action and action.startswith('data:'):
            suspicious.append('data_url_form_action')

        return suspicious

    def _detect_payment_processors(self, html_content: str, soup) -> List[Dict[str, Any]]:
        """Detect payment processors in HTML content"""
        detected_processors = []

        # Check for script sources
        scripts = soup.find_all('script', {'src': True})
        for script in scripts:
            src = script['src'].lower()
            for processor_name, patterns in self.payment_processors.items():
                for domain in patterns['domains']:
                    if domain in src:
                        detected_processors.append({
                            'processor': processor_name,
                            'detection_method': 'script_domain',
                            'evidence': src,
                            'confidence': 'high'
                        })

        # Check for form patterns in HTML
        html_lower = html_content.lower()
        for processor_name, patterns in self.payment_processors.items():
            for pattern in patterns['form_patterns']:
                if pattern in html_lower:
                    detected_processors.append({
                        'processor': processor_name,
                        'detection_method': 'form_pattern',
                        'evidence': pattern,
                        'confidence': 'medium'
                    })

        # Check for specific input names
        all_inputs = soup.find_all('input')
        for input_field in all_inputs:
            name = input_field.get('name', '').lower()
            for processor_name, patterns in self.payment_processors.items():
                for input_pattern in patterns['input_names']:
                    if input_pattern in name:
                        detected_processors.append({
                            'processor': processor_name,
                            'detection_method': 'input_name',
                            'evidence': name,
                            'confidence': 'high'
                        })

        # Remove duplicates and sort by confidence
        unique_processors = {}
        for proc in detected_processors:
            key = proc['processor']
            if key not in unique_processors or self._get_confidence_score(proc['confidence']) > self._get_confidence_score(unique_processors[key]['confidence']):
                unique_processors[key] = proc

        return list(unique_processors.values())

    def _get_confidence_score(self, confidence: str) -> int:
        """Convert confidence string to numeric score"""
        scores = {'low': 1, 'medium': 2, 'high': 3}
        return scores.get(confidence, 0)

    def _detect_suspicious_patterns(self, forms: List[Dict]) -> List[Dict[str, Any]]:
        """Detect suspicious patterns across all forms"""
        suspicious = []

        # Check for multiple payment forms
        payment_forms = [f for f in forms if 'complete_payment_form' in f.get('payment_indicators', [])]
        if len(payment_forms) > 1:
            suspicious.append({
                'type': 'multiple_payment_forms',
                'description': 'Multiple complete payment forms detected',
                'severity': 'medium'
            })

        # Check for forms with many hidden fields
        for form in forms:
            hidden_count = sum(1 for inp in form.get('inputs', []) if inp.get('type') == 'hidden')
            if hidden_count > 10:
                suspicious.append({
                    'type': 'excessive_hidden_fields',
                    'description': f'Form {form["index"]} has {hidden_count} hidden fields',
                    'severity': 'low'
                })

        # Check for suspicious form actions
        for form in forms:
            action = form.get('action', '')
            if action:
                parsed = urlparse(action)
                if parsed.scheme not in ['http', 'https', '']:
                    suspicious.append({
                        'type': 'suspicious_form_action',
                        'description': f'Unusual form action scheme: {parsed.scheme}',
                        'severity': 'medium'
                    })

        return suspicious

    def _generate_form_attribution_hints(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate attribution hints from form analysis"""
        hints = {
            'payment_ecosystem': 'unknown',
            'merchant_category': 'unknown',
            'risk_indicators': [],
            'correlation_keys': []
        }

        # Payment ecosystem analysis
        processors = result.get('payment_processors', [])
        if processors:
            processor_names = [p['processor'] for p in processors]
            if 'stripe' in processor_names:
                hints['payment_ecosystem'] = 'stripe_ecosystem'
            elif 'paypal' in processor_names:
                hints['payment_ecosystem'] = 'paypal_ecosystem'
            elif 'shopify' in processor_names:
                hints['payment_ecosystem'] = 'shopify_ecosystem'
            else:
                hints['payment_ecosystem'] = 'mixed_processors'

        # Merchant category hints
        forms = result.get('forms', [])
        payment_indicators = []
        for form in forms:
            payment_indicators.extend(form.get('payment_indicators', []))

        if 'complete_payment_form' in payment_indicators:
            hints['merchant_category'] = 'ecommerce_payment'
        elif 'credit_card_fields' in payment_indicators:
            hints['merchant_category'] = 'card_processor'
        elif any('file_upload' in ind for ind in payment_indicators):
            hints['merchant_category'] = 'data_collection'

        # Risk indicators
        suspicious = result.get('suspicious_patterns', [])
        risk_indicators = []
        for susp in suspicious:
            risk_indicators.append({
                'type': susp['type'],
                'severity': susp['severity'],
                'description': susp['description']
            })

        hints['risk_indicators'] = risk_indicators

        # Correlation keys
        correlation_keys = []

        # Payment processors
        for proc in processors:
            correlation_keys.append(f"payment_processor:{proc['processor']}")

        # Form field patterns
        for form in forms:
            for field_type in form.get('field_types', {}):
                correlation_keys.append(f"form_field:{field_type}")

        # Suspicious elements
        for form in forms:
            for susp in form.get('suspicious_elements', []):
                correlation_keys.append(f"suspicious:{susp.split(':')[0]}")

        hints['correlation_keys'] = correlation_keys

        return hints

    def _create_form_summary(self, forms: List[Dict]) -> Dict[str, Any]:
        """Create a summary of form analysis"""
        summary = {
            'total_forms': len(forms),
            'forms_by_method': defaultdict(int),
            'total_inputs': 0,
            'input_types': defaultdict(int),
            'field_type_distribution': defaultdict(int),
            'payment_forms': 0,
            'suspicious_forms': 0
        }

        for form in forms:
            # Method distribution
            summary['forms_by_method'][form.get('method', 'unknown')] += 1

            # Input analysis
            inputs = form.get('inputs', [])
            summary['total_inputs'] += len(inputs)

            for inp in inputs:
                summary['input_types'][inp.get('type', 'unknown')] += 1

            # Field type distribution
            for field_type in form.get('field_types', {}):
                summary['field_type_distribution'][field_type] += len(form['field_types'][field_type])

            # Payment and suspicious forms
            if 'complete_payment_form' in form.get('payment_indicators', []):
                summary['payment_forms'] += 1

            if form.get('suspicious_elements'):
                summary['suspicious_forms'] += 1

        return dict(summary)

    def correlate_forms_across_pages(self, page_analyses: List[Dict]) -> Dict[str, Any]:
        """Correlate form patterns across multiple pages"""
        correlation = {
            'common_processors': {},
            'common_field_patterns': {},
            'form_similarity_clusters': [],
            'payment_ecosystem_consistency': {},
            'suspicious_pattern_trends': {}
        }

        # Collect all processors
        all_processors = defaultdict(list)
        for i, analysis in enumerate(page_analyses):
            for proc in analysis.get('payment_processors', []):
                all_processors[proc['processor']].append(i)

        correlation['common_processors'] = {k: v for k, v in all_processors.items() if len(v) > 1}

        # Collect field patterns
        all_field_types = defaultdict(list)
        for i, analysis in enumerate(page_analyses):
            for form in analysis.get('forms', []):
                for field_type in form.get('field_types', {}):
                    all_field_types[field_type].append(i)

        correlation['common_field_patterns'] = {k: v for k, v in all_field_types.items() if len(v) > 1}

        # Analyze payment ecosystem consistency
        ecosystems = [a.get('attribution_hints', {}).get('payment_ecosystem', 'unknown') for a in page_analyses]
        ecosystem_counts = defaultdict(int)
        for eco in ecosystems:
            ecosystem_counts[eco] += 1

        correlation['payment_ecosystem_consistency'] = dict(ecosystem_counts)

        return correlation

def analyze_html_forms(html_content: str, url: str = None) -> Dict[str, Any]:
    """Convenience function for form analysis"""
    analyzer = FormAnalyzer()
    return analyzer.analyze_forms(html_content, url)