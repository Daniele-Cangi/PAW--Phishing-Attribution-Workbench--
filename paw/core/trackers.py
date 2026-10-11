"""Bounded tracker-pattern observations from supplied text and log records."""
from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import re
import json
import math
from urllib.parse import urlsplit


@dataclass(frozen=True)
class TrackerLimits:
    source_bytes: int = 1024 * 1024
    total_bytes: int = 2 * 1024 * 1024
    network_entries: int = 1024
    observations: int = 2048
    value_chars: int = 4096
    json_nodes: int = 16384
    json_depth: int = 8
    integer_bits: int = 4096

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in asdict(self).values()):
            raise ValueError('Tracker limits must be positive integers')

class TrackerExtractor:
    """Observe registry matches, not executed trackers or verified identities."""

    # Common tracker patterns
    TRACKER_PATTERNS = {
        'google_analytics': {
            'patterns': [
                r'UA-\d{4,10}-\d+',  # Universal Analytics
                r'G-[A-Z0-9]+',      # GA4 Measurement ID
                r'GTM-[A-Z0-9]+',    # Google Tag Manager
            ],
            'name': 'Google Analytics',
            'category': 'analytics'
        },
        'facebook_pixel': {
            'patterns': [
                r'fbq\(["\']init["\'],\s*["\'](\d+)["\']',
                r'facebook\.com/tr\?id=(\d+)',
            ],
            'name': 'Facebook Pixel',
            'category': 'social_tracking'
        },
        'tiktok_pixel': {
            'patterns': [
                r'ttp\(["\']init["\'],\s*["\']([A-Z0-9]+)["\']',
                r'analytics\.tiktok\.com/i18n/pixel/events',
            ],
            'name': 'TikTok Pixel',
            'category': 'social_tracking'
        },
        'matomo': {
            'patterns': [
                r'_paq\.push\(\[["\']setSiteId["\'],\s*["\']?(\d+)["\']?\]',
                r'matomo\.js',
                r'piwik\.js',
            ],
            'name': 'Matomo/Piwik',
            'category': 'analytics'
        },
        'hotjar': {
            'patterns': [
                r'hj\.hj\(["\'](\d+)["\']',
                r'hotjar\.com',
            ],
            'name': 'Hotjar',
            'category': 'user_tracking'
        },
        'mixpanel': {
            'patterns': [
                r'mixpanel\.init\(["\']([a-zA-Z0-9]+)["\']',
            ],
            'name': 'Mixpanel',
            'category': 'analytics'
        },
        'segment': {
            'patterns': [
                r'analytics\.load\(["\']([a-zA-Z0-9]+)["\']',
            ],
            'name': 'Segment',
            'category': 'analytics'
        }
    }

    TRACKING_DOMAINS = ('google-analytics.com', 'googletagmanager.com', 'facebook.com',
                        'connect.facebook.net', 'tiktok.com', 'analytics.tiktok.com',
                        'hotjar.com', 'mixpanel.com', 'segment.com', 'matomo.org')

    def __init__(self, *, limits=None):
        if limits is not None and not isinstance(limits, TrackerLimits):
            raise ValueError('limits must be TrackerLimits')
        self.limits = limits if limits is not None else TrackerLimits()

    def extract_from_html(self, html_content, url=''):
        inventory = _Inventory(self)
        inventory.text(html_content, 'html', url)
        return inventory.finish()

    def extract_from_javascript(self, js_content, url=''):
        inventory = _Inventory(self)
        inventory.text(js_content, 'javascript', url)
        return inventory.finish()

    def extract_from_network_logs(self, network_logs):
        inventory = _Inventory(self)
        inventory.logs(network_logs)
        return inventory.finish()

    def correlate_campaigns(self, current_trackers, known_campaigns):
        return {'status': 'unavailable', 'verified': False, 'matches': [],
                'confidence': None, 'related_campaigns': [],
                'reason': 'Tracker strings do not establish campaign identity; no validated correlation contract'}


class _Rejected(ValueError):
    pass


class _Inventory:
    def __init__(self, extractor):
        self.extractor, self.limits = extractor, extractor.limits
        self.json_nodes = 0
        self.result = {'schema_version': 2, 'status': 'completed', 'verified': False,
            'scope': 'supplied lexical observations; not tracker execution, log authenticity or attribution',
            'limits': asdict(self.limits), 'sources': [], 'observations': [], 'summary': {},
            'trackers_found': [], 'network_trackers': [], 'third_party_domains': [],
            'tracking_pixels': [], 'correlation_keys': [],
            'interpretation': {'status': 'unavailable', 'verified': False,
                'reason': 'Patterns do not verify tracking, image dimensions, third-party ownership or campaign/operator identity'},
            'coverage': {'processed_bytes': 0, 'total_log_count': 0, 'omitted_log_count': 0,
                'total_observation_count': 0, 'omitted_observation_count': 0, 'issues': []}}

    def issue(self, reason):
        self.result['status'] = 'partial'
        if reason not in self.result['coverage']['issues']:
            self.result['coverage']['issues'].append(reason)

    def source(self, kind, index):
        source = {'index': len(self.result['sources']), 'kind': kind,
                  'input_index': index, 'status': 'not_analyzed'}
        self.result['sources'].append(source)
        return source

    def admit(self, source, content, scope):
        try:
            if not isinstance(content, str): raise _Rejected('invalid_source_type')
            if len(content) > self.limits.source_bytes: raise _Rejected('source_byte_limit')
            raw = content.encode('utf-8')
            if len(raw) > self.limits.source_bytes: raise _Rejected('source_byte_limit')
            if self.result['coverage']['processed_bytes'] + len(raw) > self.limits.total_bytes:
                raise _Rejected('total_byte_limit')
        except (UnicodeEncodeError, _Rejected) as exc:
            source['reason'] = 'invalid_source_unicode' if isinstance(exc, UnicodeEncodeError) else str(exc)
            self.issue(source['reason'])
            return False
        self.result['coverage']['processed_bytes'] += len(raw)
        source.update(status='analyzed', sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw), hash_scope=scope)
        return True

    def emit(self, source, **row):
        coverage = self.result['coverage']
        coverage['total_observation_count'] += 1
        if len(self.result['observations']) >= self.limits.observations:
            coverage['omitted_observation_count'] += 1
            self.issue('observation_count_limit')
            return
        self.result['observations'].append({'source_index': source['index'], 'verified': False,
            'interpretation_status': 'lexical_observation', **row})

    def patterns(self, source, content, field):
        for tracker_type, config in self.extractor.TRACKER_PATTERNS.items():
            for index, pattern in enumerate(config['patterns']):
                compiled = re.compile(pattern, re.I)
                for match in compiled.finditer(content):
                    if match.end() - match.start() > self.limits.value_chars:
                        self.result['coverage']['total_observation_count'] += 1
                        self.result['coverage']['omitted_observation_count'] += 1
                        self.issue('observation_value_limit')
                        continue
                    identifier_group = 1 if compiled.groups else (0 if tracker_type == 'google_analytics' else None)
                    self.emit(source, context='registry_pattern', source_field=field,
                        tracker_type=tracker_type, registry_name=config['name'], category=config['category'],
                        pattern_index=index, pattern=pattern, matched_text=match.group(),
                        span={'start': match.start(), 'end': match.end()},
                        identifier_candidate=match.group(identifier_group) if identifier_group is not None else None,
                        identifier_span=({'start': match.start(identifier_group), 'end': match.end(identifier_group)}
                                         if identifier_group is not None else None))

    def text(self, content, kind, url):
        source = self.source(kind, 0)
        source['source_url'] = None
        if url is not None:
            try:
                if not isinstance(url, str) or len(url) > self.limits.value_chars:
                    raise _Rejected('invalid_or_limited_source_url')
                url.encode('utf-8')
                source['source_url'] = url
            except (UnicodeEncodeError, _Rejected):
                self.issue('invalid_or_limited_source_url')
        if self.admit(source, content, 'complete supplied Unicode text encoded as UTF-8'):
            self.patterns(source, content, 'text')

    def json_copy(self, value, depth, budget):
        self.json_nodes += 1
        if self.json_nodes > self.limits.json_nodes: raise _Rejected('json_node_limit')
        if depth > self.limits.json_depth: raise _Rejected('json_depth_limit')
        kind = type(value)
        if kind in {dict, list}:
            budget[0] += 2 + max(0, len(value) - 1) + (len(value) if kind is dict else 0)
            if budget[0] > budget[1]: raise _Rejected(budget[2])
            if len(value) > self.limits.json_nodes: raise _Rejected('json_node_limit')
            if kind is list:
                return [self.json_copy(v, depth + 1, budget) for v in value]
            result = {}
            for key, item in value.items():
                if type(key) is not str: raise _Rejected('nonstring_json_key')
                copied_key = self.json_copy(key, depth + 1, budget)
                result[copied_key] = self.json_copy(item, depth + 1, budget)
            return result
        if kind not in {str, int, float, bool, type(None)}: raise _Rejected('unsupported_json_value')
        if kind is str:
            if len(value) > budget[1] - budget[0]: raise _Rejected(budget[2])
            try: value.encode('utf-8')
            except UnicodeEncodeError: raise _Rejected('invalid_source_unicode') from None
        if kind is int and value.bit_length() > self.limits.integer_bits:
            raise _Rejected('integer_bit_limit')
        if kind is float and not math.isfinite(value): raise _Rejected('nonfinite_json_number')
        budget[0] += len(json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':')))
        if budget[0] > budget[1]: raise _Rejected(budget[2])
        return value

    def parsed_url(self, source, value, field):
        try:
            if not isinstance(value, str): raise _Rejected('invalid_url_type')
            if len(value) > self.limits.value_chars: raise _Rejected('url_value_limit')
            if '\\' in value or any(ord(c) <= 32 or ord(c) == 127 for c in value):
                raise _Rejected('unsupported_url_characters')
            parsed = urlsplit(value)
            parsed.port
            if parsed.scheme.lower() not in {'http', 'https'} or not parsed.hostname:
                raise _Rejected('unresolved_or_unsupported_url_scheme')
        except (ValueError, _Rejected) as exc:
            reason = str(exc) if isinstance(exc, _Rejected) else 'malformed_url'
            source[field + '_interpretation'] = {'status': 'not_interpreted', 'reason': reason}
            self.issue(reason)
            return None
        source[field + '_interpretation'] = {'status': 'derived_literal', 'verified': False,
                                             'method': 'urllib.parse.urlsplit; not browser navigation'}
        return parsed

    def logs(self, logs):
        if type(logs) is not list:
            self.issue('invalid_log_list_type')
            return
        coverage = self.result['coverage']
        coverage['total_log_count'] = len(logs)
        coverage['omitted_log_count'] = max(0, len(logs) - self.limits.network_entries)
        if coverage['omitted_log_count']: self.issue('network_entry_limit')
        for index, log in enumerate(logs[:self.limits.network_entries]):
            source = self.source('network_record', index)
            try:
                if type(log) is not dict: raise _Rejected('invalid_log_record_type')
                remaining = self.limits.total_bytes - coverage['processed_bytes']
                cap = min(self.limits.source_bytes, remaining)
                reason = 'total_byte_limit' if remaining < self.limits.source_bytes else 'source_byte_limit'
                if cap <= 0: raise _Rejected(reason)
                record = self.json_copy(log, 0, [0, cap, reason])
                canonical = json.dumps(record, ensure_ascii=True, sort_keys=True, allow_nan=False, separators=(',', ':'))
            except (ValueError, _Rejected) as exc:
                source['reason'] = str(exc) if isinstance(exc, _Rejected) else 'json_serialization_failure'
                self.issue(source['reason'])
                continue
            if not self.admit(source, canonical, 'complete supplied record canonical JSON: sorted keys, ASCII escapes, compact separators'):
                continue
            source['supplied_record'] = record
            url = record.get('url')
            if isinstance(url, str): self.patterns(source, url, 'url')
            parsed = self.parsed_url(source, url, 'url')
            if parsed is None: continue
            self.emit(source, context='url_components', source_field='url', value=url,
                      hostname=parsed.hostname, path=parsed.path, query=parsed.query, fragment=parsed.fragment)
            for domain in self.extractor.TRACKING_DOMAINS:
                if parsed.hostname == domain or parsed.hostname.endswith('.' + domain):
                    self.emit(source, context='hostname_registry_match', source_field='url',
                              value=parsed.hostname, registry_domain=domain)
            if parsed.path.lower().endswith(('.gif', '.png', '.jpg')):
                self.emit(source, context='image_path_extension', source_field='url', value=parsed.path)
            if 'referer' in record:
                referer = self.parsed_url(source, record['referer'], 'referer')
                if referer is not None:
                    self.emit(source, context='literal_hostname_comparison', source_field='url/referer',
                              url_hostname=parsed.hostname, referer_hostname=referer.hostname,
                              equal=parsed.hostname == referer.hostname)

    def finish(self):
        observations = self.result['observations']
        self.result['summary'] = {'retained_observation_count': len(observations),
            'counts_by_context': dict(Counter(row['context'] for row in observations)),
            'registry_match_counts_by_type': dict(Counter(row['tracker_type'] for row in observations if 'tracker_type' in row)),
            'scope': 'retained lexical occurrences; not unique trackers, visits or campaign evidence'}
        return self.result


def extract_trackers(html_content, js_content='', network_logs=None, source_url='', *, limits=None):
    """Combine supplied sources with shared byte, observation and JSON budgets."""
    inventory = _Inventory(TrackerExtractor(limits=limits))
    inventory.text(html_content, 'html', source_url)
    if js_content != '': inventory.text(js_content, 'javascript', source_url)
    if network_logs is not None: inventory.logs(network_logs)
    return inventory.finish()
