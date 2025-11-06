# trackers.py - Analytics and Tracker ID Extraction
import re
import json
import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class TrackerExtractor:
    """Extract analytics and tracking IDs from HTML/JavaScript content"""

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
                r'facebook.com/tr\?id=(\d+)',
            ],
            'name': 'Facebook Pixel',
            'category': 'social_tracking'
        },
        'tiktok_pixel': {
            'patterns': [
                r'ttp\(["\']init["\'],\s*["\']([A-Z0-9]+)["\']',
                r'analytics.tiktok.com/i18n/pixel/events',
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

    def __init__(self):
        self.found_trackers = {}

    def extract_from_html(self, html_content: str, url: str = "") -> Dict[str, Any]:
        """Extract tracker IDs from HTML content"""
        results = {
            'source_url': url,
            'trackers_found': [],
            'total_trackers': 0,
            'categories': {}
        }

        for tracker_type, config in self.TRACKER_PATTERNS.items():
            tracker_results = self._find_tracker_patterns(html_content, tracker_type, config)
            if tracker_results:
                results['trackers_found'].extend(tracker_results)
                results['total_trackers'] += len(tracker_results)

                category = config['category']
                if category not in results['categories']:
                    results['categories'][category] = []
                results['categories'][category].extend([t['id'] for t in tracker_results])

        return results

    def extract_from_javascript(self, js_content: str, url: str = "") -> Dict[str, Any]:
        """Extract tracker IDs from JavaScript content"""
        return self.extract_from_html(js_content, url)

    def extract_from_network_logs(self, network_logs: List[Dict]) -> Dict[str, Any]:
        """Extract trackers from network request logs"""
        results = {
            'network_trackers': [],
            'third_party_domains': set(),
            'tracking_pixels': []
        }

        tracking_domains = {
            'google-analytics.com', 'googletagmanager.com', 'facebook.com',
            'connect.facebook.net', 'tiktok.com', 'analytics.tiktok.com',
            'hotjar.com', 'mixpanel.com', 'segment.com', 'matomo.org'
        }

        for log in network_logs:
            if isinstance(log, dict) and 'url' in log:
                parsed = urlparse(log['url'])
                domain = parsed.netloc.lower()

                # Check for known tracking domains
                if any(td in domain for td in tracking_domains):
                    results['network_trackers'].append({
                        'url': log['url'],
                        'domain': domain,
                        'method': log.get('method', 'GET'),
                        'status': log.get('status', 0)
                    })

                # Check for tracking pixels (1x1 images)
                if (parsed.path.endswith(('.gif', '.png', '.jpg')) and
                    'width' in log.get('query', '') and 'height' in log.get('query', '')):
                    results['tracking_pixels'].append(log['url'])

                # Collect third-party domains
                if domain and domain != urlparse(log.get('referer', '')).netloc:
                    results['third_party_domains'].add(domain)

        results['third_party_domains'] = list(results['third_party_domains'])
        return results

    def _find_tracker_patterns(self, content: str, tracker_type: str, config: Dict) -> List[Dict]:
        """Find tracker patterns in content"""
        found = []

        for pattern in config['patterns']:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                tracker_info = {
                    'type': tracker_type,
                    'name': config['name'],
                    'category': config['category'],
                    'id': match,
                    'pattern': pattern
                }
                found.append(tracker_info)

        return found

    def correlate_campaigns(self, current_trackers: Dict, known_campaigns: List[Dict]) -> Dict[str, Any]:
        """Correlate current trackers with known campaigns"""
        correlations = {
            'matches': [],
            'confidence': 0.0,
            'related_campaigns': []
        }

        current_ids = set()
        for tracker in current_trackers.get('trackers_found', []):
            current_ids.add(tracker['id'])

        for campaign in known_campaigns:
            campaign_ids = set(campaign.get('tracker_ids', []))
            overlap = current_ids.intersection(campaign_ids)

            if overlap:
                match_info = {
                    'campaign_id': campaign.get('id'),
                    'overlapping_ids': list(overlap),
                    'overlap_count': len(overlap),
                    'campaign_name': campaign.get('name', 'Unknown')
                }
                correlations['matches'].append(match_info)
                correlations['related_campaigns'].append(campaign['id'])

        if correlations['matches']:
            total_overlaps = sum(m['overlap_count'] for m in correlations['matches'])
            correlations['confidence'] = min(1.0, total_overlaps * 0.3)

        return correlations

def extract_trackers(html_content: str, js_content: str = "", network_logs: List = None,
                    source_url: str = "") -> Dict[str, Any]:
    """Convenience function to extract all tracker information"""
    extractor = TrackerExtractor()

    results = {
        'html_analysis': extractor.extract_from_html(html_content, source_url),
        'js_analysis': {},
        'network_analysis': {},
        'correlations': {},
        'summary': {}
    }

    if js_content:
        results['js_analysis'] = extractor.extract_from_javascript(js_content, source_url)

    if network_logs:
        results['network_analysis'] = extractor.extract_from_network_logs(network_logs)

    # Combine all trackers found
    all_trackers = []
    all_trackers.extend(results['html_analysis'].get('trackers_found', []))
    all_trackers.extend(results['js_analysis'].get('trackers_found', []))
    all_trackers.extend(results['network_analysis'].get('network_trackers', []))

    results['summary'] = {
        'total_trackers': len(all_trackers),
        'categories': {},
        'unique_domains': len(set(t.get('domain', '') for t in all_trackers if 'domain' in t))
    }

    # Count by category
    for tracker in all_trackers:
        category = tracker.get('category', 'unknown')
        if category not in results['summary']['categories']:
            results['summary']['categories'][category] = 0
        results['summary']['categories'][category] += 1

    return results