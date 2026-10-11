"""Passive Received descriptions; no validated header-forgery assessment."""
from typing import Dict, Any
from .ip_observations import classify_ip
from .received_timing import observe_received_timing

def analyze_received_anomalies(hops: list, reference_time=None) -> dict:
    """Describe supplied normalized Received hops without verifying their claims."""
    anomalies = {
        "non_monotonic_dates": None,
        "private_ip_before_boundary": None,
        "invalid_fqdn_count": 0,
        "impossible_negative_skew": None,
        "ip_fqdn_mismatch": None,
        "suspicious_relay_chain": None,
        "missing_auth_headers": None,
        "timestamp_manipulation": None,
        "spoofing_patterns": [],
        "auth_failures": [],
        "verified": False,
        "forgery_assessment": {
            "status": "unavailable", "verified": False,
            "reason": "Received claims do not establish forgery, IP/hostname binding or independently verified authentication failures"
        }
    }
    anomalies['receiver_boundary'] = {'status':'not_evaluated','verified':False,
        'reason':'Recipient trust boundary not independently established; provider names are heuristic'}
    anomalies['ip_observations'] = [{'header_index':hop.get('header_index'),
        'ip':hop['ip'],'category':classify_ip(hop['ip'])['category'],
        'source':'Received header claim','verified':False} for hop in hops if hop.get('ip')]
    timing = observe_received_timing(hops,reference_time)
    anomalies['timing_observations'] = timing
    if any(pair['result']=='backward' for pair in timing['adjacent_pairs']):
        anomalies['non_monotonic_dates'] = True
    elif timing['comparison_status']=='completed':
        anomalies['non_monotonic_dates'] = False

    if not hops:
        anomalies.update(status='not_evaluated', reason='No Received headers')
        return anomalies

    # Address categories and provider-name roles cannot establish a trusted
    # receiver boundary. Keep syntax counts descriptive, never infer malice.
    for hop in hops:
        if hop.get("fqdn_ok") is False:
            anomalies["invalid_fqdn_count"] += 1

    anomalies.update(status='heuristic_observations', verified=False)
    return anomalies


def received_score_components(anomalies):
    """Header timestamp, hostname and address claims are descriptive only."""
    return {'received_non_monotonic_dates': 0.0,
            'received_private_ip_before_boundary': 0.0,
            'received_invalid_fqdn': 0.0}

def analyze_header_forgery_indicators(email_headers: Dict[str, Any]) -> Dict[str, Any]:
    """Compatibility entry point: no validated aggregate forgery contract exists.

    This function does not interpret its input. The active pipeline retains
    Received descriptions through analyze_received_anomalies instead.
    """
    return {
        "status": "unavailable",
        "verified": False,
        "forgery_score": None,
        "indicators": [],
        "confidence": None,
        "reason": "No validated aggregate header-forgery assessment; use Received descriptions and separate authentication evidence"
    }
