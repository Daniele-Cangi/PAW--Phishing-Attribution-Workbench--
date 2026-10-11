"""Actual passive Received descriptions must not manufacture forgery findings."""
import ast
import copy
import inspect
import unittest

from paw.core import header_forgery
from paw.core.header_forgery import (
    analyze_header_forgery_indicators, analyze_received_anomalies,
    received_score_components)
from paw.core.network_policy import offline_policy, violations
from paw.core.parser_mail import parse_eml_bytes
from paw.core.received import normalize_received


REFERENCE = '2026-10-11T12:00:00+00:00'


class HeaderForgeryContracts(unittest.TestCase):
    def assert_unavailable(self, result):
        self.assertFalse(result['verified'])
        self.assertEqual(result['forgery_assessment']['status'], 'unavailable')
        self.assertFalse(result['forgery_assessment']['verified'])
        for field in ('ip_fqdn_mismatch', 'missing_auth_headers',
                      'private_ip_before_boundary', 'impossible_negative_skew',
                      'suspicious_relay_chain', 'timestamp_manipulation'):
            self.assertIsNone(result[field])
        self.assertEqual(result['auth_failures'], [])
        self.assertEqual(result['spoofing_patterns'], [])

    def test_empty_chain_has_no_false_verification_or_forgery_result(self):
        result = analyze_received_anomalies([], reference_time=REFERENCE)
        self.assertEqual(result['status'], 'not_evaluated')
        self.assertIsNone(result['non_monotonic_dates'])
        self.assertEqual(result['timing_observations']['status'], 'unavailable')
        self.assert_unavailable(result)

    def test_authentication_words_and_claims_do_not_become_verified_failures(self):
        for value in ('fail', 'none', 'softfail', 'this is not a failure',
                      'none of these are results', 'pass'):
            with self.subTest(value=value):
                hops = [{'header_index': 0, 'spf_note': value, 'DKIM': value,
                         'dmarc_claim': value, 'date': '2025-10-08T10:00:00+00:00'}]
                original = copy.deepcopy(hops)
                result = analyze_received_anomalies(hops, reference_time=REFERENCE)
                self.assert_unavailable(result)
                self.assertEqual(hops, original)

    def test_auth_like_metadata_is_not_stringified_or_interpreted(self):
        class Uninterpretable:
            def __str__(self):
                raise AssertionError('Metadata must not be stringified as an auth result')
        value = Uninterpretable()
        result = analyze_received_anomalies([{'spf_extra': value}], reference_time=REFERENCE)
        self.assert_unavailable(result)

    def test_claimed_mapping_is_unavailable_for_ipv4_ipv6_and_host_syntax(self):
        before = len(violations())
        with offline_policy():
            for ip, fqdn in [('192.0.2.1', 'example.invalid'),
                             ('2001:db8::1', 'example.invalid'),
                             ('127.0.0.1', 'localhost'),
                             ('::1', 'host with invalid syntax')]:
                with self.subTest(ip=ip, fqdn=fqdn):
                    hops = [{'header_index': 0, 'ip': ip, 'fqdn': fqdn}]
                    original = copy.deepcopy(hops)
                    result = analyze_received_anomalies(hops, reference_time=REFERENCE)
                    self.assert_unavailable(result)
                    self.assertEqual(result['ip_observations'][0]['ip'], ip)
                    self.assertFalse(result['ip_observations'][0]['verified'])
                    self.assertEqual(hops, original)
        self.assertEqual(len(violations()), before)

    def test_backward_and_syntax_descriptions_are_retained_without_forgery_score(self):
        hops = [{'header_index': 2, 'date': '2025-10-08T10:00:00+00:00', 'fqdn_ok': False},
                {'header_index': 1, 'date': '2025-10-08T09:00:00+00:00', 'fqdn_ok': False},
                {'header_index': 0, 'fqdn_ok': False}]
        result = analyze_received_anomalies(hops, reference_time=REFERENCE)
        self.assertTrue(result['non_monotonic_dates'])
        self.assertEqual(result['invalid_fqdn_count'], 3)
        self.assertEqual(result['timing_observations']['adjacent_pairs'][0]['delta_seconds'], -3600)
        self.assert_unavailable(result)
        aggregate = analyze_header_forgery_indicators({'received': hops})
        self.assertIsNone(aggregate['forgery_score'])
        self.assertIsNone(aggregate['confidence'])
        self.assertEqual(aggregate['indicators'], [])

    def test_legacy_aggregate_never_interprets_raw_normalized_or_missing_input(self):
        inputs = [{}, {'received': []}, {'received': ['from a.example by b.example']},
                  {'received': [{'date': '2025-10-08T10:00:00+00:00', 'spf': 'fail'}]},
                  {'received': None}, None]
        for supplied in inputs:
            with self.subTest(supplied=supplied):
                original = copy.deepcopy(supplied)
                result = analyze_header_forgery_indicators(supplied)
                self.assertEqual(result['status'], 'unavailable')
                self.assertFalse(result['verified'])
                self.assertIsNone(result['forgery_score'])
                self.assertIsNone(result['confidence'])
                self.assertEqual(result['indicators'], [])
                self.assertEqual(supplied, original)

    def test_original_header_claims_and_normalized_sources_remain_available(self):
        raw = (b'From: a@example.invalid\r\n'
               b'Authentication-Results: receiver.invalid; spf=fail; dkim=none; dmarc=fail\r\n'
               b'Received: from a.example (192.0.2.1) by mx.example; Wed, 8 Oct 2025 09:00:00 +0000\r\n'
               b'Received: from a.example (192.0.2.1) by mx.example; Wed, 8 Oct 2025 10:00:00 +0000\r\n'
               b'\r\nOriginal body\r\n')
        before = len(violations())
        with offline_policy():
            headers = parse_eml_bytes(raw)
            normalized = normalize_received(headers['received'])
            original = copy.deepcopy((headers, normalized))
            result = analyze_received_anomalies(normalized['ordered_hops'], reference_time=REFERENCE)
        self.assertEqual((headers, normalized), original)
        self.assertEqual([hop['raw'] for hop in normalized['ordered_hops']], list(reversed(headers['received'])))
        self.assertEqual([hop['header_index'] for hop in normalized['ordered_hops']], [1, 0])
        self.assertEqual([m['result'] for m in headers['authentication_results'][0]['methods']], ['fail', 'none', 'fail'])
        self.assertTrue(result['non_monotonic_dates'])
        self.assert_unavailable(result)
        self.assertEqual(len(violations()), before)

    def test_descriptive_received_components_remain_zero_for_all_supported_claims(self):
        for hops in ([], [{'fqdn_ok': False}], [{'ip': '127.0.0.1', 'spf': 'fail'}]):
            result = analyze_received_anomalies(hops, reference_time=REFERENCE)
            self.assertEqual(received_score_components(result), {
                'received_non_monotonic_dates': 0.0,
                'received_private_ip_before_boundary': 0.0,
                'received_invalid_fqdn': 0.0})

    def test_header_helper_has_no_dns_or_network_permission_path(self):
        tree = ast.parse(inspect.getsource(header_forgery))
        imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        imports += [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
        self.assertFalse({'socket', 'network_policy', 'requests', 'urllib', 'http'} & set(imports))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, {'gethostbyname_ex', 'gethostbyaddr', 'getaddrinfo', 'connect'})
            if isinstance(node, ast.Name):
                self.assertNotIn(node.id, {'network_allowed', 'socket'})


if __name__ == '__main__':
    unittest.main()
