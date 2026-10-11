"""Supplied text/record contracts: no tracker execution or phishing labels."""
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from paw.core.trackers import TrackerExtractor, TrackerLimits, extract_trackers
from paw.core.attribution_matrix import AttributionMatrix
from paw.core.evidence import seal_case
from paw.core.verify import verify_case
from paw.core.exporter import export_case
from paw.core.runtime import atomic_json
from paw.core.network_policy import offline_policy, violations


def canonical(record):
    return json.dumps(record, ensure_ascii=True, sort_keys=True, allow_nan=False, separators=(',', ':')).encode()


class TrackerObservationContracts(unittest.TestCase):
    def extractor(self, **limits):
        return TrackerExtractor(limits=replace(TrackerLimits(), **limits))

    def test_all_existing_tracker_families_keep_patterns_and_identifier_candidates(self):
        text = ('UA-12345-1 G-ABCD GTM-ABCD fbq("init", "12345") '
                'facebook.com/tr?id=54321 ttp("init", "ABCD") '
                '_paq.push(["setSiteId", "17"] hj.hj("23" '
                'mixpanel.init("abc123" analytics.load("key456"')
        result = self.extractor().extract_from_javascript(text)
        observations = result['observations']
        self.assertEqual({r['tracker_type'] for r in observations}, set(TrackerExtractor.TRACKER_PATTERNS))
        self.assertTrue(all(r['identifier_candidate'] is not None for r in observations))
        self.assertTrue(all(r['verified'] is False for r in observations))
        for row in observations:
            span = row['span']; identifier = row['identifier_span']
            self.assertEqual(text[span['start']:span['end']], row['matched_text'])
            self.assertEqual(text[identifier['start']:identifier['end']], row['identifier_candidate'])

    def test_filename_and_domain_references_are_not_identifier_candidates(self):
        result = self.extractor().extract_from_html('matomo.js piwik.js hotjar.com analytics.tiktok.com/i18n/pixel/events')
        self.assertEqual(len(result['observations']), 4)
        self.assertTrue(all(r['identifier_candidate'] is None for r in result['observations']))
        self.assertTrue(all(r['identifier_span'] is None for r in result['observations']))
        self.assertEqual(result['trackers_found'], [])
        self.assertEqual(result['interpretation']['status'], 'unavailable')

    def test_literal_domain_dots_do_not_match_other_characters(self):
        result = self.extractor().extract_from_html('facebookXcom/tr?id=12345 analyticsXtiktokXcom/i18n/pixel/events')
        self.assertEqual(result['observations'], [])

    def test_repeat_offsets_hashes_and_unicode_originals_are_preserved(self):
        text = 'é UA-12345-1 \n UA-12345-1'
        result = self.extractor().extract_from_html(text)
        source, = result['sources']
        self.assertEqual(source['sha256'], hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(source['bytes'], len(text.encode()))
        self.assertEqual([r['span']['start'] for r in result['observations']], [2, 15])
        self.assertEqual(len(result['observations']), 2)
        self.assertIn('Unicode', source['hash_scope'])

    def test_html_comments_and_javascript_strings_are_only_lexical_occurrences(self):
        result = extract_trackers('<!-- UA-12345-1 -->', '"UA-12345-1"')
        self.assertEqual([s['kind'] for s in result['sources']], ['html', 'javascript'])
        self.assertEqual([r['source_index'] for r in result['observations']], [0, 1])
        self.assertTrue(all(r['interpretation_status'] == 'lexical_observation' for r in result['observations']))
        self.assertEqual(result['correlation_keys'], [])

    def test_invalid_text_types_and_unicode_do_not_raise_or_hash_a_substitute(self):
        for text in (None, b'UA-12345-1', {}, 1, '\ud800'):
            with self.subTest(text=repr(text)):
                result = self.extractor().extract_from_html(text)
                self.assertEqual(result['status'], 'partial')
                self.assertNotIn('sha256', result['sources'][0])
                self.assertEqual(result['observations'], [])

    def test_empty_sources_do_not_establish_absence_of_tracking(self):
        result = self.extractor().extract_from_html('')
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['sources'][0]['sha256'], hashlib.sha256(b'').hexdigest())
        self.assertFalse(result['verified'])
        self.assertEqual(result['interpretation']['status'], 'unavailable')

    def test_utf8_byte_limit_rejects_whole_text_without_prefix_hash(self):
        result = self.extractor(source_bytes=16).extract_from_html('é' * 9)
        self.assertEqual(result['coverage']['issues'], ['source_byte_limit'])
        self.assertNotIn('sha256', result['sources'][0])
        self.assertEqual(result['observations'], [])

    def test_bad_source_url_does_not_discard_admitted_text(self):
        for url in (1, '\ud800', 'x' * 4097):
            with self.subTest(url=repr(url[:10]) if isinstance(url, str) else url):
                result = self.extractor().extract_from_html('UA-12345-1', url)
                self.assertEqual(result['status'], 'partial')
                self.assertIsNone(result['sources'][0]['source_url'])
                self.assertEqual(len(result['observations']), 1)
                self.assertIn('sha256', result['sources'][0])

    def test_long_match_is_omitted_without_truncation_and_source_hash_survives(self):
        text = 'G-' + 'A' * 100 + ' UA-12345-1'
        result = self.extractor(value_chars=16).extract_from_html(text)
        self.assertEqual(result['coverage']['omitted_observation_count'], 1)
        self.assertEqual([r['identifier_candidate'] for r in result['observations']], ['UA-12345-1'])
        self.assertEqual(result['sources'][0]['sha256'], hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(result['status'], 'partial')

    def test_combined_sources_share_observation_budget(self):
        result = extract_trackers('UA-12345-1', 'UA-54321-1', [{'url': 'https://google-analytics.com/x'}], limits=TrackerLimits(observations=1))
        self.assertEqual(len(result['observations']), 1)
        self.assertEqual(result['coverage']['total_observation_count'], 4)
        self.assertEqual(result['coverage']['omitted_observation_count'], 3)
        self.assertEqual(result['status'], 'partial')

    def test_combined_sources_share_total_byte_budget(self):
        result = extract_trackers('UA-12345-1', 'UA-54321-1', [{'url': 'https://example.invalid/x'}], limits=TrackerLimits(total_bytes=10))
        self.assertEqual(result['coverage']['processed_bytes'], 10)
        self.assertEqual(len(result['observations']), 1)
        self.assertEqual([s['status'] for s in result['sources']], ['analyzed', 'not_analyzed', 'not_analyzed'])
        self.assertEqual(result['sources'][2]['reason'], 'total_byte_limit')

    def test_host_registry_matches_exact_hostname_or_delimited_subdomain(self):
        values = [('https://google-analytics.com/x', True), ('https://www.google-analytics.com:443/x', True),
                  ('https://google-analytics.com.evil.invalid/x', False), ('https://notgoogle-analytics.com/x', False),
                  ('https://google-analytics.com@evil.invalid/x', False), ('https://evil.invalid/?host=google-analytics.com', False)]
        for url, matches in values:
            with self.subTest(url=url):
                result = self.extractor().extract_from_network_logs([{'url': url}])
                hosts = [r for r in result['observations'] if r['context'] == 'hostname_registry_match']
                self.assertEqual(bool(hosts), matches)
                self.assertTrue(all(r['verified'] is False for r in hosts))
                self.assertEqual(result['network_trackers'], [])

    def test_terminal_root_dot_matches_all_registry_domains_with_original_provenance(self):
        before = len(violations())
        with offline_policy():
            for domain in TrackerExtractor.TRACKING_DOMAINS:
                for prefix in ('', 'www.'):
                    hostname = prefix + domain
                    record = {'url': 'https://' + hostname.upper() + '.:443/x', 'extra': {'keep': 'é'}}
                    with self.subTest(domain=domain, prefix=prefix):
                        result = self.extractor().extract_from_network_logs([record])
                        plain = self.extractor().extract_from_network_logs([{'url': 'https://' + hostname + '/x'}])
                        matches = [r for r in result['observations'] if r['context'] == 'hostname_registry_match']
                        self.assertEqual([r['registry_domain'] for r in matches],
                            [r['registry_domain'] for r in plain['observations'] if r['context'] == 'hostname_registry_match'])
                        self.assertTrue(matches)
                        self.assertTrue(all(r['value'] == hostname + '.' for r in matches))
                        self.assertTrue(all(r['comparison_hostname'] == hostname for r in matches))
                        self.assertTrue(all(r['verified'] is False for r in matches))
                        components = next(r for r in result['observations'] if r['context'] == 'url_components')
                        self.assertEqual(components['hostname'], hostname + '.')
                        self.assertEqual(components['value'], record['url'])
                        source, = result['sources']
                        self.assertEqual(source['supplied_record'], record)
                        self.assertEqual(source['sha256'], hashlib.sha256(canonical(record)).hexdigest())
                        self.assertEqual(source['bytes'], len(canonical(record)))
                        summary = AttributionMatrix().generate_attribution_matrix({'trackers': result})['evidence_summary']['enrichment_sources']['trackers']
                        self.assertEqual(summary['evidence_count'], len(result['observations']))
                        self.assertEqual(summary['observation_counts']['registry_patterns'],
                            sum(r['context'] in {'registry_pattern', 'hostname_registry_match'} for r in result['observations']))
                        self.assertEqual(summary['sources'][0]['sha256'], source['sha256'])
                        self.assertEqual(summary['confidence_level'], 'unavailable')
                        self.assertEqual(result['status'], 'completed')
        self.assertEqual(len(violations()), before)

    def test_root_dot_comparison_does_not_strip_multiple_dots_or_relax_host_boundaries(self):
        for domain in TrackerExtractor.TRACKING_DOMAINS:
            for url in ('https://' + domain + '../x', 'https://www.' + domain + '../x',
                        'https://' + domain + '.evil.invalid./x', 'https://not' + domain + './x',
                        'https://' + domain + '.@evil.invalid./x', 'https://evil.invalid./' + domain + '.',
                        'https://evil.invalid./?host=' + domain + '.'):
                with self.subTest(url=url):
                    record = {'url': url}
                    result = self.extractor().extract_from_network_logs([record])
                    # notanalytics.tiktok.com is still a literal subdomain of
                    # the separately registered parent tiktok.com.
                    expected = ['tiktok.com'] if url == 'https://notanalytics.tiktok.com./x' else []
                    self.assertEqual([r['registry_domain'] for r in result['observations']
                                      if r['context'] == 'hostname_registry_match'], expected)
                    self.assertEqual(result['sources'][0]['supplied_record'], record)
                    self.assertEqual(result['sources'][0]['sha256'], hashlib.sha256(canonical(record)).hexdigest())

    def test_registry_root_dot_comparison_keeps_referrer_hostname_equality_literal(self):
        record = {'url': 'https://google-analytics.com./x', 'referer': 'https://google-analytics.com/'}
        result = self.extractor().extract_from_network_logs([record])
        comparison, = [r for r in result['observations'] if r['context'] == 'literal_hostname_comparison']
        self.assertEqual(comparison['url_hostname'], 'google-analytics.com.')
        self.assertEqual(comparison['referer_hostname'], 'google-analytics.com')
        self.assertFalse(comparison['equal'])
        self.assertEqual(result['third_party_domains'], [])

    def test_malformed_and_unsupported_urls_preserve_admitted_records(self):
        for url in ('https://[bad/x', 'https://example.invalid:wrong/x', 'javascript:x',
                    '/relative', '\thttps://example.invalid/x', 'https://evil.invalid\\@google-analytics.com/x', None, 123):
            with self.subTest(url=url):
                log = {'url': url}
                result = self.extractor().extract_from_network_logs([log])
                self.assertEqual(result['status'], 'partial')
                source, = result['sources']
                self.assertEqual(source['supplied_record'], log)
                self.assertEqual(source['sha256'], hashlib.sha256(canonical(log)).hexdigest())
                self.assertEqual(source['url_interpretation']['status'], 'not_interpreted')

    def test_missing_fields_do_not_become_get_zero_or_third_party(self):
        for log in ({'url': 'https://google-analytics.com/x'}, {'ts': 1, 'type': 'request'}):
            with self.subTest(log=log):
                result = self.extractor().extract_from_network_logs([log])
                record = result['sources'][0]['supplied_record']
                self.assertNotIn('method', record)
                self.assertNotIn('status', record)
                self.assertEqual(result['third_party_domains'], [])
                self.assertEqual(result['tracking_pixels'], [])

    def test_collector_request_and_response_shapes_retain_all_supplied_metadata(self):
        logs = [{'ts': 1.5, 'type': 'request', 'method': 'POST', 'url': 'https://example.invalid/x', 'headers': {'Referer': 'https://origin.invalid/', 'X-Extra': 'keep'}},
                {'ts': 2.5, 'type': 'response', 'status': 403, 'url': 'https://example.invalid/x', 'content_type': 'application/json'}]
        original = copy.deepcopy(logs)
        result = self.extractor().extract_from_network_logs(logs)
        self.assertEqual([s['supplied_record'] for s in result['sources']], original)
        self.assertEqual(logs, original)
        self.assertNotIn('status', result['sources'][0]['supplied_record'])
        self.assertNotIn('method', result['sources'][1]['supplied_record'])
        self.assertFalse(any(r['context'] == 'literal_hostname_comparison' for r in result['observations']))

    def test_canonical_record_hash_is_complete_and_output_copy_is_independent(self):
        log = {'url': 'https://example.invalid/x', 'extra': ['é', -0.0, True, None, {'keep': 4}]}
        original = copy.deepcopy(log)
        result = self.extractor().extract_from_network_logs([log])
        source, = result['sources']
        self.assertEqual(source['sha256'], hashlib.sha256(canonical(original)).hexdigest())
        self.assertEqual(source['bytes'], len(canonical(original)))
        log['extra'][-1]['keep'] = 5
        self.assertEqual(source['supplied_record'], original)
        source['supplied_record']['extra'].append('output mutation')
        self.assertEqual(len(log['extra']), len(original['extra']))

    def test_unrelated_long_metadata_does_not_trigger_observation_value_limit(self):
        log = {'url': 'https://google-analytics.com/x', 'headers': {'X-Note': 'x' * 5000}}
        result = self.extractor().extract_from_network_logs([log])
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['sources'][0]['supplied_record'], log)
        self.assertEqual(result['sources'][0]['sha256'], hashlib.sha256(canonical(log)).hexdigest())
        self.assertTrue(any(r['context'] == 'hostname_registry_match' for r in result['observations']))

    def test_referrer_hostname_equality_is_not_origin_or_third_party_attribution(self):
        for referer, same in [('https://example.invalid/', True), ('https://example.invalid:8443/', True), ('https://other.invalid/', False)]:
            with self.subTest(referer=referer):
                result = self.extractor().extract_from_network_logs([{'url': 'https://example.invalid/x', 'referer': referer}])
                comparisons = [r for r in result['observations'] if r['context'] == 'literal_hostname_comparison']
                self.assertEqual(comparisons[0]['equal'], same)
                self.assertFalse(comparisons[0]['verified'])
                self.assertEqual(result['third_party_domains'], [])

    def test_invalid_referrer_keeps_url_observations_and_complete_record(self):
        log = {'url': 'https://example.invalid/x', 'referer': 'https://[bad'}
        result = self.extractor().extract_from_network_logs([log])
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['sources'][0]['supplied_record'], log)
        self.assertTrue(any(r['context'] == 'url_components' for r in result['observations']))

    def test_image_path_and_dimension_strings_do_not_verify_a_tracking_pixel(self):
        log = {'url': 'https://example.invalid/p.png?width=500&height=400', 'query': 'width=500&height=400'}
        result = self.extractor().extract_from_network_logs([log])
        self.assertEqual(result['tracking_pixels'], [])
        image, = [r for r in result['observations'] if r['context'] == 'image_path_extension']
        self.assertEqual(image['value'], '/p.png')
        self.assertFalse(image['verified'])
        self.assertEqual(result['sources'][0]['supplied_record'], log)

    def test_entry_budget_admits_prefix_with_explicit_omissions(self):
        logs = [{'url': f'https://example.invalid/{i}'} for i in range(4)]
        result = self.extractor(network_entries=2).extract_from_network_logs(logs)
        self.assertEqual(result['coverage']['total_log_count'], 4)
        self.assertEqual(result['coverage']['omitted_log_count'], 2)
        self.assertEqual([s['input_index'] for s in result['sources']], [0, 1])
        self.assertEqual(result['status'], 'partial')

    def test_invalid_log_list_and_records_are_partial_without_raising(self):
        for logs in (None, {}, 'url', [None], ['url'], [1]):
            with self.subTest(logs=logs):
                result = self.extractor().extract_from_network_logs(logs)
                self.assertEqual(result['status'], 'partial')
                self.assertEqual(result['observations'], [])
                self.assertTrue(all('sha256' not in s for s in result['sources']))

    def test_json_depth_cycles_and_shared_node_budget_are_bounded(self):
        nested = {'url': 'https://example.invalid/x', 'extra': [[[[1]]]]}
        result = self.extractor(json_depth=2).extract_from_network_logs([nested])
        self.assertEqual(result['sources'][0]['reason'], 'json_depth_limit')
        cycle = []; cycle.append(cycle)
        result = self.extractor().extract_from_network_logs([{'url': 'https://example.invalid/x', 'extra': cycle}])
        self.assertEqual(result['sources'][0]['reason'], 'json_depth_limit')
        logs = [{'url': 'https://example.invalid/x'}] * 2
        result = self.extractor(json_nodes=5).extract_from_network_logs(logs)
        self.assertEqual(result['sources'][0]['status'], 'analyzed')
        self.assertEqual(result['sources'][1]['reason'], 'json_node_limit')

    def test_nonfinite_and_unsupported_json_values_are_not_serialized_or_hashed(self):
        for value in (float('nan'), float('inf'), float('-inf'), b'bytes', {1, 2}, (1, 2), object(), '\ud800'):
            with self.subTest(value=repr(value)):
                result = self.extractor().extract_from_network_logs([{'url': 'https://example.invalid/x', 'extra': value}])
                self.assertEqual(result['status'], 'partial')
                self.assertNotIn('sha256', result['sources'][0])
                json.dumps(result, allow_nan=False)
        result = self.extractor().extract_from_network_logs([{'url': 'https://example.invalid/x', 3: 'key'}])
        self.assertEqual(result['sources'][0]['reason'], 'nonstring_json_key')

    def test_large_integers_have_named_limit_and_finite_values_are_preserved(self):
        result = self.extractor(integer_bits=8).extract_from_network_logs([{'url': 'https://example.invalid/x', 'extra': 256}])
        self.assertEqual(result['sources'][0]['reason'], 'integer_bit_limit')
        log = {'url': 'https://example.invalid/x', 'extra': [1, -2, -0.0, 1.5, 1e300, True, None]}
        result = self.extractor().extract_from_network_logs([log])
        self.assertEqual(result['sources'][0]['supplied_record'], log)
        self.assertEqual(result['status'], 'completed')

    def test_canonical_ascii_byte_limit_matches_exact_record_boundary(self):
        log = {'url': 'https://example.invalid/x', 'note': 'é'}
        size = len(canonical(log))
        result = self.extractor(source_bytes=size).extract_from_network_logs([log])
        self.assertEqual(result['sources'][0]['bytes'], size)
        result = self.extractor(source_bytes=size - 1).extract_from_network_logs([log])
        self.assertEqual(result['sources'][0]['reason'], 'source_byte_limit')
        self.assertNotIn('sha256', result['sources'][0])

    def test_total_byte_rejection_preserves_earlier_source_without_hashing_prefix(self):
        first = {'url': 'https://example.invalid/x'}
        result = self.extractor(total_bytes=len(canonical(first))).extract_from_network_logs([first, {'url': 'https://example.invalid/y', 'extra': 'x' * 5000}])
        self.assertEqual(result['sources'][0]['supplied_record'], first)
        self.assertEqual(result['sources'][1]['reason'], 'total_byte_limit')
        self.assertNotIn('supplied_record', result['sources'][1])
        self.assertNotIn('sha256', result['sources'][1])

    def test_long_url_retains_record_hash_and_bounded_patterns_without_truncating_target(self):
        log = {'url': 'https://example.invalid/' + 'x' * 5000 + '?id=UA-12345-1'}
        result = self.extractor(value_chars=64).extract_from_network_logs([log])
        self.assertEqual(result['sources'][0]['supplied_record'], log)
        self.assertEqual(result['sources'][0]['sha256'], hashlib.sha256(canonical(log)).hexdigest())
        self.assertEqual(result['sources'][0]['url_interpretation']['reason'], 'url_value_limit')
        self.assertFalse(any(r['context'] == 'url_components' for r in result['observations']))
        self.assertEqual(result['observations'][0]['identifier_candidate'], 'UA-12345-1')

    def test_limits_reject_nonpositive_noninteger_and_invalid_limits_object(self):
        for name in TrackerLimits.__dataclass_fields__:
            for value in (0, -1, True, 1.5, float('nan'), float('inf')):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    replace(TrackerLimits(), **{name: value})
        with self.assertRaises(ValueError): TrackerExtractor(limits=False)

    def test_campaign_string_resemblance_has_no_validated_confidence(self):
        extractor = self.extractor()
        result = extractor.extract_from_html('matomo.js UA-12345-1')
        known = [{'id': 'unrelated', 'tracker_ids': ['matomo.js', 'UA-12345-1']}]
        original = copy.deepcopy((result, known))
        correlation = extractor.correlate_campaigns(result, known)
        self.assertEqual(correlation['status'], 'unavailable')
        self.assertIsNone(correlation['confidence'])
        self.assertEqual(correlation['matches'], [])
        self.assertEqual((result, known), original)

    def test_actual_matrix_preserves_observation_count_provenance_and_unavailable_confidence(self):
        for text, limits in [('', {}), ('UA-12345-1 ' * 15, {}), ('UA-12345-1 ' * 15, {'observations': 1}), ('x' * 20, {'source_bytes': 10})]:
            with self.subTest(limits=limits):
                result = self.extractor(**limits).extract_from_html(text)
                original = copy.deepcopy(result)
                matrix = AttributionMatrix().generate_attribution_matrix({'trackers': result})
                summary = matrix['evidence_summary']['enrichment_sources']['trackers']
                self.assertEqual(summary['evidence_count'], len(result['observations']))
                self.assertEqual(summary['confidence_level'], 'unavailable')
                self.assertEqual(summary['source_status'], result['status'])
                self.assertEqual(summary['coverage'], result['coverage'])
                self.assertEqual(summary['sources'][0]['sha256'], result['sources'][0].get('sha256'))
                self.assertEqual(summary['sources'][0]['reason'], result['sources'][0].get('reason'))
                self.assertEqual(summary['evidence_types'], ['unverified_tracker_pattern'] if result['observations'] else [])
                self.assertEqual(matrix['hypotheses'], [])
                self.assertEqual(matrix['operator_attribution']['status'], 'unavailable')
                self.assertEqual(result, original)

    def test_matrix_preserves_complete_coverage_for_each_tracker_omission_and_failure(self):
        before = len(violations())
        with offline_policy():
            cases = [
                ('observation_count_limit', self.extractor(observations=1).extract_from_html('UA-12345-1 ' * 15)),
                ('observation_value_limit', self.extractor(value_chars=8).extract_from_html('UA-12345-1')),
                ('network_entry_limit', self.extractor(network_entries=1).extract_from_network_logs([{'url': 'https://example.invalid/x'}] * 5)),
                ('source_byte_limit', self.extractor(source_bytes=4).extract_from_html('UA-12345-1')),
                ('total_byte_limit', extract_trackers('UA-12345-1', 'UA-54321-1', limits=TrackerLimits(total_bytes=10))),
                ('json_node_limit', self.extractor(json_nodes=1).extract_from_network_logs([{'url': 'https://example.invalid/x'}])),
                ('json_depth_limit', self.extractor(json_depth=1).extract_from_network_logs([{'extra': [1]}])),
                ('invalid_source_type', self.extractor().extract_from_html(None)),
                ('invalid_log_record_type', self.extractor().extract_from_network_logs([None])),
                ('invalid_url_type', self.extractor().extract_from_network_logs([{'url': None}]))]
            for reason, result in cases:
                with self.subTest(reason=reason):
                    original = copy.deepcopy(result)
                    matrix = AttributionMatrix().generate_attribution_matrix({'trackers': result})
                    summary = matrix['evidence_summary']['enrichment_sources']['trackers']
                    self.assertEqual(summary['coverage'], result['coverage'])
                    self.assertIn(reason, summary['coverage']['issues'])
                    self.assertEqual(summary['source_status'], 'partial')
                    self.assertEqual(summary['evidence_count'], len(result['observations']))
                    self.assertEqual(summary['confidence_level'], 'unavailable')
                    if reason == 'observation_count_limit':
                        self.assertEqual(summary['coverage']['total_observation_count'], 15)
                        self.assertEqual(summary['coverage']['omitted_observation_count'], 14)
                    if reason == 'network_entry_limit':
                        self.assertEqual(summary['coverage']['total_log_count'], 5)
                        self.assertEqual(summary['coverage']['omitted_log_count'], 4)
                    summary['coverage']['issues'].append('output mutation')
                    summary['coverage']['processed_bytes'] = -1
                    self.assertEqual(result, original)
                    result['coverage']['issues'].append('input mutation')
                    self.assertNotIn('input mutation', summary['coverage']['issues'])
            missing = self.extractor().extract_from_html('')
            missing.pop('coverage')
            summary = AttributionMatrix().generate_attribution_matrix({'trackers': missing})['evidence_summary']['enrichment_sources']['trackers']
            self.assertIsNone(summary['coverage'])
        self.assertEqual(len(violations()), before)

    def test_plain_log_url_is_not_summarized_as_a_tracker_pattern(self):
        result = self.extractor().extract_from_network_logs([{'url': 'https://example.invalid/x'}])
        matrix = AttributionMatrix().generate_attribution_matrix({'trackers': result})
        summary = matrix['evidence_summary']['enrichment_sources']['trackers']
        self.assertEqual(summary['evidence_types'], ['supplied_log_literal'])
        self.assertEqual(summary['observation_counts'], {'registry_patterns': 0, 'log_literals': 1})
        self.assertEqual(summary['confidence_level'], 'unavailable')
        self.assertEqual(summary['coverage'], result['coverage'])

    def test_canonical_log_hash_and_results_do_not_depend_on_dictionary_order(self):
        a = {'url': 'https://example.invalid/x', 'metadata': {'b': 2, 'a': 'é'}}
        b = {'metadata': {'a': 'é', 'b': 2}, 'url': 'https://example.invalid/x'}
        self.assertEqual(self.extractor().extract_from_network_logs([a]), self.extractor().extract_from_network_logs([b]))

    def test_actual_static_sources_matrix_artifacts_seal_and_zip_no_egress(self):
        html, js = '<!-- UA-12345-1 --><script src="matomo.js"></script>', '"mixpanel.init(\"key123\""'
        logs = [{'ts': 1.5, 'type': 'request', 'url': 'https://google-analytics.com.evil.invalid/p.png?width=500&height=400', 'headers': {'X-Note': 'preserve'}}]
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory) / 'case-static-tracker-fixture'; case.mkdir()
            (case / 'supplied.html').write_bytes(html.encode())
            (case / 'supplied.js').write_bytes(js.encode())
            raw_logs = canonical(logs)
            (case / 'supplied-logs.json').write_bytes(raw_logs)
            before = len(violations())
            with offline_policy():
                result = extract_trackers((case / 'supplied.html').read_text(encoding='utf-8'),
                    (case / 'supplied.js').read_text(encoding='utf-8'), json.loads(raw_logs),
                    limits=TrackerLimits(observations=1))
                matrix = AttributionMatrix().generate_attribution_matrix({'trackers': result})
                summary = matrix['evidence_summary']['enrichment_sources']['trackers']
                self.assertEqual(summary['coverage'], result['coverage'])
                self.assertGreater(summary['coverage']['omitted_observation_count'], 0)
                self.assertEqual(summary['source_status'], 'partial')
                atomic_json(case / 'enrichment_trackers.json', result)
                atomic_json(case / 'attribution_matrix.json', matrix)
                self.assertEqual(result['sources'][2]['sha256'], hashlib.sha256(canonical(logs[0])).hexdigest())
                self.assertEqual(result['network_trackers'], [])
                self.assertEqual(result['tracking_pixels'], [])
                self.assertFalse(list(case.glob('*.tmp')))
                seal_case(case)
                self.assertTrue(verify_case(case))
                with zipfile.ZipFile(export_case(case, 'zip')) as archive:
                    self.assertEqual(archive.read(case.name + '/supplied.html'), html.encode())
                    self.assertEqual(archive.read(case.name + '/supplied.js'), js.encode())
                    self.assertEqual(archive.read(case.name + '/supplied-logs.json'), raw_logs)
                    self.assertEqual(json.loads(archive.read(case.name + '/enrichment_trackers.json')), result)
                    self.assertEqual(json.loads(archive.read(case.name + '/attribution_matrix.json')), matrix)
            self.assertEqual(len(violations()), before)


if __name__ == '__main__':
    unittest.main()
