"""Static supplied-HTML contracts, not execution or independent phishing labels."""
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from paw.core.form_analysis import FormAnalyzer, FormLimits, analyze_html_forms
from paw.core.attribution_matrix import AttributionMatrix
from paw.core.evidence import seal_case
from paw.core.exporter import export_case
from paw.core.verify import verify_case
from paw.core.runtime import atomic_json
from paw.core.network_policy import offline_policy, violations


PAGE = 'https://example.invalid/dir/index.html?old=1'


class FormObservationContracts(unittest.TestCase):
    def analyze(self, html, url=PAGE, **limits):
        return FormAnalyzer(limits=replace(FormLimits(), **limits)).analyze_forms(html, url)

    def test_source_hash_positions_and_duplicate_attributes_preserved(self):
        html = '\n<form ACTION="first" action="second"><input name="email" name="amount"></form>'
        result = self.analyze(html)
        self.assertEqual(result['source']['sha256'], hashlib.sha256(html.encode()).hexdigest())
        self.assertEqual(result['source']['bytes'], len(html.encode()))
        form, = result['forms']
        self.assertEqual((form['line'], form['column'], form['tag_index']), (2, 0, 1))
        self.assertEqual([a['value'] for a in form['attributes']], ['first', 'second'])
        self.assertEqual(form['action_declaration']['status'], 'not_interpreted_duplicate_attributes')
        self.assertIsNone(form['action_resolution']['candidate'])
        self.assertEqual([a['value'] for a in form['inputs'][0]['attributes']], ['email', 'amount'])

    def test_relative_query_fragment_protocol_and_absolute_candidates(self):
        expected = {'next.php': 'https://example.invalid/dir/next.php',
                    '?next=1': 'https://example.invalid/dir/index.html?next=1',
                    '#submit': PAGE + '#submit', '//other.invalid/pay': 'https://other.invalid/pay',
                    'https://other.invalid/pay': 'https://other.invalid/pay',
                    '': PAGE}
        for literal, candidate in expected.items():
            with self.subTest(literal=literal):
                form, = self.analyze(f'<form action="{literal}"></form>')['forms']
                self.assertEqual(form['action'], literal)
                self.assertEqual(form['action_resolution']['candidate'], candidate)
                self.assertFalse(form['action_resolution']['verified'])

    def test_missing_and_bare_actions_and_methods_do_not_become_defaults(self):
        for attributes, status in [('', 'not_declared'), ('action method', 'declared')]:
            form, = self.analyze(f'<form {attributes}></form>')['forms']
            self.assertEqual(form['action_declaration']['status'], status)
            self.assertIsNone(form['action'])
            self.assertIsNone(form['method'])
            self.assertIsNone(form['action_resolution']['candidate'])

    def test_method_and_entities_remain_declared_markup(self):
        form, = self.analyze('<form method="PoSt" action="pay?a=1&amp;b=2"></form>')['forms']
        self.assertEqual(form['method'], 'PoSt')
        self.assertEqual(form['action'], 'pay?a=1&b=2')
        self.assertEqual(form['action_resolution']['candidate'], 'https://example.invalid/dir/pay?a=1&b=2')

    def test_first_href_bearing_base_is_candidate_and_all_bases_retained(self):
        result = self.analyze('<base target="x"><base href="/new/"><base href="https://other.invalid/"><form action="pay"></form>')
        self.assertEqual(len(result['base_observations']), 3)
        self.assertEqual([b['selected_candidate_context'] for b in result['base_observations']], [False, True, False])
        self.assertEqual(result['forms'][0]['action_resolution']['candidate'], 'https://example.invalid/new/pay')
        self.assertEqual(result['resolution_context']['selected_base_tag_index'], 2)

    def test_ambiguous_or_invalid_base_does_not_fall_back_to_page(self):
        for attrs in ('href="/one/" href="/two/"', 'href="javascript:noop()"', 'href'):
            with self.subTest(attrs=attrs):
                result = self.analyze(f'<base {attrs}><base href="/valid/"><form action="pay"></form>')
                self.assertIsNone(result['forms'][0]['action_resolution']['candidate'])
                self.assertFalse(result['base_observations'][1]['selected_candidate_context'])

    def test_empty_base_uses_supplied_document_candidate(self):
        result = self.analyze('<base href=""><form action="pay"></form>')
        self.assertEqual(result['forms'][0]['action_resolution']['candidate'], 'https://example.invalid/dir/pay')

    def test_unsupported_and_malformed_actions_have_no_target_candidate(self):
        for literal in ('javascript:alert(1)', 'data:text/html,x', 'https://[invalid/pay',
                        'https://example.invalid:wrong/pay', '\tpay', 'space here'):
            with self.subTest(literal=literal):
                form, = self.analyze(f'<form action="{literal}"></form>')['forms']
                self.assertEqual(form['action'], literal)
                self.assertIsNone(form['action_resolution']['candidate'])

    def test_invalid_page_context_cannot_resolve_relative_actions(self):
        for url in (None, 'not a URL', 'https://[bad', 'https://example.invalid/\tpath', 123, '\ud800'):
            with self.subTest(url=repr(url)):
                result = self.analyze('<form action="pay"></form><form action="https://other.invalid/pay"></form>', url)
                self.assertIsNone(result['forms'][0]['action_resolution']['candidate'])
                self.assertEqual(result['forms'][1]['action_resolution']['candidate'], 'https://other.invalid/pay')
                json.dumps(result, allow_nan=False)

    def test_long_page_url_is_not_truncated_into_resolution_context(self):
        result = self.analyze('<form action="pay"></form>', PAGE + 'x' * 100, value_chars=64)
        self.assertEqual(result['status'], 'partial')
        self.assertIsNone(result['url'])
        self.assertIsNone(result['forms'][0]['action_resolution']['candidate'])

    def test_joined_candidate_has_own_bound_without_reinterpreting_original(self):
        result = self.analyze('<form action="' + 'p' * 40 + '"></form>', 'https://example.invalid/' + 'd' * 30 + '/', value_chars=64)
        self.assertEqual(result['forms'][0]['action'], 'p' * 40)
        self.assertEqual(result['forms'][0]['action_resolution']['status'], 'limited_candidate')
        self.assertEqual(result['status'], 'partial')

    def test_field_patterns_preserve_all_categories_as_unverified(self):
        result = self.analyze('<form><input name="email_amount" id="card_number" placeholder="cvv"></form>')
        control = result['forms'][0]['inputs'][0]
        self.assertEqual({c['category'] for c in control['field_type_candidates']}, {'email', 'amount', 'credit_card', 'cvv'})
        self.assertTrue(all(c['verified'] is False for c in control['field_type_candidates']))
        self.assertEqual(result['forms'][0]['field_types'], {})
        self.assertEqual(result['attribution_hints']['merchant_category'], 'unknown')
        self.assertEqual(result['attribution_hints']['risk_indicators'], [])

    def test_processor_literal_hostname_does_not_match_lookalike(self):
        for src, expected in [('https://js.stripe.com/sdk.js', 1),
                              ('//js.stripe.com/sdk.js', 1),
                              ('https://js.stripe.com.evil.invalid/sdk.js', 0),
                              ('https://js.stripe.com@evil.invalid/sdk.js', 0),
                              ('https://evil.invalid/?host=js.stripe.com', 0)]:
            with self.subTest(src=src):
                result = self.analyze(f'<script src="{src}"></script>')
                host = [r for r in result['processor_observations'] if r['context'] == 'script_hostname_literal']
                self.assertEqual(len(host), expected)
                self.assertEqual(result['script_observations'][0]['attributes'][0]['value'], src)
                self.assertEqual(result['payment_processors'], [])
                self.assertEqual(result['attribution_hints']['payment_ecosystem'], 'unknown')
                self.assertTrue(all(r['verified'] is False for r in result['processor_observations']))

    def test_duplicate_script_sources_are_preserved_and_not_selected(self):
        result = self.analyze('<script src="https://js.stripe.com/x" src="https://evil.invalid/y"></script>')
        script, = result['script_observations']
        self.assertEqual(len(script['attributes']), 2)
        self.assertEqual(script['src_declaration']['status'], 'not_interpreted_duplicate_attributes')
        self.assertFalse(any(r['context'] == 'script_hostname_literal' for r in result['processor_observations']))

    def test_text_tokens_keep_every_occurrence_without_behavior_claims(self):
        html = '<!-- stripe stripe --><script>"stripe"</script><form name="Stripe"></form>'
        result = self.analyze(html)
        rows = [r for r in result['processor_observations'] if r.get('token') == 'stripe']
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertEqual(html[row['offset']:row['offset'] + len(row['matched_text'])], row['matched_text'])
        self.assertEqual(result['correlation_keys'], [])
        self.assertEqual(result['suspicious_patterns'], [])

    def test_inert_markup_and_templates_do_not_produce_form_occurrences(self):
        html = ('<!-- <form></form> --><script>"<form></form>"</script>'
                '<style><form></form></style><title><form></form></title>'
                '<template><template><form></form></template></template>'
                '<form><textarea><form></form><input name="password"></textarea></form>')
        result = self.analyze(html)
        self.assertEqual(len(result['forms']), 1)
        self.assertEqual([c['tag'] for c in result['forms'][0]['inputs']], ['textarea'])
        self.assertEqual(result['status'], 'completed')

    def test_control_inventory_keeps_external_ownership_unresolved(self):
        result = self.analyze('<input form="f" name="email"><form id="f"><select name="a"></select><button name="b"></button></form>')
        self.assertEqual(len(result['unassigned_controls']), 1)
        self.assertIsNone(result['unassigned_controls'][0]['form_index'])
        self.assertEqual([c['tag'] for c in result['forms'][0]['inputs']], ['select', 'button'])
        self.assertIn('not browser form ownership', result['scope'])

    def test_nested_forms_have_only_literal_scope_association(self):
        result = self.analyze('<form><input name="outer"><form><input name="inner"></form><input name="outer2"></form>')
        self.assertEqual([len(f['inputs']) for f in result['forms']], [2, 1])
        self.assertEqual(result['forms'][1]['inputs'][0]['form_index'], 1)

    def test_unterminated_lexical_scopes_are_partial(self):
        for html, reason in [('<form><input name="x">', 'unterminated_lexical_scope'),
                             ('<script>stripe', 'unterminated_lexical_scope'),
                             ('<template>', 'unterminated_lexical_scope')]:
            with self.subTest(html=html):
                result = self.analyze(html)
                self.assertEqual(result['status'], 'partial')
                self.assertIn(reason, result['coverage']['issues'])
                self.assertEqual(result['source']['sha256'], hashlib.sha256(html.encode()).hexdigest())

    def test_empty_is_an_observation_not_safe_and_invalid_inputs_are_partial(self):
        result = self.analyze('')
        self.assertEqual(result['status'], 'completed')
        self.assertFalse(result['verified'])
        self.assertEqual(result['attribution_hints']['status'], 'unavailable')
        for html in (None, b'html', 3, '\ud800'):
            with self.subTest(html=repr(html)):
                result = self.analyze(html)
                self.assertEqual(result['status'], 'partial')
                self.assertNotIn('sha256', result['source'])

    def test_html_bound_is_utf8_bytes_without_prefix_analysis(self):
        result = self.analyze('é' * 10, html_bytes=15)
        self.assertEqual(result['coverage']['issues'], ['html_byte_limit'])
        self.assertEqual(result['forms'], [])
        self.assertNotIn('sha256', result['source'])

    def test_form_and_control_budgets_are_global_with_omission_counts(self):
        result = self.analyze('<form><input><input><input></form><form><input></form>', forms=1, controls=2)
        self.assertEqual(result['coverage']['total_form_count'], 2)
        self.assertEqual(result['coverage']['omitted_form_count'], 1)
        self.assertEqual(result['coverage']['total_control_count'], 4)
        self.assertEqual(result['coverage']['omitted_control_count'], 2)
        self.assertEqual(len(result['forms'][0]['inputs']), 2)

    def test_attribute_budget_prevents_any_declaration_from_partial_node(self):
        result = self.analyze('<form action="pay" method="post"><input name="email"></form>', attributes=1)
        self.assertEqual(result['coverage']['total_attribute_count'], 3)
        self.assertEqual(result['coverage']['omitted_attribute_count'], 2)
        self.assertEqual(result['forms'][0]['action_declaration']['status'], 'not_interpreted_limited_attributes')
        self.assertIsNone(result['forms'][0]['action_resolution']['candidate'])

    def test_limited_values_keep_hashes_but_cannot_create_hints_or_targets(self):
        value = 'email' * 10
        result = self.analyze(f'<form action="{value}"><input name="{value}"></form>', value_chars=8)
        self.assertEqual(result['coverage']['limited_value_count'], 2)
        attribute = result['forms'][0]['attributes'][0]
        self.assertEqual(attribute['value_preview'], value[:8])
        self.assertEqual(attribute['value_sha256'], hashlib.sha256(value.encode()).hexdigest())
        self.assertIsNone(result['forms'][0]['action'])
        self.assertEqual(result['forms'][0]['inputs'][0]['field_type_candidates'], [])

    def test_context_budget_covers_attribute_free_bases_and_scripts(self):
        result = self.analyze('<script></script><base><base href="/other/"><form action="pay"></form>', context_nodes=2)
        self.assertEqual(result['coverage']['total_context_node_count'], 3)
        self.assertEqual(result['coverage']['omitted_context_node_count'], 1)
        self.assertEqual(len(result['base_observations']), 1)
        self.assertEqual(len(result['script_observations']), 1)
        self.assertIsNone(result['forms'][0]['action_resolution']['candidate'])
        result = self.analyze('<base>' * 1000, context_nodes=2)
        self.assertEqual(len(result['base_observations']), 2)
        self.assertEqual(result['coverage']['omitted_context_node_count'], 998)

    def test_observation_budget_is_shared_across_fields_and_processor_tokens(self):
        result = self.analyze('<form><input name="email_amount"></form> stripe stripe', observations=1)
        retained = sum(len(c['field_type_candidates']) for f in result['forms'] for c in f['inputs'])
        retained += len(result['processor_observations'])
        self.assertEqual(retained, 1)
        self.assertEqual(result['coverage']['total_observation_count'], retained + result['coverage']['omitted_observation_count'])
        self.assertEqual(result['status'], 'partial')

    def test_limits_reject_nonpositive_noninteger_or_invalid_options(self):
        for key in FormLimits.__dataclass_fields__:
            for value in (0, -1, True, 1.5, float('nan'), float('inf')):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    replace(FormLimits(), **{key: value})
        with self.assertRaises(ValueError): FormAnalyzer(limits=False)

    def test_cross_page_resemblance_has_no_validated_correlation_contract(self):
        result = self.analyze('<form><input name="email"></form><form><input name="email"></form>')
        before = copy.deepcopy(result)
        correlation = FormAnalyzer().correlate_forms_across_pages([result, result])
        self.assertEqual(correlation['status'], 'unavailable')
        self.assertEqual(correlation['common_field_patterns'], {})
        self.assertEqual(correlation['form_similarity_clusters'], [])
        self.assertEqual(result, before)

    def test_actual_matrix_preserves_unverified_source_status_without_confidence(self):
        for forms, limits in [(15, {}), (15, {'forms': 1})]:
            with self.subTest(limits=limits):
                result = self.analyze('<form><input name="email"></form> stripe' * forms, **limits)
                before = copy.deepcopy(result)
                matrix = AttributionMatrix().generate_attribution_matrix({'url': PAGE, 'form_analysis': result})
                summary = matrix['evidence_summary']['enrichment_sources']['form_analysis']
                self.assertEqual(summary['source_status'], result['status'])
                self.assertEqual(summary['source_sha256'], result['source']['sha256'])
                self.assertEqual(summary['confidence_level'], 'unavailable')
                self.assertNotIn('payment_processor', summary['evidence_types'])
                self.assertEqual(matrix['operator_attribution']['status'], 'unavailable')
                self.assertEqual(matrix['hypotheses'], [])
                self.assertEqual(matrix['correlation_matrix']['source_correlations'], {})
                self.assertEqual(matrix['correlation_matrix']['cross_source_links'], [])
                self.assertEqual(matrix['correlation_matrix']['key_frequency'], {})
                self.assertEqual(result, before)

    def test_empty_matrix_source_has_no_observed_evidence_types(self):
        matrix = AttributionMatrix().generate_attribution_matrix({'form_analysis': self.analyze('')})
        summary = matrix['evidence_summary']['enrichment_sources']['form_analysis']
        self.assertEqual(summary['evidence_count'], 0)
        self.assertEqual(summary['evidence_types'], [])
        self.assertEqual(summary['confidence_level'], 'unavailable')

    def test_actual_static_artifacts_matrix_seal_and_zip_with_no_egress(self):
        html = '<form action="next.php"><input name="email_amount"></form><script src="https://js.stripe.com.evil.invalid/sdk.js"></script>'
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory) / 'case-static-form-fixture'
            case.mkdir()
            capture = case / 'supplied.html'
            capture.write_bytes(html.encode())
            blocked = len(violations())
            with offline_policy():
                result = analyze_html_forms(capture.read_text(encoding='utf-8'), PAGE)
                matrix = AttributionMatrix().generate_attribution_matrix({'url': PAGE, 'form_analysis': result})
                atomic_json(case / 'enrichment_forms.json', result)
                atomic_json(case / 'attribution_matrix.json', matrix)
                self.assertFalse(list(case.glob('*.tmp')))
                seal_case(case)
                self.assertTrue(verify_case(case))
                with zipfile.ZipFile(export_case(case, 'zip')) as archive:
                    self.assertEqual(archive.read(case.name + '/supplied.html'), html.encode())
                    self.assertEqual(json.loads(archive.read(case.name + '/enrichment_forms.json')), result)
                    self.assertEqual(json.loads(archive.read(case.name + '/attribution_matrix.json')), matrix)
            self.assertEqual(len(violations()), blocked)


if __name__ == '__main__':
    unittest.main()
