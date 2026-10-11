"""Static source contracts, not labels for real phishing or active collection."""
import ast
import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

from paw.core import trace
from paw.core.kit_static import KitLimits, analyze_captured_kit, analyze_phishing_kit_content, publish_captured_kit_inventory
from paw.core.evidence import seal_case
from paw.core.exporter import export_case
from paw.core.verify import verify_case
from paw.core.network_policy import offline_policy, violations


HTML = '<form action="https://example.invalid/login"><input name="password"></form>'
JS = 'fetch("https://example.invalid/data");'
CSS = 'a {background:url("https://example.invalid/image")} '


class KitStaticTests(unittest.TestCase):
    def test_all_scalar_list_producer_shapes_retain_identical_observations(self):
        for kind, value in [('html', HTML), ('javascript', JS), ('css', CSS)]:
            with self.subTest(kind=kind):
                scalar = trace.analyze_phishing_kit_content({kind: value})
                listed = trace.analyze_phishing_kit_content({kind: [value]})
                self.assertEqual(scalar, listed)
                self.assertTrue(scalar['observations'])
                self.assertEqual(scalar['sources'][0]['text_utf8_sha256'], hashlib.sha256(value.encode()).hexdigest())

    def test_empty_and_literal_keywords_do_not_fabricate_behavior_or_risk(self):
        for content in ({}, {'html': ''}, {'javascript': 'eval("emotet password")'},
                        {'files': [{'filename': 'steal.php'}], 'html_analysis': {'content': 'invoice'}}):
            result = trace.analyze_phishing_kit_content(content)
            self.assertEqual(result['risk_level'], 'unavailable')
            for field in ('c2_servers', 'callback_domains', 'exfiltration_endpoints', 'suspicious_patterns', 'obfuscated_code'):
                self.assertEqual(result[field], [])
            self.assertEqual(result['patterns']['attacker_fingerprint'], {})
            self.assertEqual(result['patterns']['malware_family'], 'unknown')
            self.assertEqual(result['patterns']['similar_campaigns'], [])
            self.assertEqual(trace.assess_kit_risk(result), 'unavailable')

    def test_all_legacy_adapters_share_actual_observation_contract(self):
        for call, content in [(trace.analyze_html_for_c2, HTML),
                              (trace.analyze_javascript_for_c2, JS),
                              (trace.analyze_css_for_c2, CSS)]:
            self.assertTrue(call([content])['observations'])
            self.assertEqual(call(content), call([content]))
        root = Path(trace.__file__).parent
        for path in (root/'trace.py', root/'kit_static.py'):
            names = [n.name for n in ast.parse(path.read_text(encoding='utf-8')).body if isinstance(n, ast.FunctionDef)]
            self.assertEqual(len(names), len(set(names)))

    def test_source_occurrences_are_not_merged_or_mutated(self):
        contents = {'html': [HTML, HTML], 'javascript': [JS]}
        before = copy.deepcopy(contents)
        result = analyze_phishing_kit_content(contents)
        self.assertEqual(contents, before)
        self.assertEqual([s['input_index'] for s in result['sources']], [0, 1, 0])
        self.assertEqual([s['kind'] for s in result['sources']], ['html', 'html', 'javascript'])
        targets = [r for r in result['observations'] if r['value'] == 'https://example.invalid/login']
        self.assertEqual([r['source_index'] for r in targets], [0, 1])

    def test_malformed_inputs_and_missing_items_do_not_erase_valid_siblings(self):
        result = analyze_phishing_kit_content({'html': [None, HTML, {}, b'HTML', '\ud800'], 'javascript': JS})
        self.assertEqual(result['status'], 'partial')
        self.assertEqual([s['status'] for s in result['sources']], ['not_analyzed', 'analyzed', 'not_analyzed', 'not_analyzed', 'not_analyzed', 'analyzed'])
        self.assertIn('invalid_unicode', result['coverage']['issues'])
        self.assertEqual({r['source_index'] for r in result['observations']}, {1, 5})
        self.assertEqual(analyze_phishing_kit_content(None)['coverage']['issues'], ['invalid_kit_type'])
        self.assertIn('unsupported_content_keys', analyze_phishing_kit_content({'other': 'data'})['coverage']['issues'])

    def test_common_host_names_and_query_keywords_are_retained_without_verdicts(self):
        values = ['https://google.example.invalid/cdn', 'https://example.invalid/exec', 'https://example.invalid/exfil']
        result = analyze_phishing_kit_content({'javascript': ';'.join('fetch("'+v+'")' for v in values)})
        self.assertEqual([r['value'] for r in result['observations'] if r['context'] == 'javascript_url_literal'], values)
        self.assertTrue(all(r['interpretation_status'] == 'not_verified' for r in result['observations']))

    def test_html_parser_preserves_attribute_occurrences_and_relative_targets(self):
        html = '<form action="/login?x=1&amp;y=2" action="other"><iframe src="//example.invalid/f"></iframe></form>'
        result = analyze_phishing_kit_content({'html': html})
        attrs = [r for r in result['observations'] if r['context'] == 'html_attribute']
        self.assertEqual([r['value'] for r in attrs], ['/login?x=1&y=2', 'other', '//example.invalid/f'])
        self.assertEqual([r['attribute_index'] for r in attrs], [0, 1, 0])
        self.assertEqual(attrs[0]['line'], 1)

    def test_html_inline_script_and_comment_have_distinct_locations(self):
        value = '<!-- https://comment.invalid/a -->\n<script>atob("data"); fetch("https://script.invalid/a");</script>'
        rows = analyze_phishing_kit_content({'html': value})['observations']
        self.assertEqual({r['context'] for r in rows}, {'html_comment_url', 'inline_script_url_literal', 'inline_script_lexical_marker'})
        script = next(r for r in rows if r['context'] == 'inline_script_url_literal')
        self.assertEqual(script['line'], 2)
        self.assertEqual(script['offset_scope'], 'parser data segment')

    def test_comments_and_strings_with_markers_remain_lexical_not_execution(self):
        rows = analyze_phishing_kit_content({'javascript': '// eval(\n"atob("; "\\x41";'})['observations']
        self.assertEqual([r['value'] for r in rows], ['eval(', 'atob(', '\\x'])
        self.assertTrue(all('comments and strings' in r['representation'] for r in rows))

    def test_unterminated_script_keeps_literal_observations_and_partial_status(self):
        result = analyze_phishing_kit_content({'html': '<script>'+JS})
        self.assertEqual(result['status'], 'partial')
        self.assertIn('unterminated_inline_script', result['coverage']['issues'])
        self.assertEqual([r['value'] for r in result['observations']], ['https://example.invalid/data'])

    def test_css_all_literal_arguments_and_whitespace_remain_observations(self):
        content = 'a{a:url( /local );b:URL( "data:image/png;base64,abc" );c:url(https://remote.invalid/x)}'
        rows = analyze_phishing_kit_content({'css': content})['observations']
        self.assertEqual([r['value'] for r in rows], ['/local', 'data:image/png;base64,abc', 'https://remote.invalid/x'])

    def test_source_count_limit_is_shared_across_content_types(self):
        result = analyze_phishing_kit_content({'html': [HTML]*2, 'javascript': [JS]*3, 'css': CSS}, limits=replace(KitLimits(), sources=3))
        self.assertEqual(len(result['sources']), 3)
        self.assertEqual(result['coverage']['omitted_source_count'], 3)
        self.assertEqual(result['status'], 'partial')

    def test_multibyte_and_total_byte_limits_do_not_analyze_partial_source(self):
        result = analyze_phishing_kit_content({'javascript': ['é'*6, JS, JS]}, limits=replace(KitLimits(), source_bytes=len(JS.encode()), total_bytes=len(JS.encode())+12))
        self.assertEqual([s['status'] for s in result['sources']], ['analyzed', 'analyzed', 'not_analyzed'])
        self.assertEqual(result['sources'][2]['reason'], 'total_byte_limit')
        oversized = analyze_phishing_kit_content({'html': 'é'*6}, limits=replace(KitLimits(), source_bytes=10))
        self.assertEqual(oversized['sources'][0]['reason'], 'source_byte_limit')
        self.assertNotIn('text_utf8_sha256', oversized['sources'][0])
        self.assertEqual(oversized['observations'], [])

    def test_observation_and_value_limits_count_exact_omissions(self):
        result = analyze_phishing_kit_content({'javascript': JS*5}, limits=replace(KitLimits(), observations=2))
        self.assertEqual(len(result['observations']), 2)
        self.assertEqual(result['coverage']['total_observation_count'], 5)
        self.assertEqual(result['coverage']['omitted_observation_count'], 3)
        result = analyze_phishing_kit_content({'javascript': JS}, limits=replace(KitLimits(), value_chars=5))
        self.assertEqual(result['coverage']['omitted_observation_count'], 1)
        self.assertEqual(result['observations'], [])

    def test_limits_reject_nonfinite_boolean_negative_or_zero_budgets(self):
        for value in (0, -1, True, 1.5, float('inf')):
            with self.assertRaises(ValueError):
                KitLimits(sources=value)

    def test_captured_files_have_complete_raw_and_derived_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'sub').mkdir()
            samples = {'sub/page.HTML': HTML.encode()+b'\xff', 'script.JS': JS.encode(), 'style.css': CSS.encode()}
            for name, raw in samples.items():
                (root/name).write_bytes(raw)
            (root/'ignore.bin').write_bytes(b'never a supported source')
            before = len(violations())
            with offline_policy():
                result = analyze_captured_kit(root)
            self.assertEqual(len(violations()), before)
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(len(result['sources']), 3)
            for source in result['sources']:
                raw = samples[source['path']]
                self.assertEqual(source['captured_sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(source['text_utf8_sha256'], hashlib.sha256(raw.decode('utf-8', errors='replace').encode()).hexdigest())
                self.assertEqual(source['decoding_lossy'], source['path'] == 'sub/page.HTML')
                self.assertEqual((root/source['path']).read_bytes(), raw)

    def test_capture_oversized_sources_and_source_limits_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'a.html').write_text('x'*100)
            (root/'b.js').write_text(JS)
            (root/'c.css').write_text(CSS)
            result = analyze_captured_kit(root, limits=replace(KitLimits(), source_bytes=50, sources=2))
            self.assertEqual(result['sources'][0]['reason'], 'source_byte_limit')
            self.assertNotIn('captured_sha256', result['sources'][0])
            self.assertEqual(result['sources'][1]['status'], 'analyzed')
            self.assertEqual(result['coverage']['omitted_source_count'], 1)
            self.assertEqual(result['status'], 'partial')

    def test_complete_raw_provenance_survives_all_derived_text_admission_limits(self):
        for kind in ('html', 'js', 'css'):
            for raw, maximum in ((b'\xff', 1), (b'\xff'*2, 2), (b'\xff'+b'a'*3, 4)):
                with self.subTest(kind=kind, raw=raw), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory); (root/('bad.'+kind)).write_bytes(raw)
                    result = analyze_captured_kit(root, limits=replace(KitLimits(), source_bytes=maximum))
                    source = result['sources'][0]
                    self.assertEqual(source['status'], 'not_analyzed')
                    self.assertEqual(source['reason'], 'source_byte_limit')
                    self.assertEqual(source['captured_sha256'], hashlib.sha256(raw).hexdigest())
                    self.assertEqual(source['captured_bytes'], len(raw))
                    self.assertTrue(source['decoding_lossy'])
                    self.assertNotIn('text_utf8_sha256', source)
                    self.assertEqual(result['observations'], [])
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root/('a.'+kind)).write_bytes(b'a')
                (root/('b.'+kind)).write_bytes(b'b')
                result = analyze_captured_kit(root, limits=replace(KitLimits(), total_bytes=1))
                source = result['sources'][1]
                self.assertEqual(source['reason'], 'total_byte_limit')
                self.assertEqual(source['captured_sha256'], hashlib.sha256(b'b').hexdigest())
                self.assertEqual(source['captured_bytes'], 1)
                self.assertFalse(source['decoding_lossy'])

    def test_captured_publication_is_independent_of_network_metadata(self):
        for summary in (None, {}, {'endpoints': []}, {'endpoints': None}, '{broken'):
            with self.subTest(summary=summary), tempfile.TemporaryDirectory() as directory:
                case = Path(directory); captures = case/'detonation'/'runs'; captures.mkdir(parents=True)
                (captures/'page.html').write_bytes(HTML.encode())
                if summary is not None:
                    (case/'detonation'/'summary.json').write_text(summary if isinstance(summary, str) else json.dumps(summary))
                with offline_policy():
                    result = publish_captured_kit_inventory(case)
                self.assertTrue(result['observations'])
                self.assertTrue((case/'phishing_kit_analysis.json').is_file())
                stored = json.loads((case/'campaign_origin.json').read_text())
                self.assertEqual(stored['static_observations']['captured_kit']['path'], 'phishing_kit_analysis.json')
        # Bind this actual consumer to trace's source control flow without
        # substituting a fake active run for the deferred collection capability.
        tree = ast.parse(Path(trace.__file__).read_text(encoding='utf-8'))
        guards = []; offsets = []
        def walk(node, conditions):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'publish_captured_kit_inventory':
                guards.append(conditions); offsets.append(node.lineno)
            inner = conditions + [ast.unparse(node.test)] if isinstance(node, ast.If) else conditions
            for child in ast.iter_child_nodes(node): walk(child, inner)
        walk(tree, [])
        self.assertEqual(len(guards), 1)
        self.assertTrue(any('not no_egress' in condition for condition in guards[0]))
        self.assertFalse(any('endpoints' in condition or 'det_sum' in condition for condition in guards[0]))
        summary_reads = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call)
                         and isinstance(node.func, ast.Name) and node.func.id == 'read_json'
                         and any(isinstance(arg, ast.Name) and arg.id == 'det_sum' for arg in node.args)]
        self.assertTrue(summary_reads and offsets[0] < min(summary_reads))

    def test_capture_directory_depth_entries_and_missing_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'a').mkdir(); (root/'a'/'b').mkdir(); (root/'a'/'b'/'c.html').write_text(HTML)
            self.assertIn('directory_depth_limit', analyze_captured_kit(root, limits=replace(KitLimits(), directory_depth=1))['coverage']['issues'])
            (root/'a.js').write_text(JS); (root/'b.js').write_text(JS)
            self.assertIn('directory_entry_limit', analyze_captured_kit(root, limits=replace(KitLimits(), directory_entries=2))['coverage']['issues'])
            self.assertEqual(analyze_captured_kit(root/'missing')['coverage']['issues'], ['unavailable_capture_directory'])

    def test_actual_static_consumer_preserves_sources_campaign_metadata_and_zip_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)/'case-static-fixture'
            captures = case/'detonation'/'runs'; captures.mkdir(parents=True)
            (captures/'page.html').write_bytes(HTML.encode())
            campaign = {'attribution_confidence': 'unavailable', 'other_observations': ['keep'],
                        'static_observations': {'existing': {'value': 'keep'}}}
            (case/'campaign_origin.json').write_text(json.dumps(campaign), encoding='utf-8')
            before = len(violations())
            with offline_policy():
                result = publish_captured_kit_inventory(case)
                stored = json.loads((case/'campaign_origin.json').read_text())
                self.assertEqual(stored['static_observations']['captured_kit']['observation_count'], len(result['observations']))
                self.assertFalse(stored['static_observations']['captured_kit']['verified'])
                self.assertNotIn('infrastructure_chain', stored)
                for key, value in campaign.items():
                    if key == 'static_observations': self.assertEqual(stored[key]['existing'], value['existing'])
                    else: self.assertEqual(stored[key], value)
                self.assertEqual(json.loads((case/'phishing_kit_analysis.json').read_text()), result)
                self.assertFalse(list(case.glob('*.tmp')))
                seal_case(case)
                self.assertTrue(verify_case(case))
                with zipfile.ZipFile(export_case(case, 'zip')) as archive:
                    self.assertEqual(archive.read(case.name+'/detonation/runs/page.html'), HTML.encode())
                    self.assertEqual(json.loads(archive.read(case.name+'/phishing_kit_analysis.json')), result)
            self.assertEqual(len(violations()), before)

    def test_consumer_rejects_malformed_campaign_without_replacing_original(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            captures = case/'detonation'/'runs'; captures.mkdir(parents=True)
            (captures/'page.html').write_bytes(HTML.encode())
            path = case/'campaign_origin.json'
            inventory = case/'phishing_kit_analysis.json'; prior = b'{"prior":"preserve"}'
            for existing in (False, True):
                for raw in (b'{"static_observations": "invalid"}', b'{"static_observations": null}',
                            b'{"static_observations": []}', b'[]', b'false', b'true', b'0', b'""', b'null', b'{broken'):
                    path.write_bytes(raw)
                    if existing: inventory.write_bytes(prior)
                    else: inventory.unlink(missing_ok=True)
                    with self.assertRaises(ValueError): publish_captured_kit_inventory(case)
                    self.assertEqual(path.read_bytes(), raw)
                    if existing: self.assertEqual(inventory.read_bytes(), prior)
                    else: self.assertFalse(inventory.exists())
                    self.assertFalse(list(case.glob('*.tmp')))

    @unittest.skipUnless(os.name == 'posix', 'POSIX FIFO and symlink semantics')
    def test_capture_does_not_follow_symlinks_or_read_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'original.html').write_text(HTML)
            (root/'linked.html').symlink_to(root/'original.html')
            os.mkfifo(root/'pipe.js')
            result = analyze_captured_kit(root)
            self.assertIn('symlink_or_reparse_skipped', result['coverage']['issues'])
            self.assertEqual([s['path'] for s in result['sources']], ['original.html', 'pipe.js'])
            self.assertEqual(result['sources'][1]['reason'], 'not_regular_file')


if __name__ == '__main__':
    unittest.main()
