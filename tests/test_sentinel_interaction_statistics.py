"""Actual stored interaction readers: complete sources, literal labels, no identity."""
from contextlib import closing
import itertools
import json
from pathlib import Path
import sqlite3
import unittest

from paw.sentinel.database import CampaignDatabase
from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer
import test_sentinel_database_rows as rows


class SentinelInteractionStatistics(unittest.TestCase):
    setUp = rows.SentinelDatabaseRows.setUp
    tearDown = rows.SentinelDatabaseRows.tearDown
    database = rows.SentinelDatabaseRows.database

    def add(self, writer, label='potential_attacker', confidence=0.8, case='stored'):
        identifier = writer.add_victim_intelligence('192.0.2.1', 'Stored UA Ω',
            'https://example.invalid/', case_id=case)
        with writer.connection() as conn:
            conn.execute('UPDATE victim_intelligence SET interaction_type=?, interaction_confidence=? WHERE id=?',
                         (label, confidence, identifier))
        return identifier

    def assert_unverified(self, report):
        self.assertEqual(report['status'], 'success')
        self.assertEqual(report['evidence_scope'], 'stored_rows_unverified')
        self.assertIsNone(report['high_confidence_attacker_interactions'])
        self.assertIsNone(report['suspicious_interactions'])
        self.assertEqual(report['potential_attacker_ips'], [])
        self.assertEqual(set(report['unavailable']), {'high_confidence_attacker_interactions',
            'suspicious_interactions', 'potential_attacker_ips'})
        self.assertEqual(json.loads(json.dumps(report, allow_nan=False)), report)

    def test_complete_old_cases_literal_case_selection_and_source_order(self):
        writer = self.database()
        cases = ['older'] * 105 + ['', None, "case' OR 1=1 --"] + ['newer'] * 105
        with writer.connection() as conn:
            for index, case in enumerate(cases):
                conn.execute('INSERT INTO victim_intelligence (victim_ip,click_time,phishing_url,case_id,'
                    'interaction_type,interaction_confidence) VALUES (?,?,?,?,?,?)',
                    ('192.0.2.1', f'{index:04}', 'https://example.invalid/', case, 'potential_attacker', 0.8))
        analyzer = IntelligenceAnalyzer(writer.db_path, read_only=True)
        before = Path(writer.db_path).read_bytes()
        for case in (None, 'older', 'newer', '', "case' OR 1=1 --", 'OLDER', 'absent'):
            expected = [i + 1 for i, value in reversed(list(enumerate(cases))) if case is None or case == value]
            stats = analyzer.get_interaction_statistics(case)
            candidates = analyzer.get_potential_attacker_interactions(case)
            self.assertEqual([r['id'] for r in stats['source_records']], expected)
            self.assertEqual([r['id'] for r in candidates], expected)
            self.assertEqual([r['source_record'] for r in candidates], stats['source_records'])
            self.assertEqual(stats['total_interactions'], len(expected))
            self.assertEqual(stats['stored_candidate_score_at_least_0_7'], len(expected))
            self.assert_unverified(stats)
        self.assertEqual(Path(writer.db_path).read_bytes(), before)
        self.assertEqual({p.name for p in self.root.iterdir()}, {'fresh.db'})

    def test_null_unusable_and_unknown_labels_are_not_verified_classifications(self):
        writer = self.database()
        labels = [None, '', '  ', 'unknown', 'unknown ', 'attacker_test', 'automated_or_suspicious',
                  'suspicious_ip', 'custom label Ω', 3]
        for label in labels:
            self.add(writer, label, None)
        analyzer = IntelligenceAnalyzer(writer.db_path, read_only=True)
        report = analyzer.get_interaction_statistics()
        evidence = report['aggregation_evidence']
        # SQLite TEXT affinity converts supplied numeric label 3 into literal text.
        self.assertEqual(report['interaction_types'], {'3': 1, 'custom label Ω': 1,
            'suspicious_ip': 1, 'automated_or_suspicious': 1, 'attacker_test': 1, 'unknown ': 1, 'unknown': 1})
        self.assertEqual(evidence['interaction_types']['unusable_ids'], [3, 2, 1])
        self.assertEqual(evidence['classified_interactions']['counted_ids'], [10, 9, 8, 7, 6, 5])
        self.assertEqual(report['classified_interactions'], 6)
        self.assertEqual(report['stored_suspicious_label_rows'], 2)
        self.assertEqual(evidence['stored_suspicious_label_rows']['counted_ids'], [8, 7])
        self.assertEqual(report['stored_candidate_score_at_least_0_7'], 0)
        self.assertEqual(analyzer.get_potential_attacker_interactions(min_confidence=0), [])
        self.assert_unverified(report)

    def test_numeric_confidence_boundaries_sorting_and_candidate_label_gate(self):
        writer = self.database()
        for value in (None, 'bad', -1, 2, 0, 0.6, 0.7, 1, 0.7):
            self.add(writer, confidence=value)
        self.add(writer, label='custom', confidence=1)
        self.add(writer, label='suspicious_ip', confidence=0.65)
        analyzer = IntelligenceAnalyzer(writer.db_path, read_only=True)
        report = analyzer.get_interaction_statistics()
        self.assertEqual(report['aggregation_evidence']['stored_confidence']['unusable_ids'], [4, 3, 2, 1])
        self.assertEqual(report['aggregation_evidence']['stored_candidate_score_at_least_0_7']['counted_ids'], [9, 8, 7])
        self.assertEqual([r['id'] for r in analyzer.get_potential_attacker_interactions()], [8, 9, 7, 11, 6])
        self.assertEqual([r['id'] for r in analyzer.get_potential_attacker_interactions(min_confidence=0)], [8, 9, 7, 11, 6, 5])
        self.assertEqual([r['id'] for r in analyzer.get_potential_attacker_interactions(min_confidence=1)], [8])
        for invalid in (True, None, '0.6', -0.1, 1.1, float('nan'), float('inf'), 10**400):
            with self.assertRaises(ValueError):
                analyzer.get_potential_attacker_interactions(min_confidence=invalid)
        for invalid in (False, 0, [], {}):
            with self.assertRaises(TypeError):
                analyzer.get_interaction_statistics(invalid)
            with self.assertRaises(TypeError):
                analyzer.get_potential_attacker_interactions(invalid)

    def test_candidate_original_sources_and_malformed_json_survive_actual_json_output(self):
        writer = self.database()
        identifier = self.add(writer)
        with writer.connection() as conn:
            conn.execute("UPDATE victim_intelligence SET interaction_indicators='{broken', "
                "geolocation_data='null', metadata=CAST(X'80' AS TEXT), "
                "attacker_correlation='{\"operator\":\"unverified\"}', risk_score=9 WHERE id=?", (identifier,))
        analyzer = IntelligenceAnalyzer(writer.db_path, read_only=True)
        report = analyzer.get_interaction_statistics()
        candidates = analyzer.get_potential_attacker_interactions()
        source = analyzer.db.get_victim_intelligence(victim_id=identifier)[0]
        self.assertEqual(report['source_records'], [source])
        self.assertEqual(candidates[0]['source_record'], source)
        self.assertFalse(candidates[0]['verified'])
        self.assertEqual(candidates[0]['evidence_scope'], 'stored_label_candidates_unverified')
        self.assertTrue(candidates[0]['unavailable']['identity'])
        self.assertTrue(candidates[0]['unavailable']['risk'])
        self.assertEqual(source['json_evidence']['fields']['interaction_indicators']['status'], 'invalid_json')
        self.assertEqual(source['json_evidence']['fields']['metadata']['status'], 'invalid_encoding')
        destination = self.root / 'observations.json'
        destination.write_text(json.dumps({'stats': report, 'candidates': candidates}, ensure_ascii=True,
                                         allow_nan=False), encoding='utf-8')
        saved = json.loads(destination.read_text(encoding='utf-8'))
        self.assertEqual(saved['stats']['source_records'], [source])
        self.assertEqual(saved['candidates'][0]['source_record'], source)

    def test_legacy_partial_layouts_are_passive_without_invented_candidates(self):
        for index, fields in enumerate(fields for size in range(4)
                for fields in itertools.permutations(rows.INTERACTION_FIELDS, size)):
            path = self.root / f'legacy-{index}.db'
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.execute('CREATE TABLE victim_intelligence (' + ', '.join(
                    key + ' ' + sql for key, sql in rows.LEGACY_FIELDS + list(fields)) + ')')
                conn.execute('INSERT INTO victim_intelligence (victim_ip,click_time,phishing_url) VALUES (?,?,?)',
                             ('192.0.2.1', 'stored', 'https://example.invalid/'))
            before = path.read_bytes()
            analyzer = IntelligenceAnalyzer(str(path), read_only=True)
            stats = analyzer.get_interaction_statistics()
            self.assertEqual(stats['source_records'], analyzer.db.get_victim_intelligence(victim_id=1))
            self.assertEqual(stats['total_interactions'], 1)
            self.assertEqual(stats['classified_interactions'], 0)
            self.assertEqual(analyzer.get_potential_attacker_interactions(), [])
            self.assert_unverified(stats)
            self.assertEqual(path.read_bytes(), before)

    def test_unsupported_selected_native_values_fail_without_hiding_or_stringifying(self):
        writer = self.database()
        identifier = self.add(writer, case='bad')
        self.add(writer, case='good')
        analyzer = IntelligenceAnalyzer(writer.db_path, read_only=True)
        for field, value, error in (('victim_ua', b'\xff', TypeError), ('interaction_confidence', float('inf'), ValueError)):
            with writer.connection() as conn:
                conn.execute('UPDATE victim_intelligence SET victim_ua=?,interaction_confidence=0.8 WHERE id=?',
                             ('stored UA', identifier))
                conn.execute(f'UPDATE victim_intelligence SET {field}=? WHERE id=?', (value, identifier))
            before = Path(writer.db_path).read_bytes()
            for read in (analyzer.get_interaction_statistics, analyzer.get_potential_attacker_interactions):
                with self.assertRaises(error):
                    read('bad')
                with self.assertRaises(error):
                    read()
                read('good')  # Unrelated source errors cannot cross an exact-case boundary.
            self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_empty_storage_and_later_pending_journal_have_distinct_results(self):
        writer = self.database()
        analyzer = IntelligenceAnalyzer(writer.db_path, read_only=True)
        report = analyzer.get_interaction_statistics()
        self.assertEqual(report['source_records'], [])
        self.assertEqual(report['total_interactions'], 0)
        self.assert_unverified(report)
        self.assertEqual(analyzer.get_potential_attacker_interactions(), [])
        journal = Path(writer.db_path + '-journal')
        journal.write_bytes(b'original pending journal')
        for read in (analyzer.get_interaction_statistics, analyzer.get_potential_attacker_interactions):
            with self.assertRaises(ValueError):
                read()
        self.assertEqual(journal.read_bytes(), b'original pending journal')


if __name__ == '__main__':
    unittest.main()
