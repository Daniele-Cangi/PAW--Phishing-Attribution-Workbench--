"""Stored report inventories and unverified interpretations on actual SQLite."""
from contextlib import closing
import itertools
import json
from pathlib import Path
import sqlite3
import unittest

from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer
import test_sentinel_database_rows as source_rows


class SentinelIntelligenceReport(unittest.TestCase):
    setUp = source_rows.SentinelDatabaseRows.setUp
    tearDown = source_rows.SentinelDatabaseRows.tearDown
    database = source_rows.SentinelDatabaseRows.database
    populated_row = source_rows.SentinelDatabaseRows.populated_row

    def seed(self):
        writer = self.database()
        identifier = self.populated_row(writer)
        return writer, identifier, IntelligenceAnalyzer(writer.db_path, read_only=True)

    def assert_unverified(self, report):
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['status'], 'success')
        self.assertEqual(report['evidence_scope'], 'stored_rows_unverified')
        self.assertEqual(report['attacker_infrastructure'], [])
        self.assertEqual(report['recommendations'], [])
        self.assertIsNone(report['summary']['high_risk_victims'])
        self.assertIsNone(report['summary']['recent_victims_24h'])
        self.assertEqual(set(report['unavailable']), {'high_risk_victims',
            'recent_victims_24h', 'attacker_infrastructure', 'recommendations'})
        self.assertTrue(all(report['unavailable'].values()))
        self.assertEqual(json.loads(json.dumps(report, allow_nan=False)), report)

    def test_old_case_inventory_is_complete_and_never_contains_other_case_infrastructure(self):
        writer = self.database()
        with writer.connection() as conn:
            for index in range(212):
                conn.execute('INSERT INTO victim_intelligence '
                    '(victim_ip, click_time, phishing_url, case_id, analyzed_status, '
                    'risk_score, geolocation_data, attacker_correlation) VALUES (?,?,?,?,?,?,?,?)',
                    ('198.51.100.2', f'{index:04}', 'https://example.invalid/stored',
                    'older-case' if index < 106 else 'other-case', 'analyzed', 8,
                    '{"country":"Older"}' if index < 106 else '{"country":"Other"}',
                    '{"claimed_operator":"stored label"}'))
        analyzer = IntelligenceAnalyzer(writer.db_path, read_only=True)
        before = Path(writer.db_path).read_bytes()
        for case, expected_ids, expected_countries in (
                ('older-case', list(range(106, 0, -1)), {'Older': 106}),
                ('other-case', list(range(212, 106, -1)), {'Other': 106}),
                (None, list(range(212, 0, -1)), {'Other': 106, 'Older': 106})):
            report = analyzer.generate_intelligence_report(case)
            self.assert_unverified(report)
            self.assertEqual([r['id'] for r in report['source_records']], expected_ids)
            self.assertEqual(report['summary']['total_victims'], len(expected_ids))
            self.assertEqual(report['summary']['analyzed_victims'], len(expected_ids))
            self.assertEqual(report['summary']['stored_score_at_least_7'], len(expected_ids))
            self.assertEqual(report['geographic_distribution'], expected_countries)
            self.assertEqual(report['risk_distribution'], {'8': len(expected_ids)})
            self.assertEqual(report['source_records'][-1]['attacker_correlation'],
                {'claimed_operator': 'stored label'})
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_literal_empty_quoted_case_and_invalid_identifier_admission(self):
        writer = self.database()
        cases = ('', None, "case' OR 1=1 --", 'Case', 'case')
        identifiers = {case: writer.add_victim_intelligence('192.0.2.1', 'stored UA',
            'https://example.invalid/stored', case_id=case) for case in cases}
        analyzer = IntelligenceAnalyzer(writer.db_path, read_only=True)
        before = Path(writer.db_path).read_bytes()
        for case in (*cases, 'absent'):
            report = analyzer.generate_intelligence_report(case)
            expected = set(identifiers.values()) if case is None else (
                {identifiers[case]} if case in identifiers else set())
            self.assertEqual({r['id'] for r in report['source_records']}, expected)
            self.assertEqual(report['case_id'], case)
            self.assert_unverified(report)
        for invalid in (1, False, [], {}):
            with self.assertRaises(TypeError):
                analyzer.generate_intelligence_report(invalid)
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_full_source_and_json_decoding_outcomes_survive_actual_report_file(self):
        writer, identifier, analyzer = self.seed()
        for raw in (None, '', 'null', '{broken', '{"x":1,"x":2}', 'NaN', b'\xff',
                    ' {"country":"é", "nested":[false,null]} \n'):
            with self.subTest(raw=raw):
                with writer.connection() as conn:
                    for field in source_rows.JSON_DEFAULTS:
                        conn.execute(f'UPDATE victim_intelligence SET {field}=?', (raw,))
                before = Path(writer.db_path).read_bytes()
                expected = analyzer.db.get_victim_intelligence(victim_id=identifier)[0]
                report = analyzer.generate_intelligence_report()
                target = self.root / 'actual-report.json'
                target.write_text(json.dumps(report, allow_nan=False), encoding='utf-8')
                restored = json.loads(target.read_text(encoding='utf-8'))
                self.assertEqual(restored['source_records'], [expected])
                self.assert_unverified(restored)
                self.assertEqual(Path(writer.db_path).read_bytes(), before)
        with writer.connection() as conn:
            conn.execute("UPDATE victim_intelligence SET metadata=CAST(X'80' AS TEXT)")
        report = analyzer.generate_intelligence_report()
        evidence = report['source_records'][0]['json_evidence']['fields']['metadata']
        self.assertEqual(evidence['raw_storage'], {'type': 'text', 'encoding': 'base64', 'value': 'gA=='})
        self.assertEqual(evidence['status'], 'invalid_encoding')

    def test_missing_and_wrong_shapes_do_not_become_countries_scores_or_verified_analysis(self):
        writer = self.database()
        rows = [
            ('analyzed', 8, '{"country":"Stored"}'),
            ('analyzed', 7.5, '{"country":"Stored"}'),
            ('analyzed', None, '{broken'),
            ('analyzed', 'not numeric', '{"country":"first","country":"second"}'),
            ('analyzed', 0, '[]'),
            ('analyzed', -2, '{"country":null}'),
            ('analyzed', 12, '{"country":5}'),
            ('analyzed', 4, '{"country":"  "}'),
            ('captured', 9, '{"country":"Unanalyzed"}'),
            (None, 10, '{"country":"No status"}')]
        with writer.connection() as conn:
            for index, (status, score, geo) in enumerate(rows):
                conn.execute('INSERT INTO victim_intelligence '
                    '(victim_ip, click_time, phishing_url, analyzed_status, risk_score, geolocation_data) '
                    'VALUES (?,?,?,?,?,?)', ('192.0.2.1', f'{index:04}', 'https://example.invalid/', status, score, geo))
        analyzer = IntelligenceAnalyzer(writer.db_path, read_only=True)
        before = Path(writer.db_path).read_bytes()
        report = analyzer.generate_intelligence_report()
        self.assert_unverified(report)
        self.assertEqual(report['summary']['analyzed_victims'], 8)
        self.assertEqual(report['summary']['stored_score_at_least_7'], 5)
        self.assertEqual(report['status_breakdown'], {'analyzed': 8, 'captured': 1})
        self.assertEqual(report['geographic_distribution'], {'Stored': 2})
        self.assertEqual(report['risk_distribution'], {'8': 1, '7.5': 1, '0': 1, '-2': 1, '12': 1, '4': 1})
        evidence = report['aggregation_evidence']
        self.assertEqual(evidence['status_breakdown']['unusable_ids'], [10])
        self.assertEqual(evidence['stored_score_at_least_7']['unusable_ids'], [4, 3])
        self.assertEqual(evidence['geographic_distribution']['counted_ids'], [2, 1])
        self.assertEqual(evidence['geographic_distribution']['unusable_ids'], [8, 7, 6, 5, 4, 3])
        self.assertEqual(evidence['risk_distribution']['unusable_ids'], [4, 3])
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_empty_selection_is_a_real_empty_inventory_without_false_safe_or_recent_zero(self):
        writer = self.database()
        analyzer = IntelligenceAnalyzer(writer.db_path, read_only=True)
        before = Path(writer.db_path).read_bytes()
        report = analyzer.generate_intelligence_report()
        self.assert_unverified(report)
        self.assertEqual(report['source_records'], [])
        self.assertEqual(report['summary']['total_victims'], 0)
        self.assertEqual(report['summary']['stored_score_at_least_7'], 0)
        self.assertEqual(report['risk_distribution'], {})
        self.assertEqual(report['geographic_distribution'], {})
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_uninterpreted_timestamps_are_retained_with_explicitly_unavailable_recency(self):
        writer, identifier, analyzer = self.seed()
        for raw in (None, '', 'not a date', '2099-01-01T00:00:00Z',
                    '2026-10-12 01:00:00', '2026-10-12T01:00:00+02:00'):
            with self.subTest(raw=raw):
                with writer.connection() as conn:
                    conn.execute('UPDATE victim_intelligence SET created_at=?', (raw,))
                before = Path(writer.db_path).read_bytes()
                report = analyzer.generate_intelligence_report()
                self.assertEqual(report['source_records'][0]['created_at'], raw)
                self.assert_unverified(report)
                self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_all_original_partial_layouts_are_read_without_migration(self):
        layouts = [fields for size in range(4)
                   for fields in itertools.permutations(source_rows.INTERACTION_FIELDS, size)]
        self.assertEqual(len(layouts), 16)
        for index, fields in enumerate(layouts):
            with self.subTest(fields=fields):
                path = self.root / f'legacy-{index}.db'
                with closing(sqlite3.connect(path)) as conn, conn:
                    conn.execute('CREATE TABLE victim_intelligence (' + ', '.join(
                        key + ' ' + sql for key, sql in source_rows.LEGACY_FIELDS + list(fields)) + ')')
                    conn.execute('INSERT INTO victim_intelligence (victim_ip, click_time, phishing_url) '
                        'VALUES (?,?,?)', ('192.0.2.1', 'stored-date', 'https://example.invalid/'))
                before = path.read_bytes()
                analyzer = IntelligenceAnalyzer(str(path), read_only=True)
                report = analyzer.generate_intelligence_report()
                self.assert_unverified(report)
                self.assertEqual(report['source_records'], analyzer.db.get_victim_intelligence(victim_id=1))
                self.assertEqual(path.read_bytes(), before)

    def test_missing_corrupt_incomplete_and_later_pending_storage_never_become_empty_reports(self):
        missing = self.root / 'absent' / 'source.db'
        with self.assertRaises(FileNotFoundError):
            IntelligenceAnalyzer(str(missing), read_only=True)
        self.assertFalse(missing.parent.exists())
        corrupt = self.root / 'corrupt.db'
        corrupt.write_bytes(b'original corrupt bytes')
        with self.assertRaises(sqlite3.DatabaseError):
            IntelligenceAnalyzer(str(corrupt), read_only=True)
        self.assertEqual(corrupt.read_bytes(), b'original corrupt bytes')
        empty = self.root / 'empty.db'
        with closing(sqlite3.connect(empty)):
            pass
        before = empty.read_bytes()
        analyzer = IntelligenceAnalyzer(str(empty), read_only=True)
        with self.assertRaises(sqlite3.OperationalError):
            analyzer.generate_intelligence_report()
        self.assertEqual(empty.read_bytes(), before)
        writer, identifier, analyzer = self.seed()
        before = Path(writer.db_path).read_bytes()
        journal = Path(writer.db_path + '-journal')
        journal.write_bytes(b'pending saved journal')
        with self.assertRaises(ValueError):
            analyzer.generate_intelligence_report()
        self.assertEqual(journal.read_bytes(), b'pending saved journal')
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_unsupported_selected_native_values_fail_but_other_case_does_not_interfere(self):
        writer, identifier, analyzer = self.seed()
        other = writer.add_victim_intelligence('192.0.2.2', 'stored UA',
            'https://example.invalid/other', case_id='other-case')
        for field, value, error in (('risk_score', float('inf'), ValueError),
                                     ('victim_ua', b'\xff', TypeError)):
            with self.subTest(field=field):
                with writer.connection() as conn:
                    conn.execute('UPDATE victim_intelligence SET risk_score=0, victim_ua=? WHERE id=?', ('UA', other))
                    conn.execute(f'UPDATE victim_intelligence SET {field}=? WHERE id=?', (value, other))
                before = Path(writer.db_path).read_bytes()
                report = analyzer.generate_intelligence_report('source-case')
                self.assertEqual([r['id'] for r in report['source_records']], [identifier])
                with self.assertRaises(error):
                    analyzer.generate_intelligence_report()
                self.assertEqual(Path(writer.db_path).read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
