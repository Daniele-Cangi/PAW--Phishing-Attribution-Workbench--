"""Actual saved SQLite export fidelity and independently recomputed JSON digest."""
import base64
from contextlib import closing
import hashlib
import itertools
import json
from pathlib import Path
import sqlite3
import unittest

from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer
import test_sentinel_database_rows as source_rows


EMPTY_SHA256 = '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'


class SentinelForensicExport(unittest.TestCase):
    setUp = source_rows.SentinelDatabaseRows.setUp
    tearDown = source_rows.SentinelDatabaseRows.tearDown
    database = source_rows.SentinelDatabaseRows.database
    populated_row = source_rows.SentinelDatabaseRows.populated_row

    def seed(self):
        writer = self.database()
        self.identifier = self.populated_row(writer)
        return writer, IntelligenceAnalyzer(writer.db_path, read_only=True)

    def assert_digest(self, report):
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['evidence_scope'], 'stored_rows_unverified')
        self.assertEqual(report['chain_of_custody'], 'not_established')
        self.assertEqual(report['data_integrity'], {'algorithm': 'sha256', 'scope': 'victims',
            'serialization': 'json_sorted_keys_ascii_compact_v1'})
        # Independently serialize the returned and round-tripped list, rather
        # than invoking the production hash helper as an oracle.
        payload = json.dumps(report['victims'], sort_keys=True, ensure_ascii=True,
            separators=(',', ':'), allow_nan=False).encode('ascii')
        self.assertEqual(report['data_integrity_hash'], hashlib.sha256(payload).hexdigest())
        decoded = json.loads(json.dumps(report, allow_nan=False))
        payload = json.dumps(decoded['victims'], sort_keys=True, ensure_ascii=True,
            separators=(',', ':'), allow_nan=False).encode('ascii')
        self.assertEqual(report['data_integrity_hash'], hashlib.sha256(payload).hexdigest())

    def test_full_named_records_survive_actual_json_file_and_hash_matches_exported_list(self):
        writer, analyzer = self.seed()
        source = analyzer.db.get_victim_intelligence()[0]
        before = Path(writer.db_path).read_bytes()
        report = analyzer.export_forensic_data('source-case')
        self.assert_digest(report)
        record = report['victims'][0]
        self.assertEqual(record['stored_record'], source)
        self.assertEqual(record['geolocation'], source['geolocation_data'])
        self.assertEqual(record['evidence_chain'], {'captured_at': source['created_at'],
            'analyzed_at': source['updated_at'], 'analysis_method': None,
            'scope': 'stored_timestamp_aliases',
            'source_fields': {'captured_at': 'created_at', 'analyzed_at': 'updated_at'}, 'verified': False})
        target = self.root / 'export.json'
        target.write_text(json.dumps(report, allow_nan=False), encoding='utf-8')
        restored = json.loads(target.read_text(encoding='utf-8'))
        self.assertEqual(restored['victims'][0]['stored_record'], source)
        self.assert_digest(restored)
        changed = json.loads(target.read_text(encoding='utf-8'))
        changed['victims'][0]['stored_record']['metadata']['original'][0] = 'changed source'
        payload = json.dumps(changed['victims'], sort_keys=True, ensure_ascii=True,
            separators=(',', ':'), allow_nan=False).encode('ascii')
        self.assertNotEqual(report['data_integrity_hash'], hashlib.sha256(payload).hexdigest())
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_json_decoding_sources_remain_exact_instead_of_only_exporting_fallback_values(self):
        writer, analyzer = self.seed()
        cases = [(None, 'sql_null'), ('', 'empty'), ('null', 'decoded'),
                 (' {"é": [1, false]} \n', 'decoded'), ('{broken', 'invalid_json'),
                 ('{"x":1,"x":2}', 'duplicate_keys'), ('NaN', 'non_finite_number'),
                 (b'\xff', 'invalid_encoding')]
        for raw, status in cases:
            with self.subTest(raw=raw):
                with writer.connection() as conn:
                    for field in source_rows.JSON_DEFAULTS:
                        conn.execute(f'UPDATE victim_intelligence SET {field}=?', (raw,))
                before = Path(writer.db_path).read_bytes()
                source = analyzer.db.get_victim_intelligence()[0]
                report = analyzer.export_forensic_data()
                self.assert_digest(report)
                exported = report['victims'][0]['stored_record']
                self.assertEqual(exported, source)
                for evidence in exported['json_evidence']['fields'].values():
                    self.assertEqual(evidence['status'], status)
                    self.assertFalse(evidence['verified'])
                    stored = evidence['raw_storage']
                    if isinstance(raw, bytes):
                        self.assertEqual(stored['type'], 'blob')
                        self.assertEqual(base64.b64decode(stored['value']), raw)
                    else:
                        self.assertEqual(stored['value'], raw)
                self.assertEqual(Path(writer.db_path).read_bytes(), before)
        with writer.connection() as conn:
            conn.execute("UPDATE victim_intelligence SET metadata=CAST(X'80' AS TEXT)")
        before = Path(writer.db_path).read_bytes()
        report = analyzer.export_forensic_data()
        self.assert_digest(report)
        evidence = report['victims'][0]['stored_record']['json_evidence']['fields']['metadata']
        self.assertEqual(evidence['status'], 'invalid_encoding')
        self.assertEqual(evidence['raw_storage'], {'type': 'text', 'encoding': 'base64', 'value': 'gA=='})
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_exact_case_filter_including_empty_string_and_known_empty_digest(self):
        writer, analyzer = self.seed()
        identifiers = {'source-case': self.identifier}
        for case in ('other-case', '', None):
            identifiers[case] = writer.add_victim_intelligence('192.0.2.2', 'stored UA',
                'https://example.invalid/other', case_id=case)
        before = Path(writer.db_path).read_bytes()
        for case in ('source-case', 'other-case', '', 'absent-case', None):
            report = analyzer.export_forensic_data(case)
            expected = set(identifiers.values()) if case is None else (
                {identifiers[case]} if case in identifiers else set())
            self.assertEqual({v['id'] for v in report['victims']}, expected)
            self.assertEqual(report['total_records'], len(expected))
            self.assertEqual(report['case_id'], case)
            self.assert_digest(report)
            if not expected:
                self.assertEqual(report['data_integrity_hash'], EMPTY_SHA256)
        with self.assertRaises(TypeError):
            analyzer.export_forensic_data(1)
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_export_includes_old_cases_and_more_than_100_rows_per_case(self):
        writer = self.database()
        literal = "case' OR 1=1 --"
        cases = ['older-case'] * 105 + ['', None, literal] + ['newer-case'] * 105
        expected = {}
        with writer.connection() as conn:
            for index, case in enumerate(cases):
                cursor = conn.execute('INSERT INTO victim_intelligence '
                    '(victim_ip, victim_ua, click_time, phishing_url, case_id, metadata) '
                    'VALUES (?,?,?,?,?,?)', ('192.0.2.1', 'stored UA', f'{index:04}',
                    'https://example.invalid/stored', case, '{"source":1}'))
                expected.setdefault(case, []).append(cursor.lastrowid)
            oldest = expected['older-case'][0]
            conn.execute("UPDATE victim_intelligence SET metadata=CAST(X'80' AS TEXT) WHERE id=?",
                (oldest,))
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM victim_intelligence').fetchone()[0], 213)
        analyzer = IntelligenceAnalyzer(writer.db_path, read_only=True)
        before = Path(writer.db_path).read_bytes()
        # The interactive listing keeps its existing cap; it cannot be the
        # completeness oracle for the export.
        self.assertEqual(len(analyzer.db.get_victim_intelligence()), 100)
        for case in (None, 'older-case', 'newer-case', '', literal, 'OLDER-CASE', 'absent-case'):
            with self.subTest(case=case):
                identifiers = list(range(213, 0, -1)) if case is None else list(reversed(expected.get(case, [])))
                report = analyzer.export_forensic_data(case)
                self.assertEqual([v['id'] for v in report['victims']], identifiers)
                self.assertEqual(report['total_records'], len(identifiers))
                self.assert_digest(report)
                if oldest in identifiers:
                    record = next(v['stored_record'] for v in report['victims'] if v['id'] == oldest)
                    self.assertEqual(record, analyzer.db.get_victim_intelligence(victim_id=oldest)[0])
                    evidence = record['json_evidence']['fields']['metadata']
                    self.assertEqual(evidence['status'], 'invalid_encoding')
                    self.assertEqual(evidence['raw_storage']['value'], 'gA==')
        self.assertEqual(Path(writer.db_path).read_bytes(), before)
        original = analyzer.export_forensic_data()['data_integrity_hash']
        with writer.connection() as conn:
            conn.execute('UPDATE victim_intelligence SET metadata=? WHERE id=?', ('{"changed":true}', oldest))
        self.assertNotEqual(analyzer.export_forensic_data()['data_integrity_hash'], original)

    def test_case_selection_precedes_decoding_unrelated_invalid_rows(self):
        writer, analyzer = self.seed()
        other = writer.add_victim_intelligence('192.0.2.2', 'stored UA',
            'https://example.invalid/other', case_id='other-case')
        with writer.connection() as conn:
            conn.execute("UPDATE victim_intelligence SET victim_ua=CAST(X'80' AS TEXT) WHERE id=?", (other,))
        before = Path(writer.db_path).read_bytes()
        report = analyzer.export_forensic_data('source-case')
        self.assertEqual([v['id'] for v in report['victims']], [self.identifier])
        self.assert_digest(report)
        # A full export still fails explicitly on an unsupported selected row;
        # it must not hide that row by skipping it.
        with self.assertRaises(sqlite3.OperationalError):
            analyzer.export_forensic_data()
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_original_and_partial_layouts_are_exported_without_initialization_or_migration(self):
        layouts = []
        for size in range(4):
            layouts.extend(itertools.permutations(source_rows.INTERACTION_FIELDS, size))
        self.assertEqual(len(layouts), 16)
        for index, fields in enumerate(layouts):
            with self.subTest(fields=fields):
                path = self.root / f'legacy-{index}.db'
                with closing(sqlite3.connect(path)) as conn, conn:
                    conn.execute('CREATE TABLE victim_intelligence (' + ', '.join(
                        key + ' ' + sql for key, sql in source_rows.LEGACY_FIELDS + list(fields)) + ')')
                    conn.execute('INSERT INTO victim_intelligence (victim_ip, click_time, phishing_url, metadata) '
                        'VALUES (?,?,?,?)', ('192.0.2.1', 'stored-date', 'https://example.invalid/', '{"source":"é"}'))
                before = path.read_bytes()
                analyzer = IntelligenceAnalyzer(str(path), read_only=True)
                source = analyzer.db.get_victim_intelligence()[0]
                report = analyzer.export_forensic_data()
                self.assertEqual(report['victims'][0]['stored_record'], source)
                self.assert_digest(report)
                self.assertEqual(path.read_bytes(), before)

    def test_missing_corrupt_or_incomplete_storage_is_not_an_empty_healthy_export(self):
        missing = self.root / 'absent' / 'source.db'
        with self.assertRaises(FileNotFoundError):
            IntelligenceAnalyzer(str(missing), read_only=True)
        self.assertFalse(missing.parent.exists())
        corrupt = self.root / 'corrupt.db'
        corrupt.write_bytes(b'original damaged source')
        with self.assertRaises(sqlite3.DatabaseError):
            IntelligenceAnalyzer(str(corrupt), read_only=True)
        self.assertEqual(corrupt.read_bytes(), b'original damaged source')
        empty = self.root / 'empty.db'
        with closing(sqlite3.connect(empty)):
            pass
        before = empty.read_bytes()
        analyzer = IntelligenceAnalyzer(str(empty), read_only=True)
        with self.assertRaises(sqlite3.OperationalError):
            analyzer.export_forensic_data()
        self.assertEqual(empty.read_bytes(), before)

    def test_unsupported_non_json_scalars_fail_without_stringifying_or_omitting_rows(self):
        writer, analyzer = self.seed()
        for field, raw, error in [('risk_score', float('inf'), ValueError), ('victim_ua', b'\xff', TypeError)]:
            with self.subTest(field=field):
                with writer.connection() as conn:
                    conn.execute('UPDATE victim_intelligence SET risk_score=6, victim_ua=?', ('stored UA',))
                    conn.execute(f'UPDATE victim_intelligence SET {field}=?', (raw,))
                before = Path(writer.db_path).read_bytes()
                with self.assertRaises(error):
                    analyzer.export_forensic_data()
                self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_passive_mode_rejects_collector_paths_before_threads_or_storage_updates(self):
        writer, analyzer = self.seed()
        before = Path(writer.db_path).read_bytes()
        self.assertIsNone(analyzer.ip_analyzer)
        for operation in (analyzer.analyze_unanalyzed_victims,
                          lambda: analyzer._analyze_single_victim(analyzer.db.get_victim_intelligence()[0]),
                          analyzer._update_attacker_correlations):
            with self.assertRaises(RuntimeError):
                operation()
        journal = Path(writer.db_path + '-journal')
        journal.write_bytes(b'preserved pending source')
        with self.assertRaises(ValueError):
            analyzer.export_forensic_data()
        self.assertEqual(journal.read_bytes(), b'preserved pending source')
        self.assertEqual(Path(writer.db_path).read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
