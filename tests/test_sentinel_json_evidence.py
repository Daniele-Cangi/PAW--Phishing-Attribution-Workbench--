"""Actual saved SQLite JSON provenance and strict serializable fallback records."""
import base64
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import unittest

from paw.sentinel.database import CampaignDatabase
import test_sentinel_database_rows as source_rows


class SentinelJSONEvidence(unittest.TestCase):
    setUp = source_rows.SentinelDatabaseRows.setUp
    tearDown = source_rows.SentinelDatabaseRows.tearDown
    database = source_rows.SentinelDatabaseRows.database
    populated_row = source_rows.SentinelDatabaseRows.populated_row
    stored_row = source_rows.SentinelDatabaseRows.stored_row

    def seed(self):
        writer = self.database()
        self.identifier = self.populated_row(writer)
        self.campaign = writer.add_campaign('source-case', 'https://example.invalid/')
        writer.record_check(self.campaign, 'stored-status')
        writer.record_alert(self.campaign, 'stored-alert', 'stored message')
        return writer, CampaignDatabase(writer.db_path, read_only=True)

    def set_metadata(self, writer, raw):
        with writer.connection() as conn:
            for table in ('campaigns', 'checks', 'alerts', 'victim_intelligence'):
                conn.execute(f'UPDATE {table} SET metadata=?', (raw,))

    def records(self, reader):
        return [reader.get_campaign(self.campaign), *reader.get_active_campaigns(),
                *reader.get_recent_checks(self.campaign), *reader.get_unacknowledged_alerts(),
                *reader.get_victim_intelligence(victim_id=self.identifier),
                *reader.get_victim_intelligence(victim_ip='192.0.2.1'),
                *reader.get_victim_intelligence(), *reader.get_unanalyzed_victims(),
                *reader.get_victims_by_risk_score(5), *reader.get_victims_by_country('StoredCountry')]

    def evidence(self, record, field='metadata'):
        self.assertEqual(record['json_evidence']['schema_version'], 1)
        result = record['json_evidence']['fields'][field]
        self.assertFalse(result['verified'])
        return result

    def test_exact_valid_text_and_nested_values_are_preserved_by_every_reader(self):
        writer, reader = self.seed()
        raw = ' {\n "é": [1, {"unknown": false}], "claim": "unverified", "nullable": null } \n'
        self.set_metadata(writer, raw)
        before = Path(writer.db_path).read_bytes()
        records = self.records(reader)
        self.assertEqual(len(records), 10)
        for record in records:
            self.assertEqual(record['metadata'], {'é': [1, {'unknown': False}], 'claim': 'unverified', 'nullable': None})
            self.assertEqual(self.evidence(record), {'status': 'decoded', 'raw_storage': {'type': 'text', 'value': raw},
                                                    'default_applied': False, 'verified': False})
        self.assertEqual(Path(writer.db_path).read_bytes(), before)
        json.dumps(records, allow_nan=False)  # Actual strict serialization, no new exporter.

    def test_sql_null_empty_text_and_json_null_do_not_share_a_decode_status(self):
        writer, reader = self.seed()
        cases = [(None, 'sql_null', {}, True), ('', 'empty', {}, True),
                 ('null', 'decoded', None, False), ('{}', 'decoded', {}, False),
                 ('false', 'decoded', False, False), ('0', 'decoded', 0, False)]
        for raw, status, parsed, default_applied in cases:
            with self.subTest(raw=raw):
                self.set_metadata(writer, raw)
                for record in self.records(reader):
                    result = self.evidence(record)
                    self.assertEqual(record['metadata'], parsed)
                    self.assertEqual(result['status'], status)
                    self.assertEqual(result['default_applied'], default_applied)
                    self.assertEqual(result['raw_storage'], {'type': 'null' if raw is None else 'text', 'value': raw})

    def test_malformed_alert_does_not_hide_other_rows_and_source_is_retained(self):
        writer, reader = self.seed()
        raw = '{broken original source'
        self.set_metadata(writer, raw)
        writer.record_alert(self.campaign, 'second-stored', 'second message', metadata={'é': 'retained'})
        before = Path(writer.db_path).read_bytes()
        for record in self.records(reader):
            if record.get('message') == 'second message':
                self.assertEqual(record['metadata'], {'é': 'retained'})
                self.assertEqual(self.evidence(record)['status'], 'decoded')
            else:
                self.assertEqual(record['metadata'], {})
                self.assertEqual(self.evidence(record)['status'], 'invalid_json')
                self.assertEqual(self.evidence(record)['raw_storage']['value'], raw)
                self.assertTrue(self.evidence(record)['default_applied'])
        self.assertEqual(len(reader.get_unacknowledged_alerts()), 2)
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_invalid_utf8_text_retains_text_type_and_valid_neighbor_alert(self):
        writer, reader = self.seed()
        writer.record_alert(self.campaign, 'second-stored', 'second message', metadata={'é': 'retained'})
        for raw in (b'\x80', b'{"x":"\xff"}', '{"é":1}'.encode('utf-16')):
            with self.subTest(raw=raw):
                with writer.connection() as conn:
                    for table in ('campaigns', 'checks', 'alerts', 'victim_intelligence'):
                        where = " WHERE message != 'second message'" if table == 'alerts' else ''
                        conn.execute(f'UPDATE {table} SET metadata=CAST(? AS TEXT)' + where, (raw,))
                        stored = conn.execute(f'SELECT typeof(metadata), CAST(metadata AS BLOB) FROM {table}' + where).fetchone()
                        self.assertEqual(stored, ('text', raw))
                before = Path(writer.db_path).read_bytes()
                records = self.records(reader)
                self.assertEqual(len(records), 11)
                for record in records:
                    if record.get('message') == 'second message':
                        self.assertEqual(record['metadata'], {'é': 'retained'})
                        self.assertEqual(self.evidence(record)['status'], 'decoded')
                    else:
                        self.assertEqual(record['metadata'], {})
                        self.assertEqual(self.evidence(record), {
                            'status': 'invalid_encoding', 'raw_storage': {
                                'type': 'text', 'encoding': 'base64',
                                'value': base64.b64encode(raw).decode('ascii')},
                            'default_applied': True, 'verified': False})
                json.dumps(records, allow_nan=False).encode('utf-8')
                self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_invalid_utf8_in_other_json_columns_and_non_json_failure_boundary(self):
        writer, reader = self.seed()
        raw = b'\x80'
        with writer.connection() as conn:
            for field in source_rows.JSON_DEFAULTS:
                conn.execute(f'UPDATE victim_intelligence SET {field}=CAST(? AS TEXT)', (raw,))
        before = Path(writer.db_path).read_bytes()
        for record in (reader.get_victim_intelligence(victim_id=self.identifier)[0],
                       reader.get_unanalyzed_victims()[0], reader.get_victims_by_risk_score(5)[0]):
            for field, default in source_rows.JSON_DEFAULTS.items():
                self.assertEqual(record[field], default)
                result = self.evidence(record, field)
                self.assertEqual(result['status'], 'invalid_encoding')
                self.assertEqual(result['raw_storage']['type'], 'text')
                self.assertEqual(base64.b64decode(result['raw_storage']['value']), raw)
            json.dumps(record, allow_nan=False).encode('utf-8')
        self.assertEqual(Path(writer.db_path).read_bytes(), before)
        # Only JSON columns receive the new decoding evidence. Do not leak a
        # private bytes marker into an unrelated compatibility field.
        with writer.connection() as conn:
            conn.execute('UPDATE alerts SET message=CAST(? AS TEXT)', (raw,))
        before = Path(writer.db_path).read_bytes()
        with self.assertRaises(sqlite3.OperationalError):
            reader.get_unacknowledged_alerts()
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_duplicate_keys_at_any_depth_are_ambiguous_instead_of_last_value_wins(self):
        writer, reader = self.seed()
        for raw in ('{"country":"first","country":"last"}',
                    '{"nested":[{"x":1,"x":2}]}', '{"a":1,"\\u0061":2}'):
            with self.subTest(raw=raw):
                self.set_metadata(writer, raw)
                before = Path(writer.db_path).read_bytes()
                for record in self.records(reader):
                    self.assertEqual(record['metadata'], {})
                    self.assertEqual(self.evidence(record)['status'], 'duplicate_keys')
                    self.assertEqual(self.evidence(record)['raw_storage']['value'], raw)
                self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_non_finite_constants_and_exponent_overflow_remain_only_in_raw_source(self):
        writer, reader = self.seed()
        for raw in ('NaN', 'Infinity', '-Infinity', '1e999', '-1e999', '{"nested":[0,NaN]}',
                    '{"nested":{"number":1e999}}'):
            with self.subTest(raw=raw):
                self.set_metadata(writer, raw)
                before = Path(writer.db_path).read_bytes()
                records = self.records(reader)
                for record in records:
                    self.assertEqual(record['metadata'], {})
                    self.assertEqual(self.evidence(record)['status'], 'non_finite_number')
                    self.assertEqual(self.evidence(record)['raw_storage']['value'], raw)
                json.dumps(records, allow_nan=False)
                self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_blob_and_wrong_sql_scalar_storage_remain_lossless_and_serializable(self):
        writer, reader = self.seed()
        cases = [(b'{"x":1}', 'decoded', {'x': 1}),
                 ('{"é":"original"}'.encode('utf-16'), 'decoded', {'é': 'original'}),
                 (b'\xffbroken', 'invalid_encoding', {}), (b'', 'empty', {}),
                 (0, 'unsupported_storage_type', {}), (1.5, 'unsupported_storage_type', {}),
                 (float('inf'), 'unsupported_storage_type', {})]
        for raw, status, parsed in cases:
            with self.subTest(raw=raw):
                self.set_metadata(writer, raw)
                # SQLite TEXT affinity can turn bound numeric values into TEXT.
                # Use the actual returned storage type, not the bound parameter.
                with writer.connection() as conn:
                    actual = conn.execute('SELECT metadata FROM campaigns').fetchone()[0]
                records = self.records(reader)
                for record in records:
                    evidence = self.evidence(record)
                    source = evidence['raw_storage']
                    if isinstance(actual, bytes):
                        self.assertEqual(base64.b64decode(source['value']), actual)
                        self.assertEqual(source['type'], 'blob')
                        self.assertEqual(record['metadata'], parsed)
                        self.assertEqual(evidence['status'], status)
                    else:
                        self.assertEqual(source, {'type': 'text', 'value': actual})
                        if actual in ('0', '1.5'):
                            self.assertEqual(record['metadata'], json.loads(actual))
                            self.assertEqual(evidence['status'], 'decoded')
                        else:
                            self.assertEqual(record['metadata'], {})
                            self.assertEqual(evidence['status'], 'invalid_json')
                json.dumps(records, allow_nan=False)

    def test_legacy_non_text_sql_storage_is_preserved_in_a_serializable_typed_source(self):
        path = self.root / 'non-text-storage.db'
        with closing(sqlite3.connect(path)) as conn, conn:
            conn.execute('CREATE TABLE campaigns (id TEXT PRIMARY KEY, case_id TEXT, '
                'created_at TEXT, last_check TEXT, status TEXT, url TEXT, domain TEXT, '
                'title TEXT, description TEXT, risk_level TEXT, metadata BLOB)')
            conn.execute('INSERT INTO campaigns (id,case_id,created_at,status,url) '
                         'VALUES (?,?,?,?,?)', ('stored', 'source', '2020-01-01', 'active', 'https://example.invalid/'))
        reader = CampaignDatabase(str(path), read_only=True)
        for raw in (0, 42, 1.5, float('inf'), float('-inf')):
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.execute('UPDATE campaigns SET metadata=?', (raw,))
            before = path.read_bytes()
            records = [reader.get_campaign('stored'), *reader.get_active_campaigns()]
            for record in records:
                self.assertEqual(record['metadata'], {})
                self.assertEqual(self.evidence(record)['status'], 'unsupported_storage_type')
                source = self.evidence(record)['raw_storage']
                if isinstance(raw, int):
                    self.assertEqual(source, {'type': 'integer', 'value': raw})
                else:
                    self.assertEqual(source['type'], 'real')
                    self.assertEqual(source['encoding'], 'float_hex')
                    self.assertEqual(float.fromhex(source['value']), raw)
            json.dumps(records, allow_nan=False)
            self.assertEqual(path.read_bytes(), before)

    def test_each_interaction_json_field_retains_its_named_source_and_default(self):
        writer, reader = self.seed()
        raw = '{broken'
        with writer.connection() as conn:
            for field in source_rows.JSON_DEFAULTS:
                conn.execute(f'UPDATE victim_intelligence SET {field}=?', (raw,))
        before = Path(writer.db_path).read_bytes()
        stored = self.stored_row(reader, self.identifier)
        for record in (reader.get_victim_intelligence(victim_id=self.identifier)[0],
                       reader.get_unanalyzed_victims()[0], reader.get_victims_by_risk_score(5)[0]):
            self.assertEqual(set(record['json_evidence']['fields']), set(source_rows.JSON_DEFAULTS))
            for field, default in source_rows.JSON_DEFAULTS.items():
                self.assertEqual(record[field], default)
                self.assertEqual(self.evidence(record, field)['raw_storage']['value'], stored[field])
                self.assertEqual(self.evidence(record, field)['status'], 'invalid_json')
        self.assertEqual(reader.get_victims_by_country('StoredCountry'), [])
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_legacy_absent_column_is_distinct_from_stored_sql_null_and_json_null(self):
        path = self.root / 'original-legacy.db'
        with closing(sqlite3.connect(path)) as conn, conn:
            conn.execute('CREATE TABLE victim_intelligence (' + ', '.join(
                key + ' ' + sql for key, sql in source_rows.LEGACY_FIELDS) + ')')
            conn.execute('INSERT INTO victim_intelligence (victim_ip, click_time, phishing_url) '
                         'VALUES (?,?,?)', ('192.0.2.1', '2020-01-01', 'https://example.invalid/'))
        before = path.read_bytes()
        reader = CampaignDatabase(str(path), read_only=True)
        record = reader.get_victim_intelligence(victim_id=1)[0]
        self.assertIsNone(record['interaction_indicators'])
        self.assertEqual(self.evidence(record, 'interaction_indicators'), {
            'status': 'missing_column', 'raw_storage': None, 'default_applied': False, 'verified': False})
        self.assertEqual(path.read_bytes(), before)
        writer = CampaignDatabase(str(path))  # Explicit migration, separately from passive reads.
        for raw, parsed, status in [(None, [], 'sql_null'), ('null', None, 'decoded')]:
            with writer.connection() as conn:
                conn.execute('UPDATE victim_intelligence SET interaction_indicators=?', (raw,))
            record = reader.get_victim_intelligence(victim_id=1)[0]
            self.assertEqual(record['interaction_indicators'], parsed)
            self.assertEqual(self.evidence(record, 'interaction_indicators')['status'], status)

    def test_decoder_depth_failure_retains_source_and_is_explicit(self):
        writer, reader = self.seed()
        # Python 3.13's C decoder admission is not sys.getrecursionlimit().
        depth = 100_000
        raw = '[' * depth + '0' + ']' * depth
        self.set_metadata(writer, raw)
        before = Path(writer.db_path).read_bytes()
        records = self.records(reader)
        for record in records:
            self.assertEqual(record['metadata'], {})
            self.assertEqual(self.evidence(record)['status'], 'decode_error')
            self.assertEqual(self.evidence(record)['raw_storage']['value'], raw)
        json.dumps(records, allow_nan=False)
        self.assertEqual(Path(writer.db_path).read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
