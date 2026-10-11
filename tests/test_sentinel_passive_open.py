"""Real saved SQLite opening without creation, migration or source rewrites."""
from contextlib import closing
import itertools
import json
from pathlib import Path
import sqlite3
import unittest

from paw.sentinel.database import CampaignDatabase
import test_sentinel_database_rows as source_rows
from test_sentinel_database_rows import LEGACY_FIELDS, INTERACTION_FIELDS


class SentinelPassiveOpen(unittest.TestCase):
    # Reuse real offline SQLite helpers without inheriting their test cases.
    setUp = source_rows.SentinelDatabaseRows.setUp
    tearDown = source_rows.SentinelDatabaseRows.tearDown
    database = source_rows.SentinelDatabaseRows.database
    populated_row = source_rows.SentinelDatabaseRows.populated_row
    readers = source_rows.SentinelDatabaseRows.readers
    stored_row = source_rows.SentinelDatabaseRows.stored_row
    expected_row = source_rows.SentinelDatabaseRows.expected_row

    def test_missing_database_and_parent_are_not_created(self):
        for path in (self.root / 'missing.db', self.root / 'absent' / 'missing.db'):
            with self.subTest(path=path):
                before = list(self.root.rglob('*'))
                with self.assertRaises(FileNotFoundError):
                    CampaignDatabase(str(path), read_only=True)
                self.assertEqual(list(self.root.rglob('*')), before)

    def test_current_schema_readers_preserve_database_and_tree(self):
        writer = self.database()
        identifier = self.populated_row(writer)
        campaign = writer.add_campaign('saved-case', 'https://example.invalid/', {'é': ['raw']})
        writer.record_check(campaign, 'stored-status', http_status=201, metadata={'source': 'stored'})
        writer.record_alert(campaign, 'stored-alert', 'stored message', metadata={'source': 'stored'})
        before = self.snapshot()
        reader = CampaignDatabase(writer.db_path, read_only=True)
        expected = self.expected_row(self.stored_row(writer, identifier))
        for records in self.readers(reader, identifier).values():
            self.assertEqual(records, [expected])
        self.assertEqual(reader.get_campaign(campaign), writer.get_campaign(campaign))
        self.assertEqual(reader.get_active_campaigns(), writer.get_active_campaigns())
        self.assertEqual(reader.get_recent_checks(campaign), writer.get_recent_checks(campaign))
        self.assertEqual(reader.get_unacknowledged_alerts(), writer.get_unacknowledged_alerts())
        self.assertEqual(reader.get_victim_statistics()['total_victims'], 1)
        self.assertEqual(self.snapshot(), before)
        path = Path(writer.db_path)
        renamed = path.with_suffix('.saved')
        path.rename(renamed)
        renamed.rename(path)  # Windows also verifies closed handles.

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes() if p.is_file() else None
                for p in self.root.rglob('*')}

    def test_preexisting_legacy_rows_are_read_without_adding_missing_columns_or_tables(self):
        for size in range(4):
            for i, fields in enumerate(itertools.permutations(INTERACTION_FIELDS, size)):
                with self.subTest(size=size, order=i):
                    path = self.root / f'legacy-{size}-{i}.db'
                    with closing(sqlite3.connect(path)) as conn, conn:
                        conn.execute('CREATE TABLE victim_intelligence (' + ', '.join(
                            key + ' ' + sql for key, sql in LEGACY_FIELDS + list(fields)) + ')')
                        conn.execute('INSERT INTO victim_intelligence '
                            '(victim_ip, victim_ua, click_time, phishing_url, metadata, '
                            'geolocation_data, risk_score) VALUES (?,?,?,?,?,?,?)',
                            ('192.0.2.1', 'Stored UA', '2020-01-01T01:02:03Z',
                             'https://example.invalid/', json.dumps({'é': ['original']}),
                             json.dumps({'country': 'StoredCountry'}), 6))
                        for key, _ in fields:
                            value = {'interaction_type': 'stored-label', 'interaction_confidence': 0.375,
                                     'interaction_indicators': '["stored indicator"]'}[key]
                            conn.execute(f'UPDATE victim_intelligence SET {key}=?', (value,))
                    before = self.snapshot()
                    reader = CampaignDatabase(str(path), read_only=True)
                    raw = self.stored_row(reader, 1)
                    expected = dict(raw)
                    for key, default in source_rows.JSON_DEFAULTS.items():
                        if key in raw:
                            expected[key] = json.loads(raw[key]) if raw[key] else default
                    for key, _ in INTERACTION_FIELDS:
                        if key not in expected:
                            expected[key] = None
                    for records in self.readers(reader, 1).values():
                        self.assertEqual(records, [expected])
                    with reader.connection() as conn:
                        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                    self.assertNotIn('campaigns', tables)
                    self.assertEqual(self.snapshot(), before)

    def test_existing_mutators_and_sql_writes_fail_on_read_only_connections(self):
        writer = self.database()
        identifier = self.populated_row(writer)
        campaign = writer.add_campaign('source-case', 'https://example.invalid/')
        writer.record_alert(campaign, 'stored', 'source')
        reader = CampaignDatabase(writer.db_path, read_only=True)
        before = self.snapshot()
        operations = [lambda: reader.add_campaign('new', 'https://example.invalid/'),
            lambda: reader.update_campaign_status(campaign, 'removed'),
            lambda: reader.record_check(campaign, 'stored'),
            lambda: reader.record_alert(campaign, 'stored', 'message'),
            lambda: reader.acknowledge_alert(1), lambda: reader.cleanup_old_data(),
            lambda: reader.add_victim_intelligence('192.0.2.2', 'UA', 'https://example.invalid/'),
            lambda: reader.update_victim_analysis(identifier, risk_score=7)]
        for operation in operations:
            with self.assertRaises(sqlite3.OperationalError):
                operation()
        with reader.connection() as conn:
            self.assertEqual(conn.execute('PRAGMA query_only').fetchone()[0], 1)
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute('CREATE TEMP TABLE forbidden (id INTEGER)')
        self.assertEqual(self.snapshot(), before)

    def test_literal_special_characters_in_path_are_not_sqlite_uri_options(self):
        # '?' is not a legal Windows filename; '#' and '%' are portable.
        path = self.root / 'saved # Ω % mode=rw.db'
        writer = CampaignDatabase(str(path))
        identifier = self.populated_row(writer)
        before = self.snapshot()
        reader = CampaignDatabase(str(path), read_only=True)
        self.assertEqual(reader.get_victim_intelligence(victim_id=identifier),
                         writer.get_victim_intelligence(victim_id=identifier))
        self.assertEqual(self.snapshot(), before)

    def test_disappeared_target_is_not_recreated_on_later_connections(self):
        writer = self.database()
        reader = CampaignDatabase(writer.db_path, read_only=True)
        Path(writer.db_path).unlink()
        with self.assertRaises(FileNotFoundError):
            reader.get_active_campaigns()
        self.assertFalse(Path(writer.db_path).exists())

    def test_corrupt_file_directory_and_empty_schema_are_not_repaired(self):
        path = self.root / 'corrupt.db'
        path.write_bytes(b'original non-SQLite source')
        before = self.snapshot()
        with self.assertRaises(sqlite3.DatabaseError):
            CampaignDatabase(str(path), read_only=True)
        with self.assertRaises(FileNotFoundError):
            CampaignDatabase(str(self.root), read_only=True)
        self.assertEqual(self.snapshot(), before)
        empty = self.root / 'empty.db'
        with closing(sqlite3.connect(empty)):
            pass
        before = self.snapshot()
        reader = CampaignDatabase(str(empty), read_only=True)
        with self.assertRaises(sqlite3.OperationalError):
            reader.get_active_campaigns()
        self.assertEqual(self.snapshot(), before)

    def test_wal_and_pending_journal_are_rejected_without_sidecar_changes(self):
        writer = self.database()
        for suffix in ('-wal', '-shm', '-journal'):
            sidecar = Path(writer.db_path + suffix)
            sidecar.write_bytes(b'preserve pending source')
            before = self.snapshot()
            with self.assertRaises(ValueError):
                CampaignDatabase(writer.db_path, read_only=True)
            self.assertEqual(self.snapshot(), before)
            sidecar.unlink()
        # Real committed WAL data, not a fabricated header or collector result.
        with closing(sqlite3.connect(writer.db_path)) as conn, conn:
            self.assertEqual(conn.execute('PRAGMA journal_mode=WAL').fetchone()[0], 'wal')
            conn.execute('CREATE TABLE wal_source (value TEXT)')
        before = self.snapshot()
        with self.assertRaises(ValueError):
            CampaignDatabase(writer.db_path, read_only=True)
        self.assertEqual(self.snapshot(), before)

    def test_later_connections_recheck_journal_admission(self):
        writer = self.database()
        reader = CampaignDatabase(writer.db_path, read_only=True)
        with closing(sqlite3.connect(writer.db_path)) as conn, conn:
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('CREATE TABLE later_wal_source (value TEXT)')
            before = self.snapshot()
            with self.assertRaises(ValueError):
                reader.get_active_campaigns()
            self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
