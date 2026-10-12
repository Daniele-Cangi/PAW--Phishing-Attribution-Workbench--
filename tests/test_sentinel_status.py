"""Actual stored counts and explicit instance-flag scope, without collectors."""
from contextlib import closing
from pathlib import Path
import sqlite3
import unittest

from paw.sentinel.config import SentinelConfig
from paw.sentinel.database import CampaignDatabase
from paw.sentinel.monitor import SentinelMonitor
import test_sentinel_database_rows as source_rows


class SentinelStatus(unittest.TestCase):
    setUp = source_rows.SentinelDatabaseRows.setUp
    tearDown = source_rows.SentinelDatabaseRows.tearDown
    database = source_rows.SentinelDatabaseRows.database

    def populated(self):
        writer = self.database()
        for case, status in [('active', 'active'), ('inactive', 'inactive'),
                             ('removed', 'removed'), ('unknown', None)]:
            campaign = writer.add_campaign(case, 'https://example.invalid/stored')
            writer.update_campaign_status(campaign, status)
            if case == 'active':
                self.active = campaign
        for message in ('old-unacknowledged', 'new-unacknowledged', 'acknowledged', 'unknown-ack'):
            writer.record_alert(self.active, 'stored', message)
        with writer.connection() as conn:
            conn.execute("UPDATE alerts SET alert_time='2000-01-01' WHERE message='old-unacknowledged'")
            conn.execute("UPDATE alerts SET acknowledged=1 WHERE message='acknowledged'")
            conn.execute("UPDATE alerts SET acknowledged=NULL WHERE message='unknown-ack'")
            # Counting does not need JSON/message decoding or claim validation.
            conn.execute("UPDATE alerts SET metadata=CAST(X'80' AS TEXT)")
            conn.execute("UPDATE campaigns SET metadata='{broken'")
        return writer, CampaignDatabase(writer.db_path, read_only=True)

    def test_actual_counts_include_all_campaign_states_and_old_unacknowledged_alerts(self):
        writer, reader = self.populated()
        before = Path(writer.db_path).read_bytes()
        expected = {'total_campaigns': 4, 'active_campaigns': 1, 'unacknowledged_alerts': 2}
        self.assertEqual(reader.get_monitor_statistics(), expected)
        self.assertEqual(reader.get_monitor_statistics(), expected)
        self.assertEqual(Path(writer.db_path).read_bytes(), before)
        with writer.connection() as conn:
            conn.execute('UPDATE alerts SET acknowledged=1 WHERE acknowledged=0')
            conn.execute("UPDATE campaigns SET status='inactive' WHERE status='active'")
        before = Path(writer.db_path).read_bytes()
        self.assertEqual(reader.get_monitor_statistics(), {
            'total_campaigns': 4, 'active_campaigns': 0, 'unacknowledged_alerts': 0})
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_zero_counts_require_existing_empty_tables(self):
        writer = self.database()
        before = Path(writer.db_path).read_bytes()
        reader = CampaignDatabase(writer.db_path, read_only=True)
        self.assertEqual(reader.get_monitor_statistics(), {
            'total_campaigns': 0, 'active_campaigns': 0, 'unacknowledged_alerts': 0})
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_missing_required_tables_or_columns_do_not_become_zero_counts(self):
        schemas = [[], ['CREATE TABLE campaigns (status TEXT)'],
                   ['CREATE TABLE campaigns (status TEXT)', 'CREATE TABLE alerts (message TEXT)'],
                   ['CREATE TABLE campaigns (id TEXT)', 'CREATE TABLE alerts (acknowledged INTEGER)']]
        for index, schema in enumerate(schemas):
            with self.subTest(schema=schema):
                path = self.root / f'incomplete-{index}.db'
                with closing(sqlite3.connect(path)) as conn, conn:
                    for statement in schema:
                        conn.execute(statement)
                before = path.read_bytes()
                reader = CampaignDatabase(str(path), read_only=True)
                with self.assertRaises(sqlite3.OperationalError):
                    reader.get_monitor_statistics()
                self.assertEqual(path.read_bytes(), before)

    def test_instance_statistics_use_actual_counts_and_label_the_local_flag_scope(self):
        writer, reader = self.populated()
        before = Path(writer.db_path).read_bytes()
        monitor = SentinelMonitor(SentinelConfig(str(self.root / 'missing-config.json')), reader)
        self.assertEqual(monitor.get_stats(), {
            'total_campaigns': 4, 'active_campaigns': 1, 'unacknowledged_alerts': 2,
            'is_running': False, 'is_running_scope': 'this_instance_flag'})
        self.assertIsNone(monitor._thread)
        self.assertIsNone(monitor._executor)
        self.assertFalse((self.root / 'missing-config.json').exists())
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_statistics_recheck_pending_journal_admission(self):
        writer = self.database()
        reader = CampaignDatabase(writer.db_path, read_only=True)
        journal = Path(writer.db_path + '-journal')
        journal.write_bytes(b'preserved unsupported pending storage')
        before = Path(writer.db_path).read_bytes()
        with self.assertRaises(ValueError):
            reader.get_monitor_statistics()
        self.assertEqual(Path(writer.db_path).read_bytes(), before)
        self.assertEqual(journal.read_bytes(), b'preserved unsupported pending storage')


if __name__ == '__main__':
    unittest.main()
