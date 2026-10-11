"""Actual SQLite migration/read correspondence; supplied labels are unverified."""
from contextlib import closing
import itertools
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from paw.core.network_policy import offline_policy, violations
from paw.sentinel.database import CampaignDatabase


LEGACY_FIELDS = [
    ('id', 'INTEGER PRIMARY KEY AUTOINCREMENT'), ('victim_ip', 'TEXT NOT NULL'),
    ('victim_ua', 'TEXT'), ('click_time', 'TEXT NOT NULL'),
    ('phishing_url', 'TEXT NOT NULL'), ('case_id', 'TEXT'),
    ('attacker_correlation', 'TEXT'), ('risk_score', 'INTEGER DEFAULT 0'),
    ('analyzed_status', "TEXT DEFAULT 'captured'"), ('geolocation_data', 'TEXT'),
    ('whois_data', 'TEXT'), ('related_ips', 'TEXT'), ('metadata', 'TEXT'),
    ('created_at', 'TEXT DEFAULT CURRENT_TIMESTAMP'),
    ('updated_at', 'TEXT DEFAULT CURRENT_TIMESTAMP')]
INTERACTION_FIELDS = [
    ('interaction_type', "TEXT DEFAULT 'unknown'"),
    ('interaction_confidence', 'REAL DEFAULT 0.0'),
    ('interaction_indicators', 'TEXT')]
JSON_DEFAULTS = {'attacker_correlation': {}, 'geolocation_data': {},
                 'whois_data': {}, 'related_ips': [], 'metadata': {},
                 'interaction_indicators': []}


class SentinelDatabaseRows(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='paw-sentinel-rows-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.blocked_before = len(violations())
        self.policy = offline_policy()
        self.policy.__enter__()
        self.addCleanup(self.policy.__exit__, None, None, None)

    def tearDown(self):
        self.assertEqual(len(violations()), self.blocked_before)

    def database(self, name='fresh', extra=None):
        path = self.root / (name + '.db')
        if extra is not None:
            with closing(sqlite3.connect(path)) as conn, conn:
                fields = LEGACY_FIELDS + list(extra)
                conn.execute('CREATE TABLE victim_intelligence (' +
                             ', '.join(key + ' ' + sql for key, sql in fields) + ')')
        return CampaignDatabase(str(path))

    def stored_row(self, db, identifier):
        with closing(sqlite3.connect(db.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            return dict(conn.execute('SELECT * FROM victim_intelligence WHERE id=?',
                                     (identifier,)).fetchone())

    def expected_row(self, raw):
        result = dict(raw)
        for key, default in JSON_DEFAULTS.items():
            result[key] = json.loads(raw[key]) if raw[key] else default
        return result

    def populated_row(self, db):
        identifier = db.add_victim_intelligence('192.0.2.1', 'Stored UA Ω',
            'https://example.invalid/source', case_id='source-case',
            metadata={'original': ['é', {'unknown': False}], 'nullable': None})
        db.update_victim_analysis(identifier,
            geolocation_data={'country': 'StoredCountry', 'unknown': ['Ω', 1]},
            whois_data={'source': {'raw': 'stored text'}},
            attacker_correlation={'unverified': ['192.0.2.3']},
            risk_score=6, analyzed_status='captured', related_ips=['192.0.2.2'],
            interaction_type='stored-unverified-label', interaction_confidence=0.375,
            interaction_indicators=['supplied indicator', 'é'])
        with db.connection() as conn:
            conn.execute('UPDATE victim_intelligence SET created_at=?, updated_at=? WHERE id=?',
                         ('2020-01-01T01:02:03Z', '2021-01-01T01:02:03Z', identifier))
        return identifier

    def readers(self, db, identifier):
        return {
            'id': db.get_victim_intelligence(victim_id=identifier),
            'ip': db.get_victim_intelligence(victim_ip='192.0.2.1'),
            'all': db.get_victim_intelligence(),
            'unanalyzed': db.get_unanalyzed_victims(),
            'risk': db.get_victims_by_risk_score(5),
            'country': db.get_victims_by_country('StoredCountry')}

    def test_every_reader_matches_named_storage_on_fresh_legacy_and_partial_layouts(self):
        layouts = [('fresh', None)]
        for size in range(4):
            layouts.extend((f'legacy-{size}-{i}', fields)
                           for i, fields in enumerate(itertools.permutations(INTERACTION_FIELDS, size)))
        self.assertEqual(len(layouts), 17)
        for name, fields in layouts:
            with self.subTest(layout=name):
                db = self.database(name, fields)
                identifier = self.populated_row(db)
                raw = self.stored_row(db, identifier)
                before = Path(db.db_path).read_bytes()
                for reader, records in self.readers(db, identifier).items():
                    with self.subTest(reader=reader):
                        self.assertEqual(records, [self.expected_row(raw)])
                self.assertEqual(Path(db.db_path).read_bytes(), before)
                self.assertEqual(self.stored_row(db, identifier), raw)

    def test_reopening_migrated_database_preserves_records_and_writers(self):
        db = self.database('legacy', [])
        identifier = self.populated_row(db)
        raw = self.stored_row(db, identifier)
        reopened = CampaignDatabase(db.db_path)
        self.assertEqual(reopened.get_victim_intelligence(victim_id=identifier), [self.expected_row(raw)])
        reopened.update_victim_analysis(identifier, interaction_confidence=0.0,
                                       related_ips=[], interaction_indicators=[])
        updated = self.stored_row(reopened, identifier)
        self.assertEqual(updated['metadata'], raw['metadata'])
        self.assertEqual(updated['created_at'], raw['created_at'])
        self.assertEqual(updated['interaction_confidence'], 0.0)
        for records in self.readers(reopened, identifier).values():
            self.assertEqual(records, [self.expected_row(updated)])

    def test_missing_optional_fields_have_consistent_existing_general_reader_defaults(self):
        db = self.database()
        identifier = db.add_victim_intelligence('192.0.2.1', None, 'https://example.invalid/')
        raw = self.stored_row(db, identifier)
        expected = self.expected_row(raw)
        self.assertIsNone(expected['victim_ua'])
        self.assertIsNone(expected['case_id'])
        self.assertEqual(expected['interaction_type'], 'unknown')
        self.assertEqual(expected['interaction_confidence'], 0.0)
        self.assertEqual(db.get_victim_intelligence(victim_id=identifier), [expected])
        self.assertEqual(db.get_unanalyzed_victims(), [expected])
        self.assertEqual(db.get_victims_by_risk_score(0), [expected])

    def test_sql_null_confidence_label_and_dates_are_not_replaced_with_inferences(self):
        db = self.database()
        identifier = self.populated_row(db)
        with db.connection() as conn:
            conn.execute('UPDATE victim_intelligence SET interaction_type=NULL, '
                         'interaction_confidence=NULL, created_at=NULL, updated_at=NULL WHERE id=?',
                         (identifier,))
        for records in self.readers(db, identifier).values():
            for key in ('interaction_type', 'interaction_confidence', 'created_at', 'updated_at'):
                self.assertIsNone(records[0][key])

    def test_valid_json_values_are_decoded_without_reclassifying_their_shape(self):
        db = self.database()
        identifier = self.populated_row(db)
        for supplied in (None, False, 0, 'raw claim', ['nested', {'é': None}], {}):
            with self.subTest(supplied=supplied):
                with db.connection() as conn:
                    conn.execute('UPDATE victim_intelligence SET metadata=?, interaction_indicators=? WHERE id=?',
                                 (json.dumps(supplied), json.dumps(supplied), identifier))
                for records in self.readers(db, identifier).values():
                    self.assertEqual(records[0]['metadata'], supplied)
                    self.assertEqual(records[0]['interaction_indicators'], supplied)

    def test_empty_or_malformed_json_keeps_general_reader_fallback_without_rewriting_storage(self):
        db = self.database()
        identifier = self.populated_row(db)
        for supplied in (None, '', '{broken'):
            with self.subTest(supplied=supplied):
                with db.connection() as conn:
                    for key in JSON_DEFAULTS:
                        conn.execute(f'UPDATE victim_intelligence SET {key}=? WHERE id=?', (supplied, identifier))
                raw = self.stored_row(db, identifier)
                for records in (db.get_victim_intelligence(victim_id=identifier),
                                db.get_unanalyzed_victims(), db.get_victims_by_risk_score(5)):
                    for key, default in JSON_DEFAULTS.items():
                        self.assertEqual(records[0][key], default)
                self.assertEqual(self.stored_row(db, identifier), raw)
        # Existing JSON SQL admission is separate from row decoding.
        with self.assertRaises(sqlite3.OperationalError):
            db.get_victims_by_country('StoredCountry')

    def test_existing_filters_ordering_and_limits_are_preserved(self):
        db = self.database()
        ids = [db.add_victim_intelligence('192.0.2.1' if i % 2 else '192.0.2.2',
               'Stored UA', 'https://example.invalid/') for i in range(105)]
        with db.connection() as conn:
            for i, identifier in enumerate(ids):
                conn.execute('UPDATE victim_intelligence SET click_time=?, risk_score=?, '
                    'analyzed_status=?, geolocation_data=? WHERE id=?',
                    (f'2020-01-01T00:{i // 60:02d}:{i % 60:02d}Z', i % 3,
                     'captured' if i % 2 else 'analyzed',
                     json.dumps({'country': 'Odd' if i % 2 else 'Even'}), identifier))
        self.assertEqual([row['id'] for row in db.get_victim_intelligence()], list(reversed(ids[-100:])))
        odd_ids = ids[1::2]
        self.assertEqual([row['id'] for row in db.get_victim_intelligence(victim_ip='192.0.2.1')], list(reversed(odd_ids)))
        self.assertEqual([row['id'] for row in db.get_unanalyzed_victims()], list(reversed(odd_ids[-50:])))
        self.assertEqual([row['id'] for row in db.get_unanalyzed_victims(limit=2)], list(reversed(odd_ids[-2:])))
        self.assertEqual([row['id'] for row in db.get_victims_by_country('Odd')], list(reversed(odd_ids)))
        self.assertEqual([row['id'] for row in db.get_victims_by_risk_score(2)], list(reversed(ids[2::3])))
        self.assertEqual(db.get_victim_intelligence(victim_id=9999), [])
        self.assertEqual(db.get_victims_by_country('Absent'), [])
        self.assertEqual(db.get_victims_by_risk_score(3), [])


if __name__ == '__main__':
    unittest.main()
