"""Actual SQLite stored-number/country selectors and honest statistics boundaries."""
from contextlib import closing
import itertools
import json
from pathlib import Path
import sqlite3
import unittest

from paw.sentinel.database import CampaignDatabase
import test_sentinel_database_rows as rows


class SentinelStoredFilters(unittest.TestCase):
    setUp = rows.SentinelDatabaseRows.setUp
    tearDown = rows.SentinelDatabaseRows.tearDown
    database = rows.SentinelDatabaseRows.database

    def add(self, writer, geo=None, score=5, status='analyzed', click='not-a-date'):
        identifier = writer.add_victim_intelligence('192.0.2.1', 'Stored UA Ω', 'https://example.invalid/')
        with writer.connection() as conn:
            conn.execute('UPDATE victim_intelligence SET geolocation_data=?,risk_score=?,analyzed_status=?,click_time=? WHERE id=?',
                         (geo, score, status, click, identifier))
        return identifier

    def test_malformed_ambiguous_and_nonstring_geography_never_hide_valid_neighbors(self):
        writer = self.database()
        raw_values = ['{"country":"A,B"}', '{broken', '{"country":"First","country":"A,B"}',
            'null', '[]', '{"country":1}', '{"country":"A,B","lat":NaN}', '', None,
            '{"country":" A,B "}', b'{"country":"A,B"}', b'\xff']
        for raw in raw_values:
            self.add(writer, raw)
        reader = CampaignDatabase(writer.db_path, read_only=True)
        before = Path(writer.db_path).read_bytes()
        selected = reader.get_victims_by_country('A,B')
        self.assertEqual([r['id'] for r in selected], [11, 1])
        for record in selected:
            self.assertEqual(record, reader.get_victim_intelligence(victim_id=record['id'])[0])
        self.assertEqual(reader.get_victims_by_country('First'), [])
        self.assertEqual(reader.get_victims_by_country('a,b'), [])
        self.assertEqual([r['id'] for r in reader.get_victims_by_country(' A,B ')], [10])
        sources = reader.get_victim_statistics()['source_records']
        self.assertEqual(len(sources), len(raw_values))
        self.assertEqual(sources[-2]['json_evidence']['fields']['geolocation_data']['status'], 'invalid_json')
        self.assertEqual(sources[-3]['json_evidence']['fields']['geolocation_data']['status'], 'duplicate_keys')
        self.assertEqual(Path(writer.db_path).read_bytes(), before)

    def test_score_filters_use_numeric_values_without_sql_type_ranking_and_stable_ties(self):
        writer = self.database()
        scores = [5, 'bogus', None, -1, 0, 8, 5.5, 5]
        for score in scores:
            self.add(writer, score=score)
        reader = CampaignDatabase(writer.db_path, read_only=True)
        self.assertEqual([r['id'] for r in reader.get_victims_by_risk_score()], [6, 7, 8, 1])
        self.assertEqual([r['id'] for r in reader.get_victims_by_risk_score(0)], [6, 7, 8, 1, 5])
        self.assertEqual([r['id'] for r in reader.get_victims_by_risk_score(-1)], [6, 7, 8, 1, 5, 4])
        self.assertEqual(reader.get_victims_by_risk_score(10**400), [])
        for invalid in (True, None, '5', float('nan'), float('inf'), -float('inf')):
            with self.assertRaises(ValueError):
                reader.get_victims_by_risk_score(invalid)
        for invalid in (True, 1, None, '', '  ', [], {}):
            with self.assertRaises(ValueError):
                reader.get_victims_by_country(invalid)
        for value in (float('inf'), b'\xff'):
            with writer.connection() as conn:
                conn.execute('UPDATE victim_intelligence SET risk_score=? WHERE id=2', (value,))
            self.assertEqual([r['id'] for r in reader.get_victims_by_risk_score()], [6, 7, 8, 1])

    def test_statistics_preserve_all_sources_and_traceable_descriptive_omissions(self):
        writer = self.database()
        for score, status in ((5, 'analyzed'), ('bogus', None), (None, ''), (-1, 'null'), (0, 'captured'), (8, 'analyzed')):
            self.add(writer, '{broken', score, status)
        reader = CampaignDatabase(writer.db_path, read_only=True)
        before = Path(writer.db_path).read_bytes()
        report = reader.get_victim_statistics()
        self.assertEqual([r['id'] for r in report['source_records']], [6, 5, 4, 3, 2, 1])
        self.assertEqual(report['status_breakdown'], {'analyzed': 2, 'captured': 1, 'null': 1, '': 1})
        self.assertEqual(report['risk_distribution'], {'8': 1, '5': 1})
        self.assertEqual(report['aggregation_evidence']['risk_distribution']['source_ids'], {'8': [6], '5': [1]})
        self.assertEqual(report['aggregation_evidence']['risk_distribution']['unusable_ids'], [3, 2])
        self.assertEqual(report['aggregation_evidence']['risk_distribution']['nonpositive_ids'], [5, 4])
        self.assertEqual(report['aggregation_evidence']['status_breakdown']['unusable_ids'], [2])
        self.assertIsNone(report['recent_victims_24h'])
        self.assertTrue(report['unavailable']['identity'])
        self.assertEqual(report['evidence_scope'], 'stored_rows_unverified')
        self.assertEqual(json.loads(json.dumps(report, allow_nan=False)), report)
        self.assertEqual(Path(writer.db_path).read_bytes(), before)
        self.assertEqual({p.name for p in self.root.iterdir()}, {'fresh.db'})

    def test_legacy_partial_layouts_and_actual_json_keep_typed_original_sources(self):
        for index, fields in enumerate(fields for size in range(4)
                for fields in itertools.permutations(rows.INTERACTION_FIELDS, size)):
            path = self.root / f'legacy-{index}.db'
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.execute('CREATE TABLE victim_intelligence (' + ', '.join(
                    key + ' ' + sql for key, sql in rows.LEGACY_FIELDS + list(fields)) + ')')
                conn.execute('INSERT INTO victim_intelligence (victim_ip,click_time,phishing_url,risk_score,geolocation_data,metadata) '
                    'VALUES (?,?,?,?,?,CAST(? AS TEXT))', ('192.0.2.1', 'not-a-date', 'https://example.invalid/', 7,
                                                        '{"country":"A,B"}', b'\x80'))
            reader = CampaignDatabase(str(path), read_only=True)
            before = path.read_bytes()
            sources = reader.get_victim_intelligence(victim_id=1)
            self.assertEqual(reader.get_victims_by_country('A,B'), sources)
            self.assertEqual(reader.get_victims_by_risk_score(), sources)
            report = reader.get_victim_statistics()
            self.assertEqual(report['source_records'], sources)
            self.assertEqual(report['source_records'][0]['json_evidence']['fields']['metadata']['status'], 'invalid_encoding')
            output = self.root / f'legacy-{index}.json'
            output.write_text(json.dumps(report, ensure_ascii=True, allow_nan=False), encoding='utf-8')
            self.assertEqual(json.loads(output.read_text(encoding='utf-8'))['source_records'], sources)
            self.assertEqual(path.read_bytes(), before)

    def test_empty_unhealthy_sources_later_journal_and_unsupported_native_statistics(self):
        writer = self.database()
        reader = CampaignDatabase(writer.db_path, read_only=True)
        self.assertEqual(reader.get_victim_statistics()['total_victims'], 0)
        self.assertEqual(reader.get_victims_by_country('Stored'), [])
        self.assertEqual(reader.get_victims_by_risk_score(), [])
        self.add(writer, '{"country":"Stored"}')
        for field, value, error in (('risk_score', float('inf'), ValueError), ('victim_ua', b'\xff', TypeError)):
            with writer.connection() as conn:
                conn.execute('UPDATE victim_intelligence SET risk_score=5,victim_ua=?', ('stored',))
                conn.execute(f'UPDATE victim_intelligence SET {field}=?', (value,))
            before = Path(writer.db_path).read_bytes()
            with self.assertRaises(error):
                reader.get_victim_statistics()
            # List selectors retain raw matched values; they are not JSON publishers.
            self.assertEqual(reader.get_victims_by_country('Stored')[0][field], value)
            self.assertEqual(Path(writer.db_path).read_bytes(), before)
        journal = Path(writer.db_path + '-journal')
        journal.write_bytes(b'original pending journal')
        for read in (reader.get_victim_statistics, reader.get_victims_by_risk_score,
                     lambda: reader.get_victims_by_country('Stored')):
            with self.assertRaises(ValueError):
                read()
        self.assertEqual(journal.read_bytes(), b'original pending journal')

    def test_correlation_unavailability_precedes_any_storage_read_and_keeps_original_claims(self):
        writer = self.database()
        for index in range(6):
            self.add(writer, '{"country":"A,B"}')
        reader = CampaignDatabase(writer.db_path, read_only=True)
        before = Path(writer.db_path).read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'correlations are unavailable'):
            reader.get_attacker_correlations()
        self.assertEqual(len(reader.get_forensic_victim_intelligence()), 6)
        self.assertEqual(Path(writer.db_path).read_bytes(), before)
        Path(writer.db_path).unlink()
        with self.assertRaisesRegex(RuntimeError, 'correlations are unavailable'):
            reader.get_attacker_correlations()
        self.assertFalse(Path(writer.db_path).exists())


if __name__ == '__main__':
    unittest.main()
