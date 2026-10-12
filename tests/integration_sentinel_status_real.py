"""Actual passive CLI status: stored counts, unknown runtime, unchanged sources."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile

from integration_sentinel_passive_real import invoke, snapshot, CampaignDatabase


def main():
    checks = []
    with tempfile.TemporaryDirectory(prefix='paw-sentinel-status-cli-') as temporary:
        root = Path(temporary)
        for name in ('populated', 'zero', 'legacy', 'missing-default', 'missing-configured',
                     'corrupt', 'empty-file', 'missing-alerts', 'wal', 'journal'):
            work = root / name
            work.mkdir()
            database = work / 'sentinel.db'
            if name == 'missing-configured':
                (work / 'sentinel_config.json').write_text(json.dumps(
                    {'storage': {'database_path': 'absent/target.db'}}), encoding='utf-8')
            elif name in ('populated', 'zero', 'legacy', 'missing-alerts', 'wal', 'journal'):
                if name == 'populated':
                    database = work / 'stored # Ω %.db'
                    (work / 'sentinel_config.json').write_text(json.dumps(
                        {'storage': {'database_path': database.name}}), encoding='utf-8')
                writer = CampaignDatabase(str(database))
                if name != 'zero':
                    active = writer.add_campaign('stored-active', 'https://example.invalid/stored')
                    removed = writer.add_campaign('stored-removed', 'https://example.invalid/stored')
                    writer.update_campaign_status(removed, 'removed')
                    for message in ('old', 'recent', 'acknowledged'):
                        writer.record_alert(active, 'stored', message)
                    with writer.connection() as conn:
                        conn.execute("UPDATE alerts SET alert_time='2000-01-01' WHERE message='old'")
                        conn.execute("UPDATE alerts SET acknowledged=1 WHERE message='acknowledged'")
                        conn.execute("UPDATE alerts SET metadata=CAST(X'80' AS TEXT)")
                if name == 'legacy':
                    with closing(sqlite3.connect(database)) as conn, conn:
                        conn.execute('DROP TABLE victim_intelligence')
                elif name == 'missing-alerts':
                    with closing(sqlite3.connect(database)) as conn, conn:
                        conn.execute('DROP TABLE alerts')
                elif name == 'wal':
                    with closing(sqlite3.connect(database)) as conn:
                        conn.execute('PRAGMA journal_mode=WAL')
                elif name == 'journal':
                    Path(str(database) + '-journal').write_bytes(b'preserved pending source')
            elif name == 'corrupt':
                database.write_bytes(b'original damaged source')
            elif name == 'empty-file':
                with closing(sqlite3.connect(database)):
                    pass
            before = snapshot(work)
            code, text = invoke(work, 'status')
            if name in ('populated', 'zero', 'legacy'):
                assert code == 0, text
                assert 'Running: unknown (not observed by this command)' in text, text
                total, active_count, alerts = (0, 0, 0) if name == 'zero' else (2, 1, 2)
                for line in (f'Total campaigns: {total}', f'Active campaigns: {active_count}',
                             f'Unacknowledged alerts: {alerts}'):
                    assert line in text, text
                assert 'Running: False' not in text and 'Running: True' not in text, text
            else:
                assert code != 0, text
                assert 'Sentinel Status' not in text and 'campaigns: 0' not in text, text
            assert snapshot(work) == before, name
            checks.append({'case': name, 'exit_code': code, 'source_tree_unchanged': True})
    print(json.dumps({'status': 'passed', 'checks': checks,
        'network_scope': 'Actual status after CLI bootstrap; guarded dispatch with zero blocked operations and no monitoring/enrichment imports',
        'runtime_scope': 'Unobserved service state is unknown; stored counts do not prove service activity'}, indent=2))


if __name__ == '__main__':
    main()
