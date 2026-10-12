"""Cold stored filter/statistics APIs, actual SQLite/JSON and source preservation."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from paw.sentinel.database import CampaignDatabase
from test_sentinel_database_rows import LEGACY_FIELDS


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() if p.is_file() else None
            for p in root.rglob('*')}


def invoke(database, output, mode):
    code = """import json,sqlite3,sys
from pathlib import Path
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
with offline_policy():
    from paw.sentinel.database import CampaignDatabase
    mode=%r
    expected={'missing':FileNotFoundError,'corrupt':sqlite3.DatabaseError,
       'incomplete':sqlite3.OperationalError,'pending':ValueError,'wal':ValueError,
       'native-blob':TypeError,'native-nonfinite':ValueError,
       'invalid-country':ValueError,'invalid-score':ValueError}.get(mode)
    try:
        reader=CampaignDatabase(%r,read_only=True)
        if mode=='invalid-country': reader.get_victims_by_country(False)
        if mode=='invalid-score': reader.get_victims_by_risk_score(float('nan'))
        stats=reader.get_victim_statistics()
        country=reader.get_victims_by_country('A,B')
        score=reader.get_victims_by_risk_score(5)
        try: reader.get_attacker_correlations()
        except RuntimeError as error:
            assert 'correlations are unavailable' in str(error),str(error)
        else: raise AssertionError('Unsupported infrastructure claim became available')
    except Exception as error:
        assert expected is not None and isinstance(error,expected),repr(error)
    else:
        assert expected is None,'Unhealthy source became successful observations'
        Path(%r).write_text(json.dumps({'stats':stats,'country':country,'score':score},
            ensure_ascii=True,allow_nan=False),encoding='utf-8')
assert not violations(),violations()
for name in ('requests','paw.sentinel.ip_analyzer','paw.sentinel.monitor',
             'paw.sentinel.geographic_reports','plotly','pandas'):
    assert name not in sys.modules,name
print('STORED_FILTERS_PASSIVE_OK')
""" % (str(REPO), mode, str(database), str(output))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, '-X', 'utf8', '-c', code], cwd=database.parent,
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    text = result.stdout.decode('utf-8')
    assert result.returncode == 0 and 'STORED_FILTERS_PASSIVE_OK' in text, text


def main():
    checks = []
    with tempfile.TemporaryDirectory(prefix='paw-stored-filters-process-') as temporary:
        root = Path(temporary)
        for mode in ('saved', 'empty', 'legacy', 'missing', 'corrupt', 'incomplete', 'pending',
                     'wal', 'native-blob', 'native-nonfinite', 'invalid-country', 'invalid-score'):
            work = root / mode
            work.mkdir()
            database = work / 'stored # Ω %.db'
            output = root / (mode + '.json')
            sources, country_sources, score_sources = [], [], []
            if mode == 'legacy':
                with closing(sqlite3.connect(database)) as conn, conn:
                    conn.execute('CREATE TABLE victim_intelligence (' + ', '.join(
                        key + ' ' + sql for key, sql in LEGACY_FIELDS) + ')')
                    conn.execute('INSERT INTO victim_intelligence (victim_ip,click_time,phishing_url,risk_score,'
                        'geolocation_data,metadata) VALUES (?,?,?,?,?,CAST(? AS TEXT))',
                        ('192.0.2.1', 'not-a-date', 'https://example.invalid/', 7, '{"country":"A,B"}', b'\x80'))
                sources = CampaignDatabase(str(database), read_only=True).get_victim_intelligence(victim_id=1)
                country_sources = score_sources = sources
            elif mode not in ('missing', 'corrupt', 'incomplete'):
                writer = CampaignDatabase(str(database))
                if mode != 'empty':
                    with writer.connection() as conn:
                        for index in range(213):
                            conn.execute('INSERT INTO victim_intelligence (victim_ip,click_time,phishing_url,'
                                'risk_score,analyzed_status,geolocation_data) VALUES (?,?,?,?,?,?)',
                                ('192.0.2.1', 'not-a-date', 'https://example.invalid/', 7,
                                 'analyzed', '{"country":"A,B"}'))
                        conn.execute("UPDATE victim_intelligence SET metadata=CAST(X'80' AS TEXT), "
                                     "geolocation_data='{broken' WHERE id=1")
                        conn.execute('UPDATE victim_intelligence SET geolocation_data=? WHERE id=2',
                                     ('{"country":"First","country":"A,B"}',))
                        conn.execute("UPDATE victim_intelligence SET risk_score='bogus' WHERE id=3")
                        conn.execute('UPDATE victim_intelligence SET risk_score=NULL WHERE id=4')
                        conn.execute('UPDATE victim_intelligence SET risk_score=-1,analyzed_status=NULL WHERE id=5')
                    reader = CampaignDatabase(str(database), read_only=True)
                    sources = [reader.get_victim_intelligence(victim_id=i)[0] for i in range(213, 0, -1)]
                    country_sources = sources[:-2]
                    score_sources = [r for r in sources if r['id'] not in (3, 4, 5)]
                if mode == 'pending':
                    Path(str(database) + '-journal').write_bytes(b'original pending journal')
                elif mode == 'wal':
                    with closing(sqlite3.connect(database)) as conn:
                        conn.execute('PRAGMA journal_mode=WAL')
                elif mode in ('native-blob', 'native-nonfinite'):
                    with writer.connection() as conn:
                        if mode == 'native-blob': conn.execute("UPDATE victim_intelligence SET victim_ua=X'FF' WHERE id=1")
                        else: conn.execute('UPDATE victim_intelligence SET risk_score=? WHERE id=1', (float('inf'),))
            elif mode == 'corrupt':
                database.write_bytes(b'original corrupt source')
            elif mode == 'incomplete':
                database.write_bytes(b'')
            before = snapshot(work)
            invoke(database, output, mode)
            assert snapshot(work) == before, mode
            if mode not in ('saved', 'empty', 'legacy'):
                assert not output.exists(), mode
                checks.append({'case': mode, 'source_tree_unchanged': True, 'result': 'explicit_error'})
                continue
            saved = json.loads(output.read_text(encoding='utf-8'))
            assert saved['stats']['source_records'] == sources
            assert saved['country'] == country_sources and saved['score'] == score_sources
            assert saved['stats']['total_victims'] == len(sources)
            assert saved['stats']['recent_victims_24h'] is None
            assert saved['stats']['unavailable']['risk_assessment']
            if mode == 'saved':
                assert saved['stats']['aggregation_evidence']['risk_distribution']['unusable_ids'] == [4, 3]
                assert saved['stats']['aggregation_evidence']['risk_distribution']['nonpositive_ids'] == [5]
                assert saved['stats']['risk_distribution'] == {'7': 210}
            checks.append({'case': mode, 'source_tree_unchanged': True,
                'source_rows': len(sources), 'country_rows': len(country_sources), 'numeric_score_rows': len(score_sources)})
    print(json.dumps({'status': 'passed', 'checks': checks,
        'network_scope': 'Actual cold passive API import/read/JSON under Python offline guard; zero blocked operations, no collectors.',
        'evidence_scope': 'Stored fixtures, complete source equality, typed interpretation and unavailable recency/identity/correlation; no accuracy or OS isolation attestation.'}, indent=2))


if __name__ == '__main__':
    main()
