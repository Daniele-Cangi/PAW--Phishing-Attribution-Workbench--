"""Actual saved intelligence JSON in fresh guarded processes; no collectors."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from paw.core.network_policy import offline_policy, violations
from paw.sentinel.database import CampaignDatabase


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() if p.is_file() else None
            for p in root.rglob('*')}


def invoke(database, output, mode, case_id):
    code = """import json, sqlite3, sys
from pathlib import Path
sys.path.insert(0, %r)
from paw.core.network_policy import offline_policy, violations
with offline_policy():
    from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer
    mode = %r
    expected = {'missing': FileNotFoundError, 'corrupt': sqlite3.DatabaseError,
                'incomplete': sqlite3.OperationalError, 'pending': ValueError}.get(mode)
    try:
        analyzer = IntelligenceAnalyzer(%r, read_only=True)
        assert analyzer.ip_analyzer is None
        report = analyzer.generate_intelligence_report(%r)
    except Exception as error:
        assert expected is not None and isinstance(error, expected), repr(error)
    else:
        assert expected is None, 'unhealthy storage became a report'
        Path(%r).write_text(json.dumps(report, allow_nan=False), encoding='utf-8')
assert not violations(), violations()
for name in ('paw.sentinel.ip_analyzer', 'paw.sentinel.geographic_reports',
             'requests', 'plotly', 'pandas'):
    assert name not in sys.modules, name
print('SENTINEL_INTELLIGENCE_PASSIVE_REPORT_OK')
""" % (str(REPO), mode, str(database), case_id, str(output))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, '-X', 'utf8', '-c', code], cwd=database.parent,
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    text = result.stdout.decode('utf-8')
    assert result.returncode == 0 and 'SENTINEL_INTELLIGENCE_PASSIVE_REPORT_OK' in text, text


def main():
    checks = []
    with tempfile.TemporaryDirectory(prefix='paw-intelligence-process-') as temporary:
        root = Path(temporary)
        for mode in ('saved', 'saved-case', 'empty', 'missing', 'corrupt', 'incomplete', 'pending'):
            work = root / mode
            work.mkdir()
            database = work / 'stored # Ω %.db'
            output = root / f'{mode}-report.json'
            case_id = 'older-case' if mode == 'saved-case' else None
            source = []
            with offline_policy():
                if mode in ('saved', 'saved-case', 'empty', 'pending'):
                    writer = CampaignDatabase(str(database))
                    if mode.startswith('saved'):
                        with writer.connection() as conn:
                            for index in range(210):
                                conn.execute('INSERT INTO victim_intelligence '
                                    '(victim_ip, click_time, phishing_url, case_id, analyzed_status, '
                                    'risk_score, geolocation_data, attacker_correlation) VALUES (?,?,?,?,?,?,?,?)',
                                    ('198.51.100.2', f'{index:04}', 'https://example.invalid/stored',
                                    'older-case' if index < 105 else 'other-case', 'analyzed', 8,
                                    '{"country":"Older"}' if index < 105 else '{"country":"Other"}',
                                    '{"operator":"unverified stored claim"}'))
                            conn.execute("UPDATE victim_intelligence SET metadata=CAST(X'80' AS TEXT), "
                                "geolocation_data='{broken' WHERE id=1")
                            assert conn.execute('SELECT COUNT(*) FROM victim_intelligence').fetchone()[0] == 210
                        reader = CampaignDatabase(str(database), read_only=True)
                        identifiers = range(105, 0, -1) if case_id else range(210, 0, -1)
                        source = [reader.get_victim_intelligence(victim_id=identifier)[0]
                                  for identifier in identifiers]
                    if mode == 'pending':
                        Path(str(database) + '-journal').write_bytes(b'pending original source')
                elif mode == 'corrupt':
                    database.write_bytes(b'original corrupt source')
                elif mode == 'incomplete':
                    database.write_bytes(b'')
                assert not violations(), violations()
            before = snapshot(work)
            invoke(database, output, mode, case_id)
            assert snapshot(work) == before, mode
            if mode in ('saved', 'saved-case', 'empty'):
                report = json.loads(output.read_text(encoding='utf-8'))
                assert report['source_records'] == source
                assert report['summary']['total_victims'] == len(source)
                assert report['summary']['analyzed_victims'] == len(source)
                assert report['attacker_infrastructure'] == []
                assert report['recommendations'] == []
                assert report['summary']['high_risk_victims'] is None
                assert report['summary']['recent_victims_24h'] is None
                assert report['evidence_scope'] == 'stored_rows_unverified'
                if source:
                    expected = {'Older': 104} if case_id else {'Other': 105, 'Older': 104}
                    assert report['geographic_distribution'] == expected
                    assert report['aggregation_evidence']['geographic_distribution']['unusable_ids'] == [1]
            else:
                assert not output.exists(), mode
            checks.append({'case': mode, 'status': 'passed', 'records': len(source)})
    print(json.dumps({'status': 'passed', 'checks': checks,
        'network_scope': 'Fresh passive import/construction/read/file serialization under application offline guard; no blocked attempts or requests/collector/plot imports.',
        'evidence_scope': 'Actual SQLite and JSON, independent fixture IDs/individual lookups; stored claims are unverified, risk/attribution/recency/action unavailable.'}, indent=2))


if __name__ == '__main__':
    main()
