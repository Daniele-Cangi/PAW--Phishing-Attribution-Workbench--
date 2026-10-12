"""Actual guarded geographic CLI/API, JSON/HTML outputs and saved-source admission."""
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


def invoke(work, arguments, api=False, database=None):
    if api:
        dispatch = "from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer\n" \
            + "report = IntelligenceAnalyzer(%r, read_only=True).generate_geographic_report(output_format='json')\n" % str(database) \
            + "print('Selected stored rows: ' + str(report['total_records']))"
        bootstrap = ''
    else:
        bootstrap = 'from paw.__main__ import main\n'
        dispatch = 'sys.argv = %r\nmain()' % (['paw'] + arguments)
    code = """import sys
sys.path.insert(0, %r)
%sfrom paw.core.network_policy import offline_policy, violations
try:
    with offline_policy():
%s
finally:
    assert not violations(), violations()
    for name in ('paw.sentinel.monitor', 'paw.sentinel.ip_analyzer', 'plotly', 'pandas'):
        assert name not in sys.modules, name
    if %r:
        assert 'requests' not in sys.modules
    print('GEOGRAPHIC_PASSIVE_NO_BLOCKED_OPERATIONS')
""" % (str(REPO), bootstrap, '\n'.join('        ' + line for line in dispatch.splitlines()), api)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, '-X', 'utf8', '-c', code], cwd=work,
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    text = result.stdout.decode('utf-8')
    assert 'GEOGRAPHIC_PASSIVE_NO_BLOCKED_OPERATIONS' in text, text
    return result.returncode, text


def main():
    checks = []
    hostile = '../outside/<script>alert(1)</script>'
    scenarios = [
        ('stats', ['geographic', 'stats'], None, None, 213),
        ('old-json', ['geographic', 'report', '--case', 'older', '--output', 'json'], 'older', {'.json'}, 105),
        ('hostile-html', ['geographic', 'report', '--case', hostile, '--output', 'html'], hostile, {'.html'}, 1),
        ('both', ['geographic', 'report', '--output', 'both'], None, {'.json', '.html'}, 213),
        ('literal-empty', ['geo', 'stats', '--case', ''], '', None, 1),
        ('threshold', ['geographic', 'report', '--case', 'older', '--min-confidence', '0.5', '--output', 'json'], 'older', {'.json'}, 105),
        ('zero-stats', ['geographic', 'stats'], None, None, 0),
        ('zero-report', ['geographic', 'report', '--output', 'json'], None, {'.json'}, 0),
        ('legacy', ['geographic', 'stats'], None, None, 1),
        ('missing', ['geographic', 'stats'], None, None, None),
        ('missing-configured', ['geographic', 'report'], None, None, None),
        ('corrupt', ['geographic', 'report'], None, None, None),
        ('incomplete', ['geographic', 'report'], None, None, None),
        ('wal', ['geographic', 'stats'], None, None, None),
        ('pending', ['geographic', 'report'], None, None, None),
        ('invalid-threshold', ['geographic', 'stats', '--min-confidence', 'nan'], None, None, None),
        ('unsupported-native', ['geographic', 'report'], None, None, None),
        ('output-blocked', ['geographic', 'report'], None, None, None),
        ('map', ['geo', 'map'], None, None, None),
        ('cold-api', [], None, {'.json'}, 213)]
    with tempfile.TemporaryDirectory(prefix='paw-geographic-cli-') as temporary:
        root = Path(temporary)
        for name, arguments, case, suffixes, total in scenarios:
            work = root / name
            work.mkdir()
            database = work / 'stored # Ω %.db'
            (work / 'sentinel_config.json').write_text(json.dumps(
                {'storage': {'database_path': database.name}}), encoding='utf-8')
            source = []
            if name == 'legacy':
                with closing(sqlite3.connect(database)) as conn, conn:
                    conn.execute('CREATE TABLE victim_intelligence (' + ', '.join(
                        key + ' ' + sql for key, sql in LEGACY_FIELDS) + ')')
                    conn.execute('INSERT INTO victim_intelligence (victim_ip, click_time, phishing_url, '
                        'geolocation_data) VALUES (?,?,?,?)',
                        ('192.0.2.1', 'stored', 'https://example.invalid/', '{"lat":0,"lon":0}'))
            elif name not in ('missing', 'missing-configured', 'corrupt', 'incomplete', 'invalid-threshold', 'map'):
                writer = CampaignDatabase(str(database))
                if name not in ('zero-stats', 'zero-report'):
                    cases = ['older'] * 105 + ['', None, hostile] + ['newer'] * 105
                    with writer.connection() as conn:
                        for index, stored_case in enumerate(cases):
                            country = '<img src="https://example.invalid/pixel">' if stored_case == hostile else 'Stored'
                            conn.execute('INSERT INTO victim_intelligence (victim_ip, click_time, phishing_url, '
                                'case_id, interaction_confidence, interaction_type, geolocation_data) '
                                'VALUES (?,?,?,?,?,?,?)', ('192.0.2.1', f'{index:04}', 'https://example.invalid/',
                                stored_case, None if index == 0 else 0.8, 'attacker',
                                json.dumps({'country': country, 'lat': 0, 'lon': 0})))
                        conn.execute("UPDATE victim_intelligence SET metadata=CAST(X'80' AS TEXT) WHERE id=1")
                    if total is not None:
                        reader = CampaignDatabase(str(database), read_only=True)
                        identifiers = [i + 1 for i, value in enumerate(cases) if case is None or value == case]
                        source = [reader.get_victim_intelligence(victim_id=i)[0] for i in reversed(identifiers)]
                if name == 'wal':
                    with closing(sqlite3.connect(database)) as conn:
                        conn.execute('PRAGMA journal_mode=WAL')
                elif name == 'pending':
                    Path(str(database) + '-journal').write_bytes(b'preserved pending journal')
                elif name == 'unsupported-native':
                    with writer.connection() as conn:
                        conn.execute("UPDATE victim_intelligence SET victim_ua=X'FF' WHERE id=1")
                elif name == 'output-blocked':
                    (work / 'reports').write_bytes(b'original output blocker')
            elif name == 'corrupt':
                database.write_bytes(b'original corrupt source')
            elif name == 'incomplete':
                database.write_bytes(b'')
            if name == 'missing-configured':
                (work / 'sentinel_config.json').write_text(json.dumps(
                    {'storage': {'database_path': 'absent/source.db'}}), encoding='utf-8')
            before = snapshot(work)
            code, text = invoke(work, arguments, api=name == 'cold-api', database=database)
            if total is None:
                assert code != 0 and 'Selected stored rows:' not in text, text
                assert snapshot(work) == before, name
            else:
                assert code == 0 and f'Selected stored rows: {total}' in text, text
                assert 'Attaccanti identificati' not in text and 'Livello rischio:' not in text, text
                after = snapshot(work)
                assert all(after[key] == value for key, value in before.items()), name
                if suffixes is None:
                    assert after == before, name
                else:
                    additions = set(after) - set(before)
                    files = [work / key for key in additions if after[key] is not None]
                    assert {p.suffix for p in files} == suffixes and len(files) == len(suffixes), additions
                    assert all(p.parent == work / 'reports' / 'geographic' for p in files)
                    for path in files:
                        output = path.read_text(encoding='utf-8')
                        if path.suffix == '.json':
                            report = json.loads(output)
                            assert report['source_records'] == source
                            assert report['total_records'] == total
                            expected_included = total - 1 if name == 'threshold' else total
                            assert report['total_victims'] == expected_included
                            assert len(report['geographic_stats']['coordinates']) == expected_included
                            assert report['summary']['risk_assessment']['level'] is None
                            if name == 'threshold':
                                assert report['selection']['confidence_unusable_ids'] == [1]
                        else:
                            assert '<script' not in output.lower() and '<img' not in output.lower()
                            assert 'Content-Security-Policy' in output
                            if name == 'hostile-html':
                                assert '&lt;img' in output and '&lt;script' in output
            checks.append({'case': name, 'exit_code': code, 'source_tree_unchanged': True,
                           'selected_records': total})
    print(json.dumps({'status': 'passed', 'checks': checks,
        'network_scope': 'Actual guarded CLI after bootstrap; API cold import fully guarded, zero blocked attempts, no collector/plot imports.',
        'output_scope': 'Actual requested JSON/escaped static HTML only; selected source rows and original storage retained. No browser/map execution or authenticity/identity/risk claim.'}, indent=2))


if __name__ == '__main__':
    main()
