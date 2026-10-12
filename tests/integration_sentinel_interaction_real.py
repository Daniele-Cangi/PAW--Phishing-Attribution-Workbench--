"""Fresh actual interaction API reads and JSON serialization, without collectors."""
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


def invoke(database, output, mode, case):
    code = """import json,sqlite3,sys
from pathlib import Path
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
with offline_policy():
    from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer
    mode=%r
    expected={'missing':FileNotFoundError,'corrupt':sqlite3.DatabaseError,
              'incomplete':sqlite3.OperationalError,'pending':ValueError,'wal':ValueError,
              'native':TypeError,'invalid-confidence':ValueError}.get(mode)
    try:
        reader=IntelligenceAnalyzer(%r,read_only=True)
        assert reader.ip_analyzer is None
        stats=reader.get_interaction_statistics(%r)
        candidates=reader.get_potential_attacker_interactions(%r,
            min_confidence=float('nan') if mode=='invalid-confidence' else 0.6)
    except Exception as error:
        assert expected is not None and isinstance(error,expected),repr(error)
    else:
        assert expected is None,'Unhealthy source became successful observations'
        Path(%r).write_text(json.dumps({'stats':stats,'candidates':candidates},
                            ensure_ascii=True,allow_nan=False),encoding='utf-8')
assert not violations(),violations()
for name in ('requests','paw.sentinel.ip_analyzer','paw.sentinel.monitor',
             'paw.sentinel.geographic_reports','plotly','pandas'):
    assert name not in sys.modules,name
print('STORED_INTERACTION_PASSIVE_OK')
""" % (str(REPO), mode, str(database), case, case, str(output))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, '-X', 'utf8', '-c', code], cwd=database.parent,
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    text = result.stdout.decode('utf-8')
    assert result.returncode == 0 and 'STORED_INTERACTION_PASSIVE_OK' in text, text


def main():
    cases = ['older'] * 105 + ['', None, "case' OR 1=1 --"] + ['newer'] * 105
    checks = []
    with tempfile.TemporaryDirectory(prefix='paw-interaction-process-') as temporary:
        root = Path(temporary)
        for mode, case in (('all', None), ('older', 'older'), ('empty-case', ''),
                ('quoted-case', "case' OR 1=1 --"), ('absent-case', 'absent'), ('zero', None),
                ('legacy', None), ('missing', None), ('corrupt', None), ('incomplete', None),
                ('pending', None), ('wal', None), ('native', None), ('invalid-confidence', None)):
            work = root / mode
            work.mkdir()
            database = work / 'stored # Ω %.db'
            output = root / (mode + '.json')
            expected_sources, expected_candidates = [], []
            if mode == 'legacy':
                with closing(sqlite3.connect(database)) as conn, conn:
                    conn.execute('CREATE TABLE victim_intelligence (' + ', '.join(
                        key + ' ' + sql for key, sql in LEGACY_FIELDS) + ')')
                    conn.execute('INSERT INTO victim_intelligence (victim_ip,click_time,phishing_url) '
                        'VALUES (?,?,?)', ('192.0.2.1', 'stored', 'https://example.invalid/'))
                expected_sources = CampaignDatabase(str(database), read_only=True).get_victim_intelligence(victim_id=1)
            elif mode not in ('missing', 'corrupt', 'incomplete'):
                writer = CampaignDatabase(str(database))
                if mode != 'zero':
                    with writer.connection() as conn:
                        for index, stored_case in enumerate(cases):
                            label = 'custom' if index % 5 == 0 else 'potential_attacker'
                            confidence = None if index == 0 else (0.6, 0.7, 0.8, 1)[index % 4]
                            conn.execute('INSERT INTO victim_intelligence (victim_ip,click_time,phishing_url,'
                                'case_id,interaction_type,interaction_confidence) VALUES (?,?,?,?,?,?)',
                                ('192.0.2.1', f'{index:04}', 'https://example.invalid/', stored_case, label, confidence))
                        conn.execute("UPDATE victim_intelligence SET metadata=CAST(X'80' AS TEXT), "
                                     "interaction_indicators='{broken' WHERE id=1")
                    reader = CampaignDatabase(str(database), read_only=True)
                    ids = [i + 1 for i, value in reversed(list(enumerate(cases))) if case is None or case == value]
                    expected_sources = [reader.get_victim_intelligence(victim_id=i)[0] for i in ids]
                    expected_candidates = sorted([r for r in expected_sources if r['interaction_type'] != 'custom'],
                        key=lambda r: r['interaction_confidence'], reverse=True)
                if mode == 'pending':
                    Path(str(database) + '-journal').write_bytes(b'original pending journal')
                elif mode == 'wal':
                    with closing(sqlite3.connect(database)) as conn:
                        conn.execute('PRAGMA journal_mode=WAL')
                elif mode == 'native':
                    with writer.connection() as conn:
                        conn.execute("UPDATE victim_intelligence SET victim_ua=X'FF' WHERE id=1")
            elif mode == 'corrupt':
                database.write_bytes(b'original corrupt source')
            elif mode == 'incomplete':
                database.write_bytes(b'')
            before = snapshot(work)
            invoke(database, output, mode, case)
            assert snapshot(work) == before, mode
            if mode in ('missing', 'corrupt', 'incomplete', 'pending', 'wal', 'native', 'invalid-confidence'):
                assert not output.exists(), mode
                checks.append({'case': mode, 'source_tree_unchanged': True, 'result': 'explicit_error'})
                continue
            saved = json.loads(output.read_text(encoding='utf-8'))
            stats, candidates = saved['stats'], saved['candidates']
            assert stats['source_records'] == expected_sources
            assert stats['total_interactions'] == len(expected_sources)
            assert [r['source_record'] for r in candidates] == expected_candidates
            assert stats['high_confidence_attacker_interactions'] is None
            assert stats['suspicious_interactions'] is None and stats['potential_attacker_ips'] == []
            assert all(not r['verified'] and r['unavailable']['identity'] for r in candidates)
            expected_high = sum(1 for r in expected_candidates if r['interaction_confidence'] >= 0.7)
            assert stats['stored_candidate_score_at_least_0_7'] == expected_high
            checks.append({'case': mode, 'source_tree_unchanged': True,
                'records': len(expected_sources), 'stored_label_candidates': len(expected_candidates)})
    print(json.dumps({'status': 'passed', 'checks': checks,
        'network_scope': 'Cold API import, passive construction/read and JSON serialization under application offline guard; zero blocked attempts, no collectors.',
        'evidence_scope': 'Actual SQLite fixtures and JSON, complete source comparisons and literal selections; no identity, accuracy or OS isolation attestation.'}, indent=2))


if __name__ == '__main__':
    main()
