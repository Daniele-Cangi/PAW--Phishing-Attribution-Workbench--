"""Fresh-process saved export with no collectors, plus default writer admission."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from paw.sentinel.database import CampaignDatabase
from paw.core.network_policy import offline_policy, violations


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() if p.is_file() else None
            for p in root.rglob('*')}


def invoke(database, output, mode, case_id=None):
    code = """import json, sys
from pathlib import Path
sys.path.insert(0, %r)
mode = %r
if mode == 'writer':
    import requests  # Common active-dependency bootstrap before the guard.
from paw.core.network_policy import offline_policy, violations
try:
    with offline_policy():
        from paw.sentinel.intelligence_analyzer import IntelligenceAnalyzer
        if mode == 'missing':
            try:
                IntelligenceAnalyzer(%r, read_only=True)
            except FileNotFoundError:
                pass
            else:
                raise AssertionError('missing source became healthy storage')
        else:
            analyzer = IntelligenceAnalyzer(%r, use_proxy=False, read_only=mode != 'writer')
            assert analyzer.db.read_only == (mode != 'writer')
            if mode == 'writer':
                assert analyzer.ip_analyzer is not None
            else:
                assert analyzer.ip_analyzer is None
            report = analyzer.export_forensic_data(%r)
            Path(%r).write_text(json.dumps(report, allow_nan=False), encoding='utf-8')
finally:
    assert not violations(), violations()
    for name in ('geographic_reports',):
        assert 'paw.sentinel.' + name not in sys.modules, name
    for name in ('plotly', 'pandas'):
        assert name not in sys.modules, name
    if mode != 'writer':
        assert 'paw.sentinel.ip_analyzer' not in sys.modules
        assert 'requests' not in sys.modules
print('SENTINEL_EXPORT_NO_BLOCKED_OPERATIONS')
""" % (str(REPO), mode, str(database), str(database), case_id, str(output))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, '-X', 'utf8', '-c', code], cwd=database.parent,
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    text = result.stdout.decode('utf-8')
    assert result.returncode == 0 and 'SENTINEL_EXPORT_NO_BLOCKED_OPERATIONS' in text, text


def main():
    checks = []
    with tempfile.TemporaryDirectory(prefix='paw-export-process-') as temporary:
        root = Path(temporary)
        for mode in ('saved', 'saved-case', 'missing', 'writer'):
            work = root / mode
            work.mkdir()
            database = work / 'stored # Ω %.db'
            output = root / f'{mode}-export.json'
            source = []
            case_id = 'older-case' if mode == 'saved-case' else None
            if mode.startswith('saved'):
                with offline_policy():
                    writer = CampaignDatabase(str(database))
                    with writer.connection() as conn:
                        for index in range(210):
                            conn.execute('INSERT INTO victim_intelligence '
                                '(victim_ip, victim_ua, click_time, phishing_url, case_id) '
                                'VALUES (?,?,?,?,?)', ('192.0.2.1', 'stored UA Ω', f'{index:04}',
                                'https://example.invalid/stored', 'older-case' if index < 105 else 'newer-case'))
                        conn.execute("UPDATE victim_intelligence SET metadata=CAST(X'80' AS TEXT) WHERE id=1")
                        assert conn.execute('SELECT COUNT(*) FROM victim_intelligence').fetchone()[0] == 210
                    # Independent fixture IDs and single-row lookups avoid an
                    # oracle that could share the export's listing truncation.
                    identifiers = range(105, 0, -1) if case_id else range(210, 0, -1)
                    reader = CampaignDatabase(str(database), read_only=True)
                    source = [reader.get_victim_intelligence(victim_id=identifier)[0]
                              for identifier in identifiers]
                    assert len(reader.get_victim_intelligence()) == 100
                    assert not violations(), violations()
            before = snapshot(work)
            invoke(database, output, mode, case_id)
            if mode != 'writer':
                assert snapshot(work) == before, mode
            else:
                assert set(snapshot(work)) == {database.name}
            if mode == 'missing':
                assert not output.exists()
            else:
                report = json.loads(output.read_text(encoding='utf-8'))
                assert [v['stored_record'] for v in report['victims']] == source
                assert report['total_records'] == len(source)
                assert report['case_id'] == case_id
                payload = json.dumps(report['victims'], sort_keys=True, ensure_ascii=True,
                    separators=(',', ':'), allow_nan=False).encode('ascii')
                assert report['data_integrity_hash'] == hashlib.sha256(payload).hexdigest()
                assert report['chain_of_custody'] == 'not_established'
            checks.append({'case': mode, 'status': 'passed', 'records': len(source),
                'admission': 'explicit default writer' if mode == 'writer' else 'passive saved source'})
    print(json.dumps({'status': 'passed', 'checks': checks,
        'network_scope': 'Saved export module import/construction/read/serialization under application offline guard; zero blocked attempts, no collector/plot imports. Default writer constructor tested after requests bootstrap; no IP analysis run.',
        'evidence_scope': 'Strict actual JSON file round-trip and independent SHA-256 of returned victims; no authenticity or custody claim'}, indent=2))


if __name__ == '__main__':
    main()
