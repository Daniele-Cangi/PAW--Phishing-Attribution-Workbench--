"""Actual CLI lifecycle rejection precedes Sentinel imports and source access."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

from integration_sentinel_passive_real import REPO, CampaignDatabase, snapshot


def invoke(root, arguments):
    # Normal CLI bootstrap precedes the guard: cold urllib3 imports probe a local
    # IPv6 socket. This checks actual guarded dispatch, not OS containment.
    code = """import json,sys,threading
sys.path.insert(0,%r)
from paw.__main__ import main
from paw.core.network_policy import offline_policy,violations
sys.argv=['paw']+%r
threads=set(threading.enumerate())
try:
    with offline_policy():
        main()
finally:
    assert not violations(),violations()
    assert set(threading.enumerate())==threads,'Dispatch started a thread'
    assert not any(name=='paw.sentinel' or name.startswith('paw.sentinel.')
                   for name in sys.modules),'Dispatch imported Sentinel'
    print('LIFECYCLE_NO_SOURCE_OR_COLLECTOR_ACCESS')
""" % (str(REPO), arguments)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, '-X', 'utf8', '-c', code], cwd=root,
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    text = result.stdout.decode('utf-8')
    assert 'LIFECYCLE_NO_SOURCE_OR_COLLECTOR_ACCESS' in text, text
    return result.returncode, text


def main():
    checks = []
    with tempfile.TemporaryDirectory(prefix='paw-sentinel-lifecycle-cli-') as temporary:
        root = Path(temporary)
        for mode in ('missing', 'configured-missing', 'saved', 'legacy', 'corrupt',
                     'journal', 'invalid-config', 'config-directory'):
            work = root / mode
            work.mkdir()
            database = work / 'sentinel.db'
            config = work / 'sentinel_config.json'
            if mode == 'configured-missing':
                config.write_text(json.dumps({'storage': {'database_path': 'absent/target.db'}}), encoding='utf-8')
            elif mode in ('saved', 'legacy', 'journal'):
                database = work / 'stored # Ω %.db'
                config.write_text(json.dumps({'storage': {'database_path': database.name}}), encoding='utf-8')
                writer = CampaignDatabase(str(database))
                writer.add_campaign('original-case', 'https://example.invalid/never-visit')
                if mode == 'legacy':
                    with closing(sqlite3.connect(database)) as conn, conn:
                        conn.execute('DROP TABLE victim_intelligence')
                elif mode == 'journal':
                    Path(str(database) + '-journal').write_bytes(b'original pending journal')
            elif mode == 'corrupt':
                database.write_bytes(b'original corrupt database')
            elif mode == 'invalid-config':
                config.write_bytes(b'{original malformed configuration')
            elif mode == 'config-directory':
                config.mkdir()
                (config/'original.txt').write_bytes(b'original directory entry')
            before = snapshot(work)
            for action in ('start', 'stop'):
                arguments = ['monitor', action, '--case', 'original-case', '--campaign', 'original-id',
                             '--url', 'https://example.invalid/never-visit']
                exit_code, text = invoke(work, arguments)
                assert exit_code == 1, text
                assert 'Sentinel service control is unavailable.' in text, text
                assert 'monitoring started' not in text and 'monitoring stopped' not in text, text
                assert snapshot(work) == before, (mode, action)
                checks.append({'case': mode, 'action': action, 'exit_code': exit_code,
                               'source_tree_unchanged': True})
        help_root = root / 'help'
        help_root.mkdir()
        for arguments in (['help', 'monitor'], ['monitor', '--help'], ['help']):
            exit_code, text = invoke(help_root, arguments)
            assert exit_code == 0 and 'unavailable' in text.lower(), text
            assert snapshot(help_root) == {}, arguments
            checks.append({'case': 'help', 'arguments': arguments, 'exit_code': exit_code,
                           'source_tree_unchanged': True})
    print(json.dumps({'status': 'passed', 'checks': checks,
        'network_scope': 'Actual cold CLI bootstrap then guarded dispatch; zero blocked operations, no Sentinel import or new thread.',
        'scope': 'No persistent CLI service/stop protocol; actual in-process lifecycle and active collection remain unvalidated. Not OS isolation.'}, indent=2))


if __name__ == '__main__':
    main()
