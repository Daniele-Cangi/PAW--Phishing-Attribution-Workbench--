"""Legacy script and canonical passive CLI parity against actual saved SQLite."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

from integration_sentinel_passive_real import REPO, CampaignDatabase, snapshot

SCRIPT = REPO / '_list_campaigns.py'


def invoke(root, legacy, arguments=()):
    # Bootstrap before the policy: ordinary CLI imports probe local IPv6 support.
    code = """import sys,runpy,threading
sys.path.insert(0,%r)
from paw.__main__ import main
from paw.core.network_policy import offline_policy,violations
sys.argv=%r
threads=set(threading.enumerate())
try:
    with offline_policy():
        if %r:
            runpy.run_path(%r,run_name='__main__')
        else:
            main()
finally:
    assert not violations(),violations()
    assert set(threading.enumerate())==threads,'New thread'
    for name in ('monitor','ip_analyzer','intelligence_analyzer','geographic_reports'):
        assert 'paw.sentinel.'+name not in sys.modules,name
    print('LEGACY_LIST_NO_COLLECTION_OR_BLOCKED_OPERATIONS')
""" % (str(REPO), ([str(SCRIPT)] if legacy else ['paw','monitor','list']) + list(arguments),
           legacy, str(SCRIPT))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUTF8='1')
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=root,env=env,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
    text = result.stdout.decode('utf-8')
    assert 'LEGACY_LIST_NO_COLLECTION_OR_BLOCKED_OPERATIONS' in text, text
    return result.returncode, text


def main():
    checks=[]
    with tempfile.TemporaryDirectory(prefix='paw-legacy-list-') as temporary:
        root=Path(temporary)
        for mode in ('missing','configured-missing','saved','legacy','corrupt','empty',
                     'wal','journal','invalid-config','config-directory'):
            work=root/mode
            work.mkdir()
            database=work/'sentinel.db'
            config=work/'sentinel_config.json'
            if mode=='configured-missing':
                config.write_text(json.dumps({'storage':{'database_path':'absent/target.db'}}),encoding='utf-8')
            elif mode in ('saved','legacy','wal','journal'):
                database=work/'stored # Ω %.db'
                config.write_text(json.dumps({'storage':{'database_path':database.name}}),encoding='utf-8')
                writer=CampaignDatabase(str(database))
                writer.add_campaign('active-case','https://example.invalid/stored-active')
                removed=writer.add_campaign('removed-case','https://example.invalid/stored-removed')
                writer.update_campaign_status(removed,'removed')
                if mode=='legacy':
                    with closing(sqlite3.connect(database)) as conn, conn:
                        conn.execute('DROP TABLE victim_intelligence')
                elif mode=='wal':
                    with closing(sqlite3.connect(database)) as conn:
                        conn.execute('PRAGMA journal_mode=WAL')
                elif mode=='journal':
                    Path(str(database)+'-journal').write_bytes(b'original pending journal')
            elif mode=='corrupt':
                database.write_bytes(b'original damaged source')
            elif mode=='empty':
                with closing(sqlite3.connect(database)):
                    pass
            elif mode=='invalid-config':
                config.write_bytes(b'{original malformed config')
            elif mode=='config-directory':
                config.mkdir()
                (config/'original.txt').write_bytes(b'original')
            before=snapshot(work)
            canonical=invoke(work,False)
            assert snapshot(work)==before, (mode,'canonical')
            legacy=invoke(work,True)
            assert snapshot(work)==before, (mode,'legacy')
            assert legacy==canonical, (mode,legacy,canonical)
            if mode in ('saved','legacy'):
                assert legacy[0]==0 and 'stored-active' in legacy[1] and 'stored-removed' not in legacy[1],legacy
            else:
                assert legacy[0]!=0 and 'No active campaigns' not in legacy[1],legacy
            checks.append({'mode':mode,'canonical_legacy_parity':True,'sources_preserved':True})
        work=root/'arguments'
        work.mkdir()
        for arguments,expected in ((['--help'],0),(['--unsupported'],2)):
            legacy=invoke(work,True,arguments)
            assert legacy==invoke(work,False,arguments),arguments
            assert legacy[0]==expected,arguments
            assert snapshot(work)=={},arguments
        env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        env.pop('PYTHONPATH',None)
        imported=subprocess.run([sys.executable,'-X','utf8','-c',
            "import runpy,sys; before=list(sys.argv); runpy.run_path(%r,run_name='legacy_import'); assert sys.argv==before; assert 'paw' not in sys.modules" % str(SCRIPT)],
            cwd=work,env=env,capture_output=True,timeout=30)
        assert imported.returncode==0,imported.stderr
        direct=subprocess.run([sys.executable,'-X','utf8',str(SCRIPT),'--help'],cwd=work,
            env=env,capture_output=True,timeout=30)
        assert direct.returncode==0 and b'list' in direct.stdout,direct.stderr
        assert snapshot(work)=={}
    print(json.dumps({'status':'passed','paired_storage_modes':checks,'processes':26,
        'scope':'24 actual guarded dispatch processes after CLI bootstrap, one inert import and one direct script help without PYTHONPATH. No cold-bootstrap/OS isolation or concurrent-writer snapshot claim.'},indent=2))


if __name__=='__main__':
    main()
