"""Actual offline EML case and legacy updater rejection without case I/O."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from paw.core.evidence import seal_case
from paw.core.verify import verify_case

SCRIPT = REPO/'scripts'/'update_origin.py'
LEGACY_CASE = 'case-2025-10-28T105745Z-32e9'


def snapshot(root):
    return {p.relative_to(root).as_posix():p.read_bytes() if p.is_file() else None
            for p in root.rglob('*')}


def invoke(root, outside, mode):
    arguments = ['--help'] if mode=='help' else ['--case','../outside'] if mode=='invalid' else []
    code = """import os,runpy,sys,threading
sys.path.insert(0,%r)
from paw.core.network_policy import offline_policy,violations
sys.argv=[%r]+%r
argv=list(sys.argv)
path=list(sys.path)
cwd=os.getcwd()
threads=set(threading.enumerate())
protected=[os.path.normcase(os.path.abspath(p)) for p in %r]
attempts=[]
def forbid_source_io(event,args):
    if event in ('os.rename','os.link','os.symlink'):
        paths=args[:2]
    elif event in ('open','os.chdir','os.listdir','os.scandir','os.mkdir',
                   'os.remove','os.rmdir','os.chmod','os.utime','os.truncate'):
        paths=args[:1]
    else:
        return
    for value in paths:
        if not isinstance(value,(str,os.PathLike)): continue
        absolute=os.path.normcase(os.path.abspath(value))
        if any(absolute==p or absolute.startswith(p+os.sep) for p in protected):
            attempts.append(event)
            raise AssertionError('Updater attempted source access: '+event)
sys.addaudithook(forbid_source_io)
try:
    with offline_policy():
        runpy.run_path(%r,run_name=%r)
finally:
    assert not attempts,attempts
    assert not violations(),violations()
    assert os.getcwd()==cwd and sys.argv==argv and sys.path==path,'Process state changed'
    assert set(threading.enumerate())==threads,'New thread'
    for name in ('ipwhois','requests','paw.__main__','paw.core.trace'):
        assert name not in sys.modules,name
    print('ORIGIN_UPDATE_NO_SOURCE_OR_NETWORK_ACCESS',file=sys.stderr)
""" % (str(REPO),str(SCRIPT),arguments,[str(root),str(outside)],str(SCRIPT),
           'legacy_import' if mode=='import' else '__main__')
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    env.pop('PYTHONPATH',None)
    result=subprocess.run([sys.executable,'-X','utf8','-c',code],cwd=root,env=env,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    text=result.stdout.decode('utf-8')+result.stderr.decode('utf-8')
    assert 'ORIGIN_UPDATE_NO_SOURCE_OR_NETWORK_ACCESS' in text,text
    expected={'execute':1,'import':0,'help':0,'invalid':2}[mode]
    assert result.returncode==expected,text
    if mode=='execute':
        assert 'Report update unavailable' in text and result.stdout==b'',text
    elif mode=='help':
        assert 'unavailable' in text and '--no-egress' in text,text
    elif mode=='import':
        assert result.stdout==b'',text
    return {'entry':mode,'exit':result.returncode,'no_source_or_network_access':True}


def main():
    checks=[]
    with tempfile.TemporaryDirectory(prefix='paw-origin-update-real-') as temporary:
        base=Path(temporary)
        completed=base/'completed'
        completed.mkdir()
        raw=next((REPO/'inbox').glob('*.eml')).read_bytes()
        (completed/'input.eml').write_bytes(raw)
        env=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
        analysis=subprocess.run([sys.executable,'-X','utf8','-m','paw','full','input.eml',
            '--no-egress','--deadline','90','--stage-timeout','60'],cwd=completed,env=env,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
        (completed/'full.log').write_bytes(analysis.stdout)
        assert analysis.returncode==0,analysis.stdout.decode('utf-8')
        case,=(completed/'cases').glob('case-*')
        control,=(p for p in (completed/'jobs').iterdir() if p.is_dir())
        supervisor=json.loads((control/'supervisor.json').read_text(encoding='utf-8'))
        execution=json.loads((case/'execution.json').read_text(encoding='utf-8'))
        assert supervisor['tree_stopped'] and supervisor['returncode']==0,supervisor
        assert execution['no_egress'] and not execution['blocked_operations'],execution
        assert (case/'input.eml').read_bytes()==raw and verify_case(str(case))

        # Actual sealed files at the former hardcoded path, not a second analysis.
        legacy=completed/'cases'/LEGACY_CASE
        legacy.mkdir()
        origin={'ip':'192.0.2.9','asn':64500,'org':'Retained source','cc':'ZZ',
                'abuse':[{'type':'email','value':'abuse@example.invalid'}]}
        (legacy/'origin.json').write_text(json.dumps(origin),encoding='utf-8')
        seal_case(legacy)
        outside=base/'outside'
        outside.mkdir()
        (outside/'preserve.txt').write_bytes(b'outside path must remain unchanged')
        roots=[('completed-and-sealed',completed)]
        for mode in ('missing','unsealed','corrupt','blocked-owner-metadata','missing-origin'):
            work=base/mode
            work.mkdir()
            roots.append((mode,work))
            if mode=='missing': continue
            target=work/'cases'/LEGACY_CASE
            target.mkdir(parents=True)
            if mode!='missing-origin':
                (target/'origin.json').write_text('{original invalid JSON' if mode=='corrupt'
                    else json.dumps(origin),encoding='utf-8')
            if mode=='blocked-owner-metadata':
                # Ownership-state fixture; this is not a live-worker claim.
                identifier='analysis_'+'1'*32
                (target/'manifest.json').write_text(json.dumps({'analysis_job':identifier}),encoding='utf-8')
                (work/'jobs').mkdir()
                (work/'jobs'/(identifier+'.json')).write_text(json.dumps({'status':'running'}),encoding='utf-8')
                seal_case(target)
        for name,work in roots:
            before=snapshot(work),snapshot(outside)
            for entry in ('execute','import','help','invalid'):
                check=invoke(work,outside,entry)
                assert (snapshot(work),snapshot(outside))==before,(name,entry)
                checks.append({'case':name,**check,'source_trees_unchanged':True})
        before=snapshot(completed)
        env.pop('PYTHONPATH',None)
        for arguments,expected in (([],1),(['--help'],0)):
            direct=subprocess.run([sys.executable,'-X','utf8',str(SCRIPT),*arguments],cwd=completed,
                env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            assert direct.returncode==expected,direct.stderr
            assert b'unavailable' in direct.stdout+direct.stderr
            assert snapshot(completed)==before
        assert (case/'input.eml').read_bytes()==raw
        assert verify_case(str(case)) and verify_case(str(legacy))
        assert json.loads((legacy/'origin.json').read_text(encoding='utf-8'))==origin
    print(json.dumps({'status':'passed','original_eml_sha256':hashlib.sha256(raw).hexdigest(),
        'actual_supervised_full_analyses':1,'guarded_entry_processes':24,'direct_entry_processes':2,
        'checks':checks,'scope':'Actual completed original-EML case and explicit filesystem/ownership-state fixtures preserved. No guarded source I/O, collector imports or blocked operations; import inert and execution unavailable. Direct stdlib-only script invocations are separate from guarded claims. Not live active-worker containment, authenticity, accuracy or OS isolation.'},indent=2))


if __name__=='__main__':
    main()
