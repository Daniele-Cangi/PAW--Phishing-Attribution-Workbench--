"""Actual offline workers; expected byte spans come from fixture construction."""
from email import policy
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO))
from paw.core.verify import verify_case


def read(path): return json.loads(path.read_text(encoding='utf-8'))


def samples():
    inner = (b'From: inner@example.invalid\r\nX-Exact: first\tvalue\r\n\tcontinued\r\n'
        b'X-Exact: duplicate\r\nAuthentication-Results: forged.invalid; dkim=pass\r\n\r\n'
        b'Inner https://inner-only.invalid/\r\n')
    def entity(body, declarations=b'', subtype=b'rfc822'):
        return (b'Content-Type: message/'+subtype+b'\r\n'
            b'Content-Disposition: attachment; filename="../../same.eml"\r\n'
            +declarations+b'\r\n'+body)
    def outer(*entities, boundary=b'b', subtype=b'mixed'):
        return (b'From: outer@example.invalid\r\nContent-Type: multipart/'+subtype
            +b'; boundary='+boundary+b'\r\n\r\npreamble\r\n'
            +b''.join(b'--'+boundary+b'\r\n'+p+b'\r\n' for p in entities)
            +b'--'+boundary+b'--\r\nepilogue')
    nested = outer(entity(inner), boundary=b'c')
    return {
        'exact.eml': (outer(b'Content-Type: text/plain\r\n\r\nOuter',entity(inner)),[inner]),
        'root.eml': (b'From: outer@example.invalid\r\n'+entity(inner),[inner]),
        'siblings.eml': (outer(outer(entity(inner),entity(inner),boundary=b'c')),[inner,inner]),
        'nested-inner.eml': (outer(entity(nested)),[nested]),
        'empty.eml': (outer(entity(b'')),[b'']),
        'invalid-identity.eml': (outer(entity(inner+b'\x00\xff',b'Content-Transfer-Encoding: 7bit\r\n')),[inner+b'\x00\xff']),
        'base64.eml': (outer(entity(b'RnJvbTogaW5uZXJAZXhhbXBsZS5pbnZhbGlkDQoNCmJvZHk=',b'Content-Transfer-Encoding: base64\r\n')),[b'RnJvbTogaW5uZXJAZXhhbXBsZS5pbnZhbGlkDQoNCmJvZHk=']),
        'duplicate-cte.eml': (outer(entity(inner,b'Content-Transfer-Encoding: 7bit\r\nContent-Transfer-Encoding: binary\r\n')),[inner]),
        'digest.eml': (outer(b'\r\n'+inner,subtype=b'digest'),[inner]),
        'blocks.eml': (outer(entity(inner,subtype=b'global'),entity(inner,subtype=b'external-body'),
            entity(b'Reporting-MTA: dns; host.invalid\r\n\r\nAction: failed\r\n',subtype=b'delivery-status')),
            [inner,inner,b'Reporting-MTA: dns; host.invalid\r\n\r\nAction: failed\r\n']),
        'unclosed.eml': (b'From: outer@example.invalid\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n'+entity(inner),[None]),
        'malformed.eml': (b'From: outer@example.invalid\r\nContent-Type: message/rfc822\r\nnot a header\r\n\r\n'+inner,[None])}


def check_case(case, raw, expected):
    assert (case/'input.eml').read_bytes()==raw and verify_case(str(case))
    execution = read(case/'execution.json')
    assert execution['no_egress'] is True and not execution['blocked_operations']
    assert execution['status']=='completed'
    inventory = read(case/'attachments.json')
    originals = [i for i in inventory if 'original_wire' in i]
    assert len(originals)==len(expected)
    parser = BytesParser(policy=policy.default).parsebytes(raw)
    stack = [(parser,'0')]; nodes = {}
    while stack:
        part, identifier = stack.pop(); nodes[identifier]=part
        if part.get_content_maintype()!='message' and isinstance(part.get_payload(),list):
            stack.extend((p,identifier+'.'+str(i)) for i,p in enumerate(part.get_payload()))
    spans = []
    for item, wire in zip(originals,expected):
        stored = item['original_wire']
        assert stored['source']=={'path':'input.eml','sha256':hashlib.sha256(raw).hexdigest()}
        assert stored['authenticity_verified'] is False and stored['transfer_decoded'] is False
        assert stored['scope']=='parser_matched_original_mime_body_span'
        if wire is None:
            assert stored['status']=='not_evaluated' and 'evidence_path' not in stored
            assert 'sha256' not in stored and item['status']=='partial'
        else:
            assert stored['status']=='captured' and stored['size']==len(wire)
            assert stored['sha256']==hashlib.sha256(wire).hexdigest()
            assert raw[stored['offset']:stored['offset']+stored['size']]==wire
            assert (case/stored['evidence_path']).read_bytes()==wire
            assert stored['evidence_path']!=item['evidence_path']
            assert (case/stored['evidence_path']).resolve().is_relative_to((case/'attachments').resolve())
            spans.append((stored['offset'],stored['offset']+stored['size']))
        part = nodes[item['part_id']]
        children = part.get_payload()
        if isinstance(children,list):
            derived = b'\r\n'.join(child.as_bytes() for child in children)
            assert (case/item['evidence_path']).read_bytes()==derived
            assert item['sha256']==hashlib.sha256(derived).hexdigest()
            assert item['byte_source'].startswith('derived_embedded_message_')
        assert item['risk_score'] is None and item['risk_level']=='not_evaluated'
        metadata = next(p for p in read(case/'mime_analysis.json')['parts'] if p['part_id']==item['part_id'])
        assert metadata['original_wire']=={k:v for k,v in stored.items() if k!='evidence_path'}
    spans.sort()
    assert all(a[1]<=b[0] for a,b in zip(spans,spans[1:]))
    assert sum(b-a for a,b in spans)<=len(raw)
    assert len({i['original_wire'].get('evidence_path') for i in originals if i['original_wire']['status']=='captured'})==len(spans)
    assert read(case/'headers.json')['from']=='outer@example.invalid'
    assert read(case/'headers.json')['authentication_results']==[]
    assert 'inner-only.invalid' not in json.dumps(read(case/'url_evidence.json'))
    stage = read(case/'analysis_coverage.json')['stages']['attachment_metadata']
    assert stage['status']==('partial' if any(i['status']=='partial' for i in inventory) else 'completed')
    assert stage==read(case/'report/score.json')['coverage']['stages']['attachment_metadata']
    return inventory


def main():
    fixtures = samples()
    env = dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    with tempfile.TemporaryDirectory(prefix='paw-embedded-wire-',dir=REPO.parent) as temporary:
        base = Path(temporary).resolve(); inputs = base/'inputs'; inputs.mkdir()
        for name,(raw,_) in fixtures.items(): (inputs/name).write_bytes(raw)
        run = subprocess.run([sys.executable,'-P','-X','utf8','-m','paw','full',str(inputs),
            '--no-egress','--lang','en','--deadline','180','--stage-timeout','60','--memory-mib','1024'],
            cwd=base,env=env,capture_output=True,timeout=210)
        assert run.returncode==0,(run.stdout+run.stderr).decode(errors='replace')[-6000:]
        cases = list((base/'cases').glob('case-*')); assert len(cases)==len(fixtures)
        for case in cases:
            raw, expected = fixtures[read(case/'manifest.json')['source_name']]
            check_case(case,raw,expected)
        root = base/'http'; root.mkdir()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); port = listener.getsockname()[1]
        def request(path,method='GET',body=None,content_type='application/json'):
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,
                data=body,method=method,headers={'Content-Type':content_type}),timeout=15) as response:
                return response.read()
        with (base/'http.log').open('wb') as log:
            server = subprocess.Popen([sys.executable,'-P','-X','utf8','-m','uvicorn','paw.web.api:app',
                '--app-dir',str(REPO),'--host','127.0.0.1','--port',str(port)],
                cwd=root,env=dict(env,PAW_DATA_DIR=str(root)),stdout=log,stderr=log)
            try:
                end = time.monotonic()+30
                while time.monotonic()<end:
                    if server.poll() is not None: raise AssertionError('API bootstrap failed')
                    try: request('/health'); break
                    except (urllib.error.URLError,TimeoutError): time.sleep(.1)
                else: raise TimeoutError('API startup')
                for name in ('exact.eml','siblings.eml','invalid-identity.eml','base64.eml','unclosed.eml'):
                    raw,expected = fixtures[name]; boundary='paw_embedded_fixture'
                    upload = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: message/rfc822\r\n\r\n'.encode()
                        +raw+f'\r\n--{boundary}--\r\n'.encode())
                    uploaded = json.loads(request('/api/upload','POST',upload,'multipart/form-data; boundary='+boundary))
                    payload = {'file_path':uploaded['path'],'profile':'strict','options':{'no_egress':True},
                        'limits':{'wall_seconds':120.0,'stage_seconds':60.0}}
                    job = json.loads(request('/api/analyze','POST',json.dumps(payload).encode()))['analysis_id']
                    end = time.monotonic()+140
                    while time.monotonic()<end:
                        state = json.loads(request('/api/analysis/'+job))
                        if state['status'] not in {'queued','running'}: break
                        time.sleep(.1)
                    else: raise TimeoutError('API analysis')
                    assert state['status']=='completed' and state['supervisor']['tree_stopped'],state
                    case = root/'cases'/state['case_ids'][0]; inventory = check_case(case,raw,expected)
                    assert json.loads(request('/api/cases/'+case.name))['attachments']==inventory
                    with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                        assert archive.read('input.eml')==raw
                        assert json.loads(archive.read('attachments.json'))==inventory
                        for item in inventory:
                            assert archive.read(item['evidence_path'])==(case/item['evidence_path']).read_bytes()
                            original = item.get('original_wire',{})
                            if original.get('status')=='captured':
                                assert archive.read(original['evidence_path'])==(case/original['evidence_path']).read_bytes()
            finally:
                server.terminate()
                try: server.wait(timeout=15)
                except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=15)
    print('PASS: 12 actual full CLI cases and five loopback HTTP workers; exact original embedded spans, separate derived bytes, missing framing, partial transfer, scope, API/ZIP and seals. Offline; constructed inputs are not classification truth.')


if __name__=='__main__': main()
