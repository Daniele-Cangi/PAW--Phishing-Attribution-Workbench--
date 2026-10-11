"""Actual offline worker cases and loopback API/ZIP; independently stated expectations."""
import hashlib,io,json,os,socket,subprocess,sys,tempfile,time,zipfile
from pathlib import Path
import urllib.error,urllib.request
REPO=Path(__file__).resolve().parents[1];sys.path.insert(0,str(REPO));sys.path.insert(0,str(REPO/'tests'))
from test_mime_cid import sample
from paw.core.verify import verify_case

def read(path):return json.loads(path.read_text(encoding='utf-8'))

def fixtures():
    result={}
    def add(name,msg,statuses,targets=(),**counts):
        result[name+'.eml']=(msg.as_bytes(),{'statuses':statuses,'targets':list(targets),**counts})
    add('matched',sample(),['candidate_match'],[['0.1']])
    add('duplicates',sample(ids=('logo@local.invalid',)*2),['ambiguous_candidates'],[['0.1','0.2']])
    msg=sample();msg.get_payload()[1]['Content-ID']='<logo@local.invalid>'
    add('duplicate-fields',msg,['ambiguous_candidates'],[['0.1','0.1']])
    add('encoded',sample('<img src="CID:logo%40local.invalid"><a href="cid:logo&#64;local.invalid">go</a>'),
        ['candidate_match']*2,[['0.1']]*2)
    add('missing',sample(ids=()),['unmatched_in_captured_fields'],[[]])
    add('case-sensitive',sample('<img src="cid:Logo@local.invalid">'),['unmatched_in_captured_fields'],[[]])
    msg=sample(ids=());msg.add_attachment(sample(),filename='inner.eml')
    add('embedded',msg,['unmatched_in_captured_fields'],[[]])
    msg=sample('outer',ids=());msg.add_attachment('<img src="cid:logo@local.invalid">',subtype='html',filename='inside.html')
    add('attached-html',msg,[])
    add('complex',sample('<img srcset="cid:logo@local.invalid 1x, cid:other@local.invalid 2x">'
        '<div style="background:url(cid:logo@local.invalid)"></div>'),['not_interpreted']*2,[[],[]])
    add('malformed',sample(''.join('<img src="cid:'+v+'">' for v in ('bad%ZZ','bad%ff','bad%00','','bad%20id'))),
        ['not_interpreted']*5,[[]]*5)
    add('link-limit',sample('<img src="cid:logo@local.invalid">'*100,ids=('logo@local.invalid',)*50),
        ['ambiguous_candidates']*100,[['0.'+str(i) for i in range(1,51)]]*100,
        total_links=5000,retained_links=4096,omitted_links=904)
    add('observation-limit',sample('<img src="cid:logo@local.invalid">'*2050),
        ['candidate_match']*2048,[['0.1']]*2048,total_observations=2050,omitted_observations=2)
    add('value-limit',sample('<img src="cid:'+'x'*5000+'">',ids=('x'*5000,)),['not_interpreted'],[[]])
    return result

def check_case(case,raw,expected):
    assert verify_case(case) and (case/'input.eml').read_bytes()==raw
    execution=read(case/'execution.json');assert execution['no_egress'] and not execution['blocked_operations']
    inv=read(case/'mime_cid_inventory.json')
    assert not inv['verified'] and inv['source']=={'path':'input.eml','sha256':hashlib.sha256(raw).hexdigest()}
    assert not list(case.glob('mime_cid_inventory.json.*.tmp'))
    assert [r['interpretation_status'] for r in inv['observations']]==expected['statuses']
    assert inv['total_observation_count']==expected.get('total_observations',len(expected['statuses']))
    assert inv['inventoried_observation_count']==len(expected['statuses'])
    assert inv['omitted_observation_count']==expected.get('omitted_observations',0)
    headers={p['part_id']:p for p in read(case/'mime_header_inventory.json')['parts']}
    bodies={p['part_id']:p for p in read(case/'mime_body_evidence.json')['parts']}
    for source in inv['html_sources']:
        body=bodies[source['part_id']];text=source['derived_from']
        assert source['artifact']=='mime_body_evidence.json' and source['representation']=='html_parser_attribute_values'
        assert source['message_root_part_id']==headers[source['part_id']]['message_root_part_id']=='0'
        for key in ('text_status','text_path','text_sha256'):assert text[key]==body[key]
        assert hashlib.sha256((case/text['text_path']).read_bytes()).hexdigest()==text['text_sha256']
    for field in inv['content_id_catalog']:
        part=headers[field['part_id']];original=part['headers']['fields'][field['header_index']]
        assert original['normalized_name']=='content-id' and field['artifact']=='mime_header_inventory.json'
        assert field['message_root_part_id']==part['message_root_part_id']
        if field['identifier'] is not None:assert original['parsed_value'].strip()=='<'+field['identifier']+'>'
    pairs=[]
    for observation,parts in zip(inv['observations'],expected['targets']):
        assert observation['candidate_count']==len(parts)
        # Fixed fixture expectation gives part multiplicity; distinct fields in
        # one part retain independent parser indexes in catalog order.
        candidates=[f['content_id_index'] for f in inv['content_id_catalog']
                    if f['part_id'] in parts and f['message_root_part_id']=='0']
        assert len(candidates)==len(parts)
        pairs.extend({'observation_index':observation['observation_index'],'content_id_index':i} for i in candidates)
    assert inv['total_link_count']==expected.get('total_links',len(pairs))
    assert inv['inventoried_link_count']==expected.get('retained_links',len(pairs))
    assert inv['omitted_link_count']==expected.get('omitted_links',0)
    assert inv['links']==pairs[:inv['limits']['max_links']]
    assert inv['link_count_scope']=='retained_observations_and_interpreted_captured_content_id_fields'
    stage=read(case/'analysis_coverage.json')['stages']['mime_cids']
    assert stage==read(case/'report/score.json')['coverage']['stages']['mime_cids']
    for key,value in stage.items():
        if key!='artifact':assert inv[key]==value
    assert stage['artifact']=='mime_cid_inventory.json'
    assert 'mime_cid_inventory.json' in (case/'report/technical.md').read_text(encoding='utf-8')
    assert not any('cid:' in str(r).lower() for r in read(case/'url_evidence.json'))
    return inv

def main():
    samples=fixtures();env=dict(os.environ,PYTHONPATH=str(REPO),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    with tempfile.TemporaryDirectory(prefix='paw-cid-',dir=REPO.parent) as temporary:
        base=Path(temporary).resolve();inputs=base/'inputs';inputs.mkdir()
        for name,(raw,_) in samples.items():(inputs/name).write_bytes(raw)
        run=subprocess.run([sys.executable,'-P','-X','utf8','-m','paw','full',str(inputs),'--no-egress',
            '--lang','en','--deadline','180','--stage-timeout','60','--memory-mib','1024'],
            cwd=base,env=env,capture_output=True,timeout=210)
        assert run.returncode==0,(run.stdout+run.stderr).decode(errors='replace')[-6000:]
        cases=list((base/'cases').glob('case-*'));assert len(cases)==len(samples)
        for case in cases:check_case(case,*samples[read(case/'manifest.json')['source_name']])
        root=base/'http';root.mkdir()
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        def request(path,method='GET',body=None,content_type='application/json'):
            with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{port}'+path,
                data=body,method=method,headers={'Content-Type':content_type}),timeout=15) as response:return response.read()
        with (base/'http.log').open('wb') as log:
            server=subprocess.Popen([sys.executable,'-P','-X','utf8','-m','uvicorn','paw.web.api:app','--app-dir',str(REPO),
                '--host','127.0.0.1','--port',str(port)],cwd=root,env=dict(env,PAW_DATA_DIR=str(root)),stdout=log,stderr=log)
            try:
                end=time.monotonic()+30
                while time.monotonic()<end:
                    if server.poll() is not None:raise AssertionError('API bootstrap failed')
                    try:request('/health');break
                    except (urllib.error.URLError,TimeoutError):time.sleep(.1)
                else:raise TimeoutError('API startup')
                for name in ('matched.eml','duplicates.eml','encoded.eml','complex.eml','link-limit.eml'):
                    raw,expected=samples[name];boundary='paw_cid_fixture'
                    body=(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\nContent-Type: message/rfc822\r\n\r\n'.encode()+raw+f'\r\n--{boundary}--\r\n'.encode())
                    path=json.loads(request('/api/upload','POST',body,'multipart/form-data; boundary='+boundary))['path']
                    payload={'file_path':path,'profile':'strict','options':{'no_egress':True},'limits':{'wall_seconds':120.,'stage_seconds':60.}}
                    job=json.loads(request('/api/analyze','POST',json.dumps(payload).encode()))['analysis_id']
                    end=time.monotonic()+140
                    while time.monotonic()<end:
                        state=json.loads(request('/api/analysis/'+job))
                        if state['status'] not in {'queued','running'}:break
                        time.sleep(.1)
                    else:raise TimeoutError('API analysis')
                    assert state['status']=='completed' and state['supervisor']['tree_stopped'],state
                    case=root/'cases'/state['case_ids'][0];inv=check_case(case,raw,expected)
                    assert json.loads(request('/api/cases/'+case.name))['mime_cid_inventory']==inv
                    with zipfile.ZipFile(io.BytesIO(request('/api/export/'+case.name))) as archive:
                        assert json.loads(archive.read('mime_cid_inventory.json'))==inv
                        for source in inv['html_sources']:
                            assert archive.read(source['derived_from']['text_path'])==(case/source['derived_from']['text_path']).read_bytes()
                        for name in ('input.eml','mime_header_inventory.json','mime_body_evidence.json'):
                            assert archive.read(name)==(case/name).read_bytes()
            finally:
                server.terminate()
                try:server.wait(timeout=15)
                except subprocess.TimeoutExpired:server.kill();server.wait(timeout=15)
    print('PASS: 13 actual no-egress CLI cases, 5 loopback HTTP workers; CID provenance, ambiguity/scopes, one-pass decoding, limits/counts, API/ZIP and seals. Fixtures are not classification truth.')

if __name__=='__main__':main()
