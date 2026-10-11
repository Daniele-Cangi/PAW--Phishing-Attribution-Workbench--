"""Per-source links to existing URL records, with explicit claim/limit boundaries."""
import base64
import copy
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
import tempfile
import unittest

from paw.core.header_inventory import inventory_headers, HeaderInventoryLimits
from paw.core.mime_analysis import analyze_mime, extract_urls
from paw.core.mime_body_evidence import preserve_body_parts
from paw.core.network_policy import offline_policy, violations
from paw.core.parser_mail import parse_message_bytes, parse_eml_bytes
from paw.core.url_evidence import build_url_evidence, extract_mime_url_candidates
from paw.core.url_sources import inventory_url_sources, url_source_coverage
from paw.deobfuscate.url import URLDeobfuscator


URL='https://shared-source.invalid/a?x=1&y=2'


def message():
    value=EmailMessage(policy=policy.SMTP)
    value['From']='outer@example.invalid';value['Subject']='Notice '+URL
    value.set_content('First '+URL+'\nAgain '+URL)
    value.add_alternative('<a href="'+URL.replace('&','&amp;')+'">'+URL.replace('&','&amp;')+'</a>', subtype='html')
    value.add_attachment('Excluded https://attached-only.invalid/',filename='letter.txt')
    return value


def run(raw, *, limits=None, extra=(), **kwargs):
    msg=parse_message_bytes(raw); headers=parse_eml_bytes(raw); mime=analyze_mime(msg)
    header=inventory_headers(msg,raw,limits) if limits else inventory_headers(msg,raw)
    observed=list(dict.fromkeys(mime['urls']+extract_urls(headers.get('subject',''))+extract_urls(headers.get('from',''))))
    candidates=list(dict.fromkeys(observed+extract_mime_url_candidates(mime,headers.get('subject',''))))
    decoder=URLDeobfuscator()
    targets,evidence=build_url_evidence(observed,[decoder.deobfuscate_url(c) for c in candidates])
    evidence+=list(extra); before=copy.deepcopy(evidence)
    with tempfile.TemporaryDirectory() as temp:
        body=preserve_body_parts(mime,raw,Path(temp)/'mime_body')
        inventory=inventory_url_sources(mime,body,msg,headers,header,evidence,**kwargs)
    assert evidence==before
    return inventory,evidence,targets


def contexts(inventory,index):
    sources=inventory['sources']
    return {(sources[link['source_index']]['kind'], sources[link['source_index']].get('part_id'),
             sources[link['source_index']].get('field')) for link in inventory['links'] if link['url_evidence_index']==index}


class URLSourceTests(unittest.TestCase):
    def test_shared_target_retains_all_part_and_selected_subject_sources(self):
        inventory,evidence,targets=run(message().as_bytes())
        self.assertEqual(targets,[URL]);self.assertEqual(len(evidence),1)
        self.assertEqual(contexts(inventory,0),{('mime_body','0.0.0',None),('mime_body','0.0.1',None),('selected_header','0','subject')})
        self.assertEqual(inventory['total_link_count'],3)
        self.assertEqual(inventory['mapped_evidence_count'],1)
        self.assertEqual(inventory['status'],'completed')
        self.assertFalse(inventory['verified'])

    def test_colliding_derived_target_matches_original_candidate_not_target_substring(self):
        value=EmailMessage(policy=policy.SMTP)
        raw='hxxps://example[.]invalid/a'
        encoded=base64.b64encode(b'https://example.invalid/a').decode()
        value.set_content(raw);value.add_alternative('<div data-next="'+encoded+'"></div>',subtype='html')
        inventory,evidence,targets=run(value.as_bytes())
        self.assertEqual(targets,['https://example.invalid/a'])
        for index,record in enumerate(evidence):
            linked=contexts(inventory,index)
            if record['source_url']==raw: self.assertEqual(linked,{('mime_body','0.0',None)})
            else: self.assertEqual(linked,{('mime_body','0.1',None)})

    def test_invalid_and_unresolved_sources_remain_linked_without_becoming_targets(self):
        raw=b'From: outer@example.invalid\r\n\r\nhxxps://bad[.]invalid/%ZZ aHR0c!!!'
        inventory,evidence,targets=run(raw)
        self.assertEqual(targets,[]);self.assertEqual(len(evidence),2)
        self.assertEqual(inventory['mapped_evidence_count'],2)
        self.assertEqual(inventory['status'],'completed')
        self.assertTrue(all(not record['network_target'] for record in evidence))

    def test_html_charrefs_split_visible_text_comments_and_script_candidates(self):
        bodies=['<p>https://split.invalid/<b>tail</b></p>',
                '<!-- hxxps://comment[.]invalid/ --><script>"aHR0cHM6Ly9zY3JpcHQuaW52YWxpZC8="</script>',
                '<a href="https://entity.invalid/?x=1&amp;y=2">go</a>',
                '<div xmlns="https://vocabulary.invalid/">text</div>']
        for body in bodies:
            value=EmailMessage(policy=policy.SMTP);value.set_content(body,subtype='html')
            with self.subTest(body=body):
                inventory,evidence,_=run(value.as_bytes())
                self.assertEqual(inventory['unmapped_evidence_count'],0)
                self.assertTrue(all(contexts(inventory,i)=={('mime_body','0',None)} for i in range(len(evidence))))
                if 'xmlns' in body:self.assertEqual(evidence,[])

    def test_plain_js_independent_html_state_and_attached_scope(self):
        value=EmailMessage(policy=policy.SMTP);value.set_content('<script>unclosed',subtype='html')
        value.add_alternative('<a href="hxxps://later[.]invalid/">go</a>',subtype='html')
        value.add_alternative('const u="https://js-source.invalid/";',subtype='javascript')
        inner=EmailMessage();inner.set_content('https://embedded-only.invalid/')
        value.add_attachment(inner,filename='inner.eml')
        inventory,evidence,targets=run(value.as_bytes())
        self.assertEqual(set(targets),{'https://later.invalid/','https://js-source.invalid/'})
        self.assertEqual(inventory['unmapped_evidence_count'],0)
        self.assertFalse(any('embedded' in str(record) for record in evidence))

    def test_first_selected_header_occurrences_only_and_unknown_fields_excluded(self):
        raw=(b'X-Unknown: https://unknown-only.invalid/\r\n'
             b'Subject: https://first.invalid/\r\nSubject: https://second-only.invalid/\r\n'
             b'From: "https://display.invalid/" <outer@example.invalid>\r\n\r\nbody')
        inventory,evidence,targets=run(raw)
        self.assertEqual(set(targets),{'https://first.invalid/','https://display.invalid/'})
        sources=[s for s in inventory['sources'] if s['kind']=='selected_header']
        self.assertEqual([(s['field'],s['header_index']) for s in sources],[('subject',1),('from',3)])
        self.assertTrue(all(contexts(inventory,i)=={('selected_header','0','subject' if 'first' in r['url'] else 'from')} for i,r in enumerate(evidence)))

    def test_header_inventory_limits_do_not_fabricate_captured_fields(self):
        inventory,_,_=run(message().as_bytes(),limits=HeaderInventoryLimits(max_fields=1))
        selected={s['field']:s for s in inventory['sources'] if s['kind']=='selected_header'}
        self.assertEqual(selected['subject']['header_inventory_status'],'not_inventoried')
        self.assertEqual(inventory['mapped_evidence_count'],1)

    def test_link_budget_keeps_order_counts_and_partial_unmapped_prefix(self):
        extras=[{'url':'https://unmapped.invalid/'+str(i),'provenance':'observed'} for i in range(5)]
        inventory,_,_=run(message().as_bytes(),max_links=2,max_unmapped=2,extra=extras)
        self.assertEqual(inventory['total_link_count'],3)
        self.assertEqual(inventory['inventoried_link_count'],2)
        self.assertEqual(inventory['omitted_link_count'],1)
        self.assertEqual(inventory['unmapped_evidence_count'],5)
        self.assertEqual(inventory['unmapped_evidence_indexes'],[1,2])
        self.assertEqual(inventory['omitted_unmapped_index_count'],3)
        self.assertEqual(inventory['status'],'partial')
        limited,_,_=run(message().as_bytes(),max_links=2)
        self.assertEqual(limited['status'],'limited')
        self.assertEqual(limited['links'],inventory['links'])
        self.assertEqual(limited['mapped_evidence_count'],1)

    def test_zero_urls_and_invalid_limit_admission(self):
        inventory,evidence,targets=run(b'\r\nbody')
        self.assertEqual(evidence,[]);self.assertEqual(targets,[])
        self.assertEqual(inventory['total_link_count'],0)
        self.assertEqual(inventory['status'],'completed')
        for name in ('max_links','max_unmapped'):
            for value in (0,-1,True,1.5,None):
                with self.subTest(name=name,value=value),self.assertRaises(ValueError):run(b'\r\nbody',**{name:value})

    def test_source_binding_and_coverage_no_egress(self):
        raw=message().as_bytes();msg=parse_message_bytes(raw);mime=analyze_mime(msg)
        header=inventory_headers(msg,raw)
        with tempfile.TemporaryDirectory() as temp:
            body=preserve_body_parts(mime,raw,Path(temp)/'mime_body')
            wrong=copy.deepcopy(body);wrong['source']['sha256']='0'*64
            with self.assertRaises(ValueError):inventory_url_sources(mime,wrong,msg,{},header,[])
            unbound=BytesParser(policy=policy.default).parsebytes(raw)
            with self.assertRaises(ValueError):inventory_url_sources(mime,body,unbound,{},header,[])
        before=len(violations())
        with offline_policy():inventory,_,_=run(raw)
        self.assertEqual(len(violations()),before)
        coverage=url_source_coverage(inventory)
        self.assertEqual(coverage['artifact'],'url_source_inventory.json')
        for key in ('status','source_count','total_link_count','omitted_link_count','unmapped_evidence_count'):
            self.assertEqual(coverage[key],inventory[key])


if __name__=='__main__':unittest.main()
