"""Candidate observations across MIME scopes; no renderer or classifier claims."""
import copy
from email import policy
from email.message import EmailMessage
from pathlib import Path
import tempfile
import unittest
from paw.core.parser_mail import parse_message_bytes
from paw.core.mime_analysis import analyze_mime
from paw.core.mime_header_inventory import inventory_mime_headers, MimeHeaderInventoryLimits
from paw.core.mime_body_evidence import preserve_body_parts
from paw.core.mime_cid import inventory_mime_cids, cid_coverage
from paw.core.network_policy import offline_policy, violations


def sample(markup='<img src="cid:logo@local.invalid">', ids=('logo@local.invalid',)):
    msg=EmailMessage(policy=policy.SMTP);msg['From']='outer@example.invalid'
    msg.set_content(markup,subtype='html')
    for identifier in ids:
        msg.add_related(b'Benign static fixture payload',maintype='application',subtype='octet-stream',
                        cid='<'+identifier+'>',filename='resource.bin')
    return msg


def inventory(msg, limits=None, **kwargs):
    raw=msg.as_bytes();parsed=parse_message_bytes(raw);mime=analyze_mime(parsed)
    headers=inventory_mime_headers(parsed,raw,limits) if limits else inventory_mime_headers(parsed,raw)
    with tempfile.TemporaryDirectory() as temporary:
        body=preserve_body_parts(mime,raw,Path(temporary)/'mime_body')
        # EmailMessage objects in attachment records compare by identity;
        # compare serialized data views, not their deepcopy object identities.
        before=copy.deepcopy((mime['body_parts'],mime['metadata'],body,headers))
        result=inventory_mime_cids(mime,body,headers,**kwargs)
        assert before==(mime['body_parts'],mime['metadata'],body,headers)
    return result


class MimeCIDTests(unittest.TestCase):
    def test_basic_same_message_candidate_with_header_and_html_input_provenance(self):
        result=inventory(sample());self.assertEqual(result['status'],'completed')
        self.assertEqual(result['total_observation_count'],1);self.assertEqual(result['total_link_count'],1)
        self.assertEqual(result['links'],[{'observation_index':0,'content_id_index':0}])
        field=result['content_id_catalog'][0]
        self.assertEqual((field['part_id'],field['message_root_part_id'],field['identifier']),('0.1','0','logo@local.invalid'))
        source=result['html_sources'][0]
        self.assertEqual(source['part_id'],'0.0');self.assertEqual(source['message_root_part_id'],'0')
        self.assertEqual(source['representation'],'html_parser_attribute_values')
        self.assertEqual(source['derived_from']['representation'],'per_part_charset_decoded_text')
        self.assertFalse(result['verified']);self.assertTrue(result['content_id_inventory_complete'])

    def test_entities_scheme_case_percent_one_pass_and_case_sensitive_identifier(self):
        msg=sample('<img src="CID:logo%40local.invalid"><a href="cid:logo&#64;local.invalid">go</a>'
                   '<img src="cid:Logo@local.invalid"><img src="cid:logo%2540local.invalid">')
        result=inventory(msg)
        self.assertEqual([r['interpretation_status'] for r in result['observations']],
                         ['candidate_match']*2+['unmatched_in_captured_fields']*2)
        self.assertEqual(result['observations'][1]['parsed_attribute_value'],'cid:logo@local.invalid')
        self.assertEqual(result['total_link_count'],2)

    def test_duplicate_parts_and_duplicate_header_occurrences_remain_ambiguous(self):
        result=inventory(sample(ids=('logo@local.invalid',)*2))
        self.assertEqual(result['observations'][0]['interpretation_status'],'ambiguous_candidates')
        self.assertEqual(result['observations'][0]['candidate_count'],2)
        msg=sample();msg.get_payload()[1]['Content-ID']='<logo@local.invalid>'
        result=inventory(msg)
        self.assertEqual(result['observations'][0]['candidate_count'],2)
        self.assertEqual(len({r['header_index'] for r in result['content_id_catalog']}),2)
        self.assertEqual({r['part_id'] for r in result['content_id_catalog']},{'0.1'})
        msg=sample('<img src="cid:second@local.invalid">')
        msg.get_payload()[1]['Content-ID']='<second@local.invalid>'
        result=inventory(msg)
        self.assertEqual(result['observations'][0]['candidate_count'],1)
        self.assertEqual(result['links'],[{'observation_index':0,'content_id_index':1}])

    def test_inner_ids_never_match_outer_references_and_attached_html_is_not_parsed(self):
        inner=sample();outer=sample(ids=());outer.add_attachment(inner,filename='inner.eml')
        outer.add_attachment('<img src="cid:attached@local.invalid">',subtype='html',filename='inside.html')
        result=inventory(outer)
        self.assertEqual(result['total_observation_count'],1);self.assertEqual(result['links'],[])
        self.assertEqual(result['observations'][0]['interpretation_status'],'unmatched_in_captured_fields')
        self.assertTrue(all(r['message_root_part_id']!='0' for r in result['content_id_catalog']))

    def test_complex_marker_attributes_do_not_invent_parsed_cid_references(self):
        result=inventory(sample('<img srcset="cid:logo@local.invalid 1x, cid:other@local.invalid 2x">'
            '<div style="background:url(cid:logo@local.invalid)"></div>'
            '<script>"<img src=cid:script@local.invalid>"</script><!-- <img src="cid:comment@local.invalid"> -->'))
        self.assertEqual(result['total_observation_count'],2);self.assertEqual(result['complex_attribute_count'],2)
        self.assertEqual(result['direct_reference_count'],0);self.assertEqual(result['links'],[])
        self.assertEqual(result['status'],'partial')
        self.assertTrue(all(r['reason']=='complex_attribute_not_parsed' for r in result['observations']))

    def test_malformed_percent_non_ascii_controls_and_unwrapped_headers(self):
        for value in ('bad%ZZ','bad%','bad%ff','bad%00','bad%20id','%3clogo%3e',''):
            with self.subTest(value=value):
                result=inventory(sample('<img src="cid:'+value+'">'))
                self.assertEqual(result['observations'][0]['interpretation_status'],'not_interpreted')
                self.assertEqual(result['links'],[]);self.assertEqual(result['status'],'partial')
        msg=sample();msg.get_payload()[1].replace_header('Content-ID','logo@local.invalid')
        result=inventory(msg);self.assertFalse(result['content_id_inventory_complete'])
        self.assertEqual(result['content_id_catalog'][0]['interpretation_status'],'not_interpreted')

    def test_parser_state_and_attribute_occurrence_indexes_are_independent(self):
        msg=sample('<script>unclosed',ids=())
        msg.add_alternative('<img src="cid:x@local.invalid" src="cid:y@local.invalid">',subtype='html')
        result=inventory(msg)
        self.assertEqual(result['total_observation_count'],2)
        self.assertEqual([r['element_index'] for r in result['observations']],[0,0])
        self.assertEqual([r['attribute_index'] for r in result['observations']],[0,1])
        self.assertEqual({r['source_index'] for r in result['observations']},{1})

    def test_observation_link_value_budgets_and_scope_counts(self):
        msg=sample('<img src="cid:logo@local.invalid">'*5,ids=('logo@local.invalid',)*2)
        result=inventory(msg,max_observations=3,max_links=4)
        self.assertEqual((result['total_observation_count'],result['inventoried_observation_count'],result['omitted_observation_count']),(5,3,2))
        self.assertEqual((result['total_link_count'],result['inventoried_link_count'],result['omitted_link_count']),(6,4,2))
        self.assertEqual(result['links'],[{'observation_index':r,'content_id_index':i} for r in range(2) for i in range(2)])
        limited=inventory(msg,max_value_bytes=4)
        self.assertTrue(all(r['parsed_attribute_value'] is None for r in limited['observations']))
        self.assertTrue(all(r['value_status']=='limited' and r['reason']=='value_capture_limit' for r in limited['observations']))
        self.assertEqual(limited['captured_value_utf8_bytes'],0)
        budget=inventory(msg,max_total_value_bytes=40)
        self.assertLessEqual(budget['captured_value_utf8_bytes'],40);self.assertIn('value_capture_limit',budget['issues'])

    def test_header_omissions_and_missing_scope_are_explicit(self):
        result=inventory(sample(),limits=MimeHeaderInventoryLimits(max_fields=1))
        self.assertFalse(result['content_id_inventory_complete']);self.assertEqual(result['status'],'partial')
        result=inventory(sample(),limits=MimeHeaderInventoryLimits(max_parts=1))
        self.assertEqual(result['observations'][0]['reason'],'message_scope_unavailable')

    def test_zero_inputs_invalid_limits_bindings_and_no_egress(self):
        msg=EmailMessage();msg.set_content('no html')
        self.assertEqual(inventory(msg)['total_observation_count'],0)
        for key in ('max_observations','max_links','max_value_bytes','max_total_value_bytes'):
            for value in (0,-1,True,1.5,None):
                with self.assertRaises(ValueError):inventory(sample(),**{key:value})
        raw=sample().as_bytes();parsed=parse_message_bytes(raw);mime=analyze_mime(parsed)
        headers=inventory_mime_headers(parsed,raw)
        with tempfile.TemporaryDirectory() as temp:
            body=preserve_body_parts(mime,raw,Path(temp)/'mime_body');wrong=copy.deepcopy(headers)
            wrong['source']['sha256']='0'*64
            with self.assertRaises(ValueError):inventory_mime_cids(mime,body,wrong)
            body['parts'][0]['text_sha256']='0'*64
            with self.assertRaises(ValueError):inventory_mime_cids(mime,body,headers)
        before=len(violations())
        with offline_policy():result=inventory(sample())
        self.assertEqual(len(violations()),before)
        self.assertEqual(cid_coverage(result)['artifact'],'mime_cid_inventory.json')


if __name__=='__main__':unittest.main()
