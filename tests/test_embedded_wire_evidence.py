"""Original embedded MIME spans versus existing derived attachment evidence."""
from email import policy
from email.parser import BytesParser
import hashlib
from pathlib import Path
import tempfile
import unittest

from paw.core.attach import scan_attachments
from paw.core.mime_analysis import analyze_mime, MimeLimits, MimeLimitExceeded
from paw.core.network_policy import offline_policy, violations
from paw.core.parser_mail import parse_message_bytes
from paw.core.evidence import seal_case
from paw.core.verify import verify_case


def entity(payload, declarations=b'', subtype=b'rfc822'):
    return (b'Content-Type: message/'+subtype+b'\r\n'
        b'Content-Disposition: attachment; filename="../../same.eml"\r\n'
        +declarations+b'\r\n'+payload)


def multipart(*entities, boundary=b'b'):
    return (b'From: outer@example.invalid\r\nContent-Type: multipart/mixed; boundary="'
        +boundary+b'"\r\n\r\npreamble\r\n'
        +b''.join(b'--'+boundary+b'\r\n'+part+b'\r\n' for part in entities)
        +b'--'+boundary+b'--\r\nepilogue')


INNER = (b'From: inner@example.invalid\r\nX-Exact: first\tvalue\r\n\tcontinued\r\n'
    b'X-Exact: duplicate\r\nAuthentication-Results: forged.invalid; dkim=pass\r\n\r\n'
    b'Inner https://inner-only.invalid/\r\n')


class EmbeddedWireEvidenceTests(unittest.TestCase):
    def check(self, raw, expected, limits=MimeLimits()):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            message = parse_message_bytes(raw, limits)
            result = analyze_mime(message, limits)
            output = scan_attachments(None, result, root/'attachments')
            originals = [item for item in output if 'original_wire' in item]
            self.assertEqual(len(originals), len(expected))
            wire_total = 0
            for item,wire in zip(originals, expected):
                metadata = item['original_wire']
                self.assertEqual(metadata['source'], {'path':'input.eml','sha256':hashlib.sha256(raw).hexdigest()})
                self.assertFalse(metadata['transfer_decoded'])
                self.assertFalse(metadata['authenticity_verified'])
                if wire is None:
                    self.assertEqual(metadata['status'], 'not_evaluated')
                    self.assertNotIn('evidence_path', metadata)
                    self.assertNotIn('sha256', metadata)
                    continue
                self.assertEqual(metadata['status'], 'captured')
                self.assertEqual(metadata['scope'], 'parser_matched_original_mime_body_span')
                self.assertEqual(metadata['size'], len(wire))
                self.assertEqual(metadata['sha256'], hashlib.sha256(wire).hexdigest())
                self.assertEqual(raw[metadata['offset']:metadata['offset']+metadata['size']], wire)
                saved = root/metadata['evidence_path']
                self.assertTrue(saved.resolve().is_relative_to((root/'attachments').resolve()))
                self.assertEqual(saved.read_bytes(), wire)
                self.assertNotEqual(metadata['evidence_path'], item['evidence_path'])
                self.assertEqual(hashlib.sha256((root/item['evidence_path']).read_bytes()).hexdigest(), item['sha256'])
                part = next(p for p in result['metadata']['parts'] if p['part_id']==item['part_id'])
                self.assertEqual({k:v for k,v in metadata.items() if k!='evidence_path'}, part['original_wire'])
                wire_total += len(wire)
            self.assertLessEqual(wire_total, len(raw))
            (root/'input.eml').write_bytes(raw)
            seal_case(root)
            self.assertTrue(verify_case(root))
            if any(wire is not None for wire in expected):
                saved.write_bytes(saved.read_bytes()+b'changed')
                self.assertFalse(verify_case(root))
            return result, output

    def test_exact_crlf_folding_duplicate_headers_and_existing_derived_contract(self):
        raw = multipart(entity(INNER))
        result, items = self.check(raw, [INNER])
        parsed = BytesParser(policy=policy.default).parsebytes(raw)
        derived = parsed.get_payload()[0].get_payload()[0].as_bytes()
        self.assertNotEqual(derived, INNER)
        self.assertEqual(items[0]['sha256'], hashlib.sha256(derived).hexdigest())
        self.assertEqual(items[0]['byte_source'], 'derived_embedded_message_serialization')
        self.assertEqual(result['body_text'], '')
        self.assertEqual(result['urls'], [])
        self.assertIsNone(items[0]['risk_score'])

    def test_root_nested_siblings_identical_payloads_and_no_recursion_into_inner(self):
        nested_inner = multipart(entity(INNER), boundary=b'inner')
        for raw, expected in (
            (entity(INNER), [INNER]),
            (multipart(multipart(entity(INNER), entity(INNER), boundary=b'sub')), [INNER, INNER]),
            (multipart(entity(nested_inner)), [nested_inner])):
            with self.subTest(count=len(expected), size=len(raw)):
                result, items = self.check(raw, expected)
                self.assertEqual(len({i['original_wire']['evidence_path'] for i in items}), len(expected))
                self.assertEqual(result['urls'], [])

    def test_empty_body_and_original_line_breaks(self):
        for wire in (b'', INNER, INNER.replace(b'\r\n', b'\n'), INNER.replace(b'\r\n', b'\r')):
            with self.subTest(size=len(wire)):
                self.check(multipart(entity(wire)), [wire])

    def test_original_span_capture_does_not_claim_transfer_decoding(self):
        for declarations in (b'Content-Transfer-Encoding: base64\r\n',
                b'Content-Transfer-Encoding: quoted-printable\r\n',
                b'Content-Transfer-Encoding: x-unknown\r\n',
                b'Content-Transfer-Encoding: 7bit\r\nContent-Transfer-Encoding: binary\r\n',
                b'Content-Transfer-Encoding: 7bit\r\n'):
            wire = INNER+b'\x00\xff'
            with self.subTest(declarations=declarations):
                _, items = self.check(multipart(entity(wire, declarations)), [wire])
                self.assertEqual(items[0]['status'], 'partial')
                self.assertEqual(items[0]['transfer_decoding']['status'], 'partial')

    def test_message_subtypes_remain_unassessed_and_wire_is_not_reconstructed(self):
        for subtype in (b'global', b'partial', b'external-body', b'delivery-status'):
            with self.subTest(subtype=subtype):
                _, items = self.check(multipart(entity(INNER, subtype=subtype)), [INNER])
                self.assertIsNone(items[0]['risk_score'])
                self.assertEqual(items[0]['malware_analysis']['status'], 'not_evaluated')

    def test_digest_implicit_message_scope(self):
        raw = (b'Content-Type: multipart/digest; boundary=b\r\n\r\n--b\r\n\r\n'
               +INNER+b'\r\n--b--\r\n')
        result, items = self.check(raw, [INNER])
        self.assertEqual(items[0]['part_id'], '0.0')
        self.assertEqual(result['urls'], [])

    def test_missing_or_malformed_framing_never_serializes_original_evidence(self):
        for raw in (
            b'Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n'+entity(INNER),
            b'Content-Type: message/rfc822\r\nnot a header\r\n\r\n'+INNER):
            with self.subTest(size=len(raw)):
                _, items = self.check(raw, [None])
                self.assertEqual(items[0]['status'], 'partial')
        result = analyze_mime(BytesParser(policy=policy.default).parsebytes(entity(INNER)))
        item, = scan_attachments(None, result)
        self.assertEqual(item['original_wire']['status'], 'not_evaluated')
        self.assertIsNone(item['original_wire']['source'])

    def test_limits_before_writes_and_no_egress(self):
        raw = multipart(entity(INNER), entity(INNER))
        message = parse_message_bytes(raw)
        for limits in (MimeLimits(max_input_bytes=len(raw)-1), MimeLimits(max_parts=2),
                       MimeLimits(max_depth=1), MimeLimits(max_decoded_bytes=1)):
            with self.subTest(limits=limits), self.assertRaises(MimeLimitExceeded):
                analyze_mime(message, limits)
        before = len(violations())
        with offline_policy(): self.check(raw, [INNER, INNER])
        self.assertEqual(len(violations()), before)

    def test_new_wire_file_is_exclusive_and_metadata_without_persistence_has_no_path(self):
        result = analyze_mime(parse_message_bytes(entity(INNER)))
        item, = scan_attachments(None, result)
        self.assertEqual(item['original_wire']['status'], 'captured')
        self.assertNotIn('evidence_path', item['original_wire'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)/'attachments'
            first, = scan_attachments(None, result, root)
            path = Path(temporary)/first['original_wire']['evidence_path']
            path.write_bytes(b'existing evidence')
            with self.assertRaises(FileExistsError): scan_attachments(None, result, root)
            self.assertEqual(path.read_bytes(), b'existing evidence')


if __name__=='__main__': unittest.main()
