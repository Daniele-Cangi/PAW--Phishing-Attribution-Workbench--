"""Local FileMonitor admission, actual files and ownership-state boundaries."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from paw.core.network_policy import offline_policy, violations
from paw.sentinel.file_monitor import FileMonitor


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() if p.is_file() else None
            for p in root.rglob('*')}


class SentinelLocalFiles(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.cases = self.root / 'cases'
        self.cases.mkdir()
        self.policy = offline_policy()
        self.policy.__enter__()
        self.before_violations = len(violations())

    def tearDown(self):
        blocked = violations()[self.before_violations:]
        self.policy.__exit__(None, None, None)
        self.temporary.cleanup()
        self.assertEqual(blocked, [])

    def owned(self):
        case = self.cases / 'case-z-owned'
        case.mkdir()
        (case / 'input.eml').write_bytes(b'Original stored bytes')
        (case / 'manifest.json').write_text(json.dumps({'analysis_job': 'analysis_stored'}), encoding='utf-8')
        control = self.root / 'jobs' / 'analysis_stored'
        control.mkdir(parents=True)
        return case, control

    def state(self, control, status, stopped):
        (control / 'supervisor.json').write_text(json.dumps({'tree_stopped': stopped}), encoding='utf-8')
        (control.parent / 'analysis_stored.json').write_text(json.dumps({'status': status}), encoding='utf-8')

    def test_default_constructor_creates_no_campaign_storage_and_preserves_injection(self):
        before = snapshot(self.root)
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            self.assertIsNone(FileMonitor().db)
            provided = object()
            self.assertIs(FileMonitor(database=provided).db, provided)
        finally:
            os.chdir(previous)
        self.assertEqual(snapshot(self.root), before)

    def test_every_case_reader_blocks_unknown_or_running_ownership_before_seal_checks(self):
        case, control = self.owned()
        monitor = FileMonitor(self.cases)
        reads = (lambda: monitor.get_case_files(case.name),
                 lambda: monitor.verify_merkle_integrity(case.name),
                 lambda: monitor.check_file_changes(case.name),
                 monitor.monitor_all_cases, monitor.generate_integrity_report)
        for status, stopped in (('running', True), ('queued', True),
                                ('recovery_blocked', True), ('completed', False)):
            self.state(control, status, stopped)
            before = snapshot(self.root)
            for read in reads:
                with self.assertRaisesRegex(RuntimeError, 'Worker shutdown not confirmed'):
                    read()
                self.assertEqual(monitor._baseline_hashes, {})
                self.assertEqual(snapshot(self.root), before)
        self.state(control, 'completed', True)
        before = snapshot(self.root)
        self.assertEqual(len(monitor.get_case_files(case.name)), 2)
        self.assertIsNone(monitor.verify_merkle_integrity(case.name)[0])
        self.assertEqual(monitor.generate_integrity_report()['integrity_summary']['unknown'], 1)
        self.assertEqual(snapshot(self.root), before)

    def test_mixed_selection_preflight_does_not_advance_neighbor_baseline_or_hide_errors(self):
        good = self.cases / 'case-a-stored'
        good.mkdir()
        (good / 'input.eml').write_bytes(b'Original neighboring bytes')
        case, control = self.owned()
        self.state(control, 'running', False)
        monitor = FileMonitor(self.cases)
        before = snapshot(self.root)
        for read in (monitor.monitor_all_cases, monitor.generate_integrity_report):
            with self.assertRaisesRegex(RuntimeError, 'Worker shutdown not confirmed'):
                read()
            self.assertEqual(monitor._baseline_hashes, {})
            self.assertEqual(snapshot(self.root), before)
        # Missing ownership state is an explicit source error, not compromise or
        # a healthy empty change list. The guard must run before missing-seal tests.
        (control.parent / 'analysis_stored.json').unlink()
        (control / 'supervisor.json').unlink()
        control.rmdir()
        with self.assertRaises(FileNotFoundError):
            monitor.verify_merkle_integrity(case.name)


if __name__ == '__main__':
    unittest.main()
