import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'host'))
import superbox as sb
import auth_probe


def fixture():
    p = copy.deepcopy(sb.profile())
    p['artifacts'] = p['artifacts'][:1] + [next(x for x in p['artifacts'] if x['classification'] == 'suspicious_boot_replacement')]
    payloads = {}
    for i, a in enumerate(p['artifacts']):
        data = ('synthetic-test-artifact-' + str(i)).encode()
        a['sha256'], a['size'] = sb.sha(data), len(data)
        payloads[a['path']] = data
    a = {'schema': 1, 'identity_hash': sb.sha(b'synthetic-device'),
         'properties': dict(p['properties']), 'hashes': {x['path']: x['sha256'] for x in p['artifacts']}}
    return p, a, payloads

class FakeADB:
    def __init__(self, audit, payloads, corrupt=False):
        self.data, self.payloads, self.corrupt = copy.deepcopy(audit), payloads, corrupt
        self.scripts = []
    def audit(self):
        return copy.deepcopy(self.data)
    def script(self, body, **kwargs):
        self.scripts.append(body)
        if body == 'cat /proc/mounts\n':
            return '/dev/root / ext4 ro,seclabel,relatime 0 0\n'
        if 'QUARANTINE_COMPLETE' in body:
            self.data['hashes'] = {k: v for k, v in self.data['hashes'].items() if ('mv ' + k + ' ') not in body}
            return 'QUARANTINE_COMPLETE'
        return ''
    def call(self, *args, **kwargs):
        assert args[0] == 'pull'
        with tarfile.open(args[2], 'w:') as t:
            for path, data in self.payloads.items():
                if self.corrupt:
                    data = b'X' * len(data)
                m = tarfile.TarInfo(path.lstrip('/')); m.size = len(data)
                t.addfile(m, io.BytesIO(data))
        return ''

class PlanningTests(unittest.TestCase):
    def test_exact_properties_required(self):
        p, a, _ = fixture()
        with patch.object(sb, 'profile', return_value=p):
            self.assertTrue(sb.build_plan(a)['supported'])
            a['properties']['ro.build.display.id'] += '-different'
            plan = sb.build_plan(a, True)
            self.assertFalse(plan['supported'])
            self.assertFalse(any(x['selected'] for x in plan['artifacts']))

    def test_unknown_hash_is_not_selected(self):
        p, a, _ = fixture(); a['hashes'][p['artifacts'][0]['path']] = 'f' * 64
        with patch.object(sb, 'profile', return_value=p):
            plan = sb.build_plan(a, True)
        self.assertEqual(plan['artifacts'][0]['status'], 'unknown')
        self.assertFalse(plan['artifacts'][0]['selected'])

    def test_boot_replacement_requires_specific_opt_in(self):
        p, a, _ = fixture()
        with patch.object(sb, 'profile', return_value=p):
            self.assertFalse(sb.build_plan(a)['artifacts'][1]['selected'])
            self.assertTrue(sb.build_plan(a, True)['artifacts'][1]['selected'])

    def test_missing_files_are_not_a_clean_device_verdict(self):
        p, a, _ = fixture(); a['hashes'] = {}
        with patch.object(sb, 'profile', return_value=p):
            plan = sb.build_plan(a)
        self.assertTrue(all(x['status'] == 'missing' for x in plan['artifacts']))
        self.assertIn('not proof', plan['warning'])

    def test_real_profile_has_no_parent_traversal_and_valid_hashes(self):
        p = sb.profile()
        self.assertEqual(len(p['artifacts']), 12)
        self.assertEqual(len({a['path'] for a in p['artifacts']}), 12)

class QuarantineTests(unittest.TestCase):
    def run_case(self, change=None, corrupt=False, boot=False):
        p, audit, payloads = fixture(); fresh = copy.deepcopy(audit)
        if change:
            change(fresh, p)
        fake = FakeADB(fresh, payloads, corrupt)
        with tempfile.TemporaryDirectory() as d, patch.object(sb, 'profile', return_value=p):
            result = sb.quarantine(fake, audit, Path(d), boot)
            self.assertEqual((Path(d) / 'before.json').stat().st_mode & 0o777, 0o600)
        return result, fake

    def test_verified_backup_precedes_moves_and_boot_file_is_preserved(self):
        result, fake = self.run_case()
        self.assertTrue(result['changed'])
        mutation = next(x for x in fake.scripts if 'QUARANTINE_COMPLETE' in x)
        self.assertIn('mount -o remount,ro /', mutation)
        self.assertNotIn('mv /system/bin/bootanimation ', mutation)

    def test_changed_identity_refuses_before_device_write(self):
        p, a, data = fixture(); fresh = copy.deepcopy(a); fresh['identity_hash'] = 'different'
        fake = FakeADB(fresh, data)
        with tempfile.TemporaryDirectory() as d, patch.object(sb, 'profile', return_value=p):
            with self.assertRaisesRegex(sb.Refused, 'identity'):
                sb.quarantine(fake, a, Path(d))
        self.assertEqual(fake.scripts, [])

    def test_newly_appeared_artifact_requires_a_new_saved_audit(self):
        p, a, data = fixture(); fresh = copy.deepcopy(a); a['hashes'] = {}
        fake = FakeADB(fresh, data)
        with tempfile.TemporaryDirectory() as d, patch.object(sb, 'profile', return_value=p):
            with self.assertRaisesRegex(sb.Refused, 'changed'):
                sb.quarantine(fake, a, Path(d))
        self.assertEqual(fake.scripts, [])

    def test_bad_backup_never_reaches_mutation(self):
        p, a, data = fixture(); fake = FakeADB(a, data, corrupt=True)
        with tempfile.TemporaryDirectory() as d, patch.object(sb, 'profile', return_value=p):
            with self.assertRaisesRegex(sb.Refused, 'hash mismatch'):
                sb.quarantine(fake, a, Path(d))
        self.assertFalse(any('QUARANTINE_COMPLETE' in x for x in fake.scripts))
        self.assertFalse(any('remount,rw' in x for x in fake.scripts))

    def test_unsupported_model_refuses_before_backup_or_mutation(self):
        p, a, data = fixture(); a['properties']['ro.product.model'] = 'other'
        fake = FakeADB(a, data)
        with tempfile.TemporaryDirectory() as d, patch.object(sb, 'profile', return_value=p):
            with self.assertRaisesRegex(sb.Refused, 'exact reference'):
                sb.quarantine(fake, a, Path(d), True)
        self.assertEqual(fake.scripts, [])

    def test_second_run_is_no_op(self):
        p, a, data = fixture(); a['hashes'] = {}; fake = FakeADB(a, data)
        with tempfile.TemporaryDirectory() as d, patch.object(sb, 'profile', return_value=p):
            result = sb.quarantine(fake, a, Path(d))
        self.assertFalse(result['changed'])
        self.assertEqual(fake.scripts, [])

    def test_symlink_backup_member_rejected(self):
        p, a, data = fixture(); artifact = p['artifacts'][0]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'backup.tar'
            with tarfile.open(path, 'w') as t:
                m = tarfile.TarInfo(artifact['path'].lstrip('/')); m.type = tarfile.SYMTYPE; m.linkname = '/etc/passwd'; t.addfile(m)
            with self.assertRaises(sb.Refused):
                sb.verify_archive(path, [artifact])

class InputAndStateTests(unittest.TestCase):
    def test_only_small_explicit_rfc1918_networks(self):
        for value in ('8.8.8.0/24', '127.0.0.0/24', '169.254.0.0/24', '100.64.0.0/24', '192.168.0.0/16', '10.0.0.1/24', '::/128'):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                sb.private_network(value)
        self.assertEqual(str(sb.private_network('192.168.50.0/24')), '192.168.50.0/24')

    def test_device_cannot_inject_command_or_target_internet(self):
        for value in ('--help', '$(id)', 'x;id', '8.8.8.8:5555', '192.168.50.5:0', '192.168.50.5:99999'):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                sb.device_arg(value)
        self.assertEqual(sb.device_arg('192.168.50.5:5858'), '192.168.50.5:5858')
        self.assertEqual(sb.device_arg('usb_serial-123'), 'usb_serial-123')

    def test_state_cannot_be_inside_repository(self):
        with self.assertRaisesRegex(sb.Refused, 'outside'):
            sb.state_dir(str(ROOT / 'state'))

    def test_state_is_private_and_existing_evidence_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            p = sb.state_dir(str(Path(d).resolve()))
            self.assertEqual(p.stat().st_mode & 0o777, 0o700)
            sb.write_json(p / 'audit.json', {'synthetic': True})
            with self.assertRaisesRegex(sb.Refused, 'previous evidence'):
                sb.state_dir(str(Path(d).resolve()))

    def test_symlink_state_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            link = Path(d) / 'link'; target = Path(d) / 'real'; target.mkdir(); link.symlink_to(target)
            with self.assertRaisesRegex(sb.Refused, 'symlink'):
                sb.state_dir(str(link))

    def test_json_output_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            victim = Path(d) / 'victim'; victim.write_text('unchanged')
            link = Path(d) / 'link'; link.symlink_to(victim)
            with self.assertRaises(OSError):
                sb.write_json(link, {})
            self.assertEqual(victim.read_text(), 'unchanged')

    def test_mutation_requires_apply_and_root_before_adb(self):
        with patch.object(sb.ADB, 'connect') as connect:
            with self.assertRaisesRegex(sb.Refused, '--apply and --root'):
                sb.main(['lockdown', '--device', '192.168.50.5:5555'])
        connect.assert_not_called()

    def test_cli_help(self):
        r = subprocess.run([sys.executable, str(ROOT / 'host/superbox.py'), '--help'], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn('quarantine', r.stdout)

class AuthProbeTests(unittest.TestCase):
    def test_fragmented_auth_challenge(self):
        import struct
        cmd = int.from_bytes(b'AUTH', 'little')
        header = struct.pack('<6I', cmd, 1, 0, 20, 0, cmd ^ 0xffffffff)
        connection = unittest.mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.side_effect = [header[:5], header[5:]]
        with patch.object(auth_probe.socket, 'create_connection', return_value=connection):
            self.assertEqual(auth_probe.probe('192.168.50.5:5555'), 'AUTH')
        self.assertEqual(connection.sendall.call_args[0][0][:4], b'CNXN')

class FirewallTests(unittest.TestCase):
    def run_guard(self, ip, fail=False):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d); log = p / 'log'
            (p / 'id').write_text('#!/bin/sh\necho 0\n')
            fw = '''#!/bin/sh
printf '%s %s\\n' "$(basename "$0")" "$*" >> "$FW_LOG"
[ "$1" != -C ] || exit 1
if [ "${FAIL_MATCH:-}" = 1 ] && [ "$1" = -A ] && [ "$6" = 5858 ]; then exit 2; fi
exit 0
'''
            for name in ('iptables', 'ip6tables'):
                (p / name).write_text(fw)
            for f in p.iterdir():
                f.chmod(0o700)
            env = dict(os.environ, PATH=d + ':' + os.environ['PATH'], FW_LOG=str(log), FAIL_MATCH='1' if fail else '0')
            r = subprocess.run(['sh', str(ROOT / 'runtime/access-guard.sh'), ip], env=env, capture_output=True, text=True)
            return r, log.read_text() if log.exists() else ''

    def test_private_address_in_rules_and_no_broad_drop_or_multiport(self):
        r, log = self.run_guard('192.168.50.20')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('-s 192.168.50.20 -j ACCEPT', log)
        self.assertIn('iptables -I INPUT 1 -j SBC_ACCESS', log)
        self.assertIn('ip6tables -I INPUT 1 -j SBC_ACCESS', log)
        self.assertNotIn('multiport', log)
        self.assertNotIn('-P INPUT', log)
        self.assertNotIn('-A SBC_ACCESS -j DROP', log)

    def test_bad_management_addresses_fail_before_firewall(self):
        for value in ('8.8.8.8', '192.168.50.300', '192.168.50.1;id', '192.168.50', '172.15.1.1', '010.0.0.1'):
            with self.subTest(value=value):
                r, log = self.run_guard(value)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(log, '')

    def test_match_failure_does_not_attach_incomplete_chain(self):
        r, log = self.run_guard('192.168.50.20', fail=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn('-I INPUT', log)


    def test_unconfirmed_watchdog_removes_both_hooks_without_sleeping(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d); log = p / 'log'
            (p / 'id').write_text('#!/bin/sh\necho 0\n')
            (p / 'sleep').write_text('#!/bin/sh\nexit 0\n')
            fake = """#!/bin/sh
printf '%s %s\\n' "$(basename "$0")" "$*" >> "$FW_LOG"
if [ "$1" = -C ]; then
 state="$FW_LOG.$(basename "$0")"
 [ ! -f "$state" ] || exit 1
 touch "$state"
fi
exit 0
"""
            for name in ('iptables', 'ip6tables'):
                (p / name).write_text(fake)
            for f in p.iterdir():
                f.chmod(0o700)
            env = dict(os.environ, PATH=d + ':' + os.environ['PATH'], FW_LOG=str(log))
            marker = '/data/local/tmp/sbc-confirm-' + 'f' * 32
            r = subprocess.run(['sh', str(ROOT / 'runtime/access-rollback.sh'), marker], env=env, capture_output=True, text=True, timeout=3)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('iptables -D INPUT -j SBC_ACCESS', log.read_text())
            self.assertIn('ip6tables -D INPUT -j SBC_ACCESS', log.read_text())

if __name__ == '__main__':
    unittest.main()
