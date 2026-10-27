#!/usr/bin/env python3
"""Local, standard-library helpers. Diagnostics stay outside the checkout."""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import tarfile
import tempfile
import uuid
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / 'profiles/s2pro-20211214.json'
PRIVATE_NETS = tuple(ipaddress.ip_network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
PROPS = ('ro.product.model', 'ro.build.display.id', 'ro.build.version.release',
         'ro.build.version.sdk', 'ro.build.version.security_patch', 'ro.adb.secure',
         'ro.build.fingerprint', 'sys.boot_completed')

class Refused(RuntimeError):
    pass

def sha(data):
    return hashlib.sha256(data).hexdigest()

def profile():
    p = json.loads(PROFILE.read_text())
    for a in p['artifacts']:
        if not re.fullmatch(r'/system/(?:bin|etc|priv-app)/[A-Za-z0-9_./-]+', a['path']) or '..' in a['path'].split('/'):
            raise Refused('Unsafe profile path')
        if not re.fullmatch('[0-9a-f]{64}', a['sha256']):
            raise Refused('Invalid artifact hash')
    return p

def private_network(value):
    try:
        n = ipaddress.ip_network(value, strict=True)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e
    if n.version != 4 or n.num_addresses > 1024 or not any(n.subnet_of(p) for p in PRIVATE_NETS):
        raise argparse.ArgumentTypeError('Use an explicit RFC1918 IPv4 subnet of /22 or smaller')
    return n

def device_arg(value):
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value) or value.startswith('-'):
        raise argparse.ArgumentTypeError('Invalid ADB device identifier')
    if ':' in value:
        try:
            host, port = value.rsplit(':', 1)
            ip = ipaddress.ip_address(host)
            assert ip.version == 4 and any(ip in n for n in PRIVATE_NETS) and 1 <= int(port) <= 65535
        except (ValueError, AssertionError) as e:
            raise argparse.ArgumentTypeError('Network targets must be RFC1918 IPv4:port') from e
    return value

def state_dir(value=None):
    # Never create evidence or secrets under the checkout, even with an explicit path.
    p = Path(value).expanduser().resolve() if value else Path.home() / '.local/state/superbox-clean' / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    if p == ROOT or ROOT in p.parents:
        raise Refused('State/backup directory must be outside the checkout')
    # Existing symlinks are rejected before resolution for explicit paths.
    if value:
        raw = Path(value).expanduser().absolute()
        if any(x.is_symlink() for x in (raw, *raw.parents)):
            raise Refused('State path must not contain symlinks')
    if p.exists() and any(p.iterdir()):
        raise Refused('Choose a new empty state directory; previous evidence must not be overwritten')
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    if p.stat().st_uid != os.getuid():
        raise Refused('State directory must be owned by the current user')
    p.chmod(0o700)
    return p

def write_json(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), 'w') as f:
        json.dump(data, f, indent=2)
        f.write('\n')

def parse_props(output):
    return {k: v for k, v in re.findall(r'^\[([^\]]+)\]: \[(.*)\]$', output, re.M)}

def supported(audit, p=None):
    p = p or profile()
    return all(audit['properties'].get(k) == v for k, v in p['properties'].items())

def build_plan(audit, include_boot=False):
    p = profile()
    if audit.get('schema') != 1 or not isinstance(audit.get('properties'), dict):
        raise Refused('Not a version 1 audit')
    rows = []
    for a in p['artifacts']:
        current = audit.get('hashes', {}).get(a['path'])
        status = 'missing' if current is None else 'match' if current == a['sha256'] else 'unknown'
        selected = (status == 'match' and supported(audit, p) and
                    (include_boot or a['classification'] != 'suspicious_boot_replacement'))
        rows.append(dict(a, status=status, selected=selected))
    return {'schema': 1, 'profile': p['id'], 'supported': supported(audit, p),
            'identity_hash': audit.get('identity_hash'), 'artifacts': rows,
            'warning': 'Exact hash matches only. Unknown artifacts require analysis; absence is not proof of a clean device.'}

class ADB:
    def __init__(self, device, executable='adb', root=False):
        self.device, self.executable, self.root = device, executable, root

    def call(self, *args, timeout=45):
        try:
            r = subprocess.run([self.executable, '-s', self.device, *args],
                               text=True, capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise Refused(f'ADB failed: {e}') from e
        if r.returncode:
            raise Refused(f'ADB {args[0]} failed: {(r.stderr or r.stdout).strip()}')
        return r.stdout.replace('\r\n', '\n')

    def connect(self):
        if ':' in self.device:
            self.call('connect', self.device, timeout=10)
        if self.call('get-state').strip() != 'device':
            raise Refused('ADB is not ready; authorize its key on the device if prompted')

    def script(self, body, root=None, timeout=60):
        root = self.root if root is None else root
        remote = '/data/local/tmp/superbox-clean-' + uuid.uuid4().hex + '.sh'
        with tempfile.TemporaryDirectory(prefix='superbox-clean-') as td:
            path = Path(td) / 'script.sh'
            path.write_text('#!/system/bin/sh\n' + ('[ "$(id -u)" = 0 ] || exit 91\n' if root else '') + body)
            path.chmod(0o600)
            self.call('push', str(path), remote)
        try:
            cmd = 'sh ' + shlex.quote(remote)
            if root and self.call('shell', '-T', 'id -u').strip() != '0':
                cmd = 'su -c ' + shlex.quote(cmd)
            return self.call('shell', '-T', cmd, timeout=timeout)
        finally:
            self.call('shell', '-T', 'rm -f ' + shlex.quote(remote))

    def audit(self):
        # No packet payloads, screenshots, Wi-Fi credentials, account files, or app data.
        all_props = parse_props(self.call('shell', '-T', 'getprop'))
        commands = ['set -e', 'for f in ' + ' '.join(shlex.quote(a['path']) for a in profile()['artifacts']) + '; do',
                    ' if [ -f "$f" ]; then sha256sum "$f"; fi', 'done']
        output = self.script('\n'.join(commands))
        hashes = {}
        for line in output.splitlines():
            m = re.fullmatch(r'([0-9a-f]{64})\s+(/system/.*)', line)
            if m:
                hashes[m[2]] = m[1]
        serial = all_props.get('ro.serialno', '')
        if not serial:
            raise Refused('No hardware serial property; cannot bind evidence safely to this device')
        data = {'schema': 1, 'created_utc': datetime.now(timezone.utc).isoformat(),
                'identity_hash': sha((serial + '\0' + all_props.get('ro.build.fingerprint', '')).encode()),
                'properties': {k: all_props.get(k, '') for k in PROPS}, 'hashes': hashes,
                'packages': self.call('shell', '-T', 'pm list packages -f -U').splitlines(),
                'processes': self.call('shell', '-T', 'ps -A -o PID,NAME,ARGS').splitlines(),
                'user_restrictions': self.call('shell', '-T', 'dumpsys user'),
                'webview': self.call('shell', '-T', 'dumpsys webviewupdate')}
        return data

def verify_archive(path, selected):
    if path.stat().st_size > sum(a['size'] for a in selected) + 102400:
        raise Refused('Backup archive exceeds the expected size budget')
    with tarfile.open(path, 'r:') as archive:
        for a in selected:
            members = [m for m in archive.getmembers() if m.name.lstrip('/') == a['path'].lstrip('/')]
            if len(members) != 1 or not members[0].isfile() or members[0].size != a['size']:
                raise Refused('Backup member missing, duplicated, or unexpected: ' + a['path'])
            f = archive.extractfile(members[0])
            if f is None or sha(f.read(a['size'] + 1)) != a['sha256']:
                raise Refused('Backup hash mismatch: ' + a['path'])
    # Deliberately never extract an archive supplied by a compromised device.

def quarantine(adb, audit, state, include_boot=False):
    fresh = adb.audit()
    if not audit.get('identity_hash') or audit['identity_hash'] != fresh['identity_hash']:
        raise Refused('Device identity changed since the audit')
    plan = build_plan(fresh, include_boot)
    if not plan['supported']:
        raise Refused('Quarantine is supported only on the exact reference model/firmware')
    selected = [a for a in plan['artifacts'] if a['selected']]
    # An unknown hash never becomes a mutation target, including at familiar paths.
    for a in selected:
        if audit.get('hashes', {}).get(a['path']) != a['sha256']:
            raise Refused('Artifact changed since the saved audit; inspect a fresh audit first')
    write_json(state / 'before.json', fresh)
    write_json(state / 'plan.json', plan)
    if not selected:
        return {'changed': False, 'message': 'No matching artifacts; unknown files were not modified.'}
    layout = adb.script('cat /proc/mounts\n', root=True)
    if not re.search(r'^/dev/root / ext4 ', layout, re.M):
        raise Refused('Unsupported system mount layout; no files were moved')
    run_id = uuid.uuid4().hex
    remote = '/data/local/tmp/sbc-backup-' + run_id + '.tar'
    paths = ' '.join(shlex.quote(a['path']) for a in selected)
    archive = state / 'quarantine-backup.tar'
    # Reserve a regular private file; ADB must not follow an existing symlink.
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    adb.script('set -e\n' + f'tar -cf {remote} {paths}\nchown 2000:2000 {remote}\nchmod 600 {remote}\n', root=True)
    try:
        adb.call('pull', remote, str(archive), timeout=120)
        archive.chmod(0o600)
        verify_archive(archive, selected)
    finally:
        adb.script('rm -f ' + shlex.quote(remote), root=True)
    checks = []
    for a in selected:
        f = shlex.quote(a['path'])
        checks.append('[ "$(sha256sum ' + f + ' | cut -d " " -f1)" = ' + shlex.quote(a['sha256']) + ' ] || exit 92')
    dest = '/system/superbox-clean-quarantine/' + run_id
    actions = []
    chosen_paths = {a['path'] for a in selected}
    if '/system/etc/init/turbovpn.rc' in chosen_paths:
        actions.append('stop turbovpn')
    for pkg in ('com.android.door', 'com.android.notes'):
        prefix = '/system/priv-app/' + ('Door' if pkg.endswith('door') else 'Notes') + '/'
        if any(x.startswith(prefix) for x in chosen_paths):
            actions.append('am force-stop ' + pkg)
    # Kill only the exact captured native payload, never by process name alone.
    payloads = '|'.join(sorted(set(profile()['payload_hashes'])))
    actions.extend(['for exe in /proc/[0-9]*/exe; do',
                    ' h=$(sha256sum "$exe" 2>/dev/null | cut -d " " -f1)',
                    ' case "$h" in ' + payloads + ') pid=${exe#/proc/}; pid=${pid%/exe}; kill -9 "$pid" 2>/dev/null || true;; esac', 'done'])
    actions += ['mount -o remount,rw /', "trap 'mount -o remount,ro /' EXIT HUP INT TERM", 'mkdir -p ' + dest, 'chmod 700 /system/superbox-clean-quarantine ' + dest]
    for a in selected:
        target = dest + a['path']
        actions += ['mkdir -p ' + shlex.quote(str(Path(target).parent)),
                    'mv ' + shlex.quote(a['path']) + ' ' + shlex.quote(target),
                    'chmod 600 ' + shlex.quote(target)]
    actions += ['sync', 'mount -o remount,ro /', 'trap - EXIT HUP INT TERM', 'echo QUARANTINE_COMPLETE']
    # All hashes rechecked before stopping a service or mounting writable.
    result = adb.script('set -e\n' + '\n'.join(checks + actions), root=True, timeout=120)
    after = adb.audit()
    if any(a['path'] in after['hashes'] for a in selected):
        raise Refused('Some quarantine targets remain; inspect private state before rebooting')
    write_json(state / 'after.json', after)
    record = {'changed': True, 'device_quarantine': dest, 'backup_sha256': sha(archive.read_bytes()),
              'result': result, 'paths': [a['path'] for a in selected]}
    write_json(state / 'quarantine-result.json', record)
    return record

def discover(network, ports):
    def probe(target):
        ip, port = target
        try:
            with socket.create_connection((str(ip), port), timeout=.4):
                return str(ip) + ':' + str(port)
        except OSError:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        return sorted(x for x in executor.map(probe, ((ip, port) for ip in network.hosts() for port in ports)) if x)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command', required=True)
    scan = subs.add_parser('discover', help='Probe only three common ADB ports on an explicit private subnet')
    scan.add_argument('--network', required=True, type=private_network)
    scan.add_argument('--ports', nargs='+', type=int, default=[5555, 5858, 63002])
    planning = subs.add_parser('plan', help='Offline plan; never changes the device')
    planning.add_argument('--audit', required=True, type=Path)
    planning.add_argument('--include-suspicious-boot-files', action='store_true')
    for name in ('audit', 'quarantine', 'lockdown', 'allow-installs', 'verify'):
        sub = subs.add_parser(name)
        sub.add_argument('--device', required=True, type=device_arg)
        sub.add_argument('--adb', default='adb')
        sub.add_argument('--state', help='Private output directory outside this repository')
        sub.add_argument('--root', action='store_true', help='Use an existing root shell or installed su; does not exploit or root the device')
        if name == 'quarantine':
            sub.add_argument('--audit', required=True, type=Path)
            sub.add_argument('--include-suspicious-boot-files', action='store_true')
        if name in ('quarantine', 'lockdown', 'allow-installs'):
            sub.add_argument('--apply', action='store_true', help='Required for device changes')
    args = parser.parse_args(argv)
    if args.command == 'discover':
        if not args.ports or any(p < 1 or p > 65535 for p in args.ports) or len(args.ports) > 8:
            raise Refused('Use one to eight valid TCP ports')
        print(json.dumps({'candidates': discover(args.network, args.ports),
                          'warning': 'Open ports are not proof of Superbox identity. No devices were authenticated or modified.'}, indent=2))
        return
    if args.command == 'plan':
        print(json.dumps(build_plan(json.loads(args.audit.read_text()), args.include_suspicious_boot_files), indent=2))
        return
    if args.command in ('quarantine', 'lockdown', 'allow-installs') and (not args.apply or not args.root):
        raise Refused('Changes require both --apply and --root; audit/plan are the default workflow')
    state = state_dir(args.state)
    adb = ADB(args.device, args.adb, args.root)
    adb.connect()
    if args.command == 'quarantine':
        result = quarantine(adb, json.loads(args.audit.read_text()), state, args.include_suspicious_boot_files)
        print(json.dumps(result, indent=2))
    else:
        before = adb.audit()
        write_json(state / 'before.json', before)
        if args.command in ('lockdown', 'allow-installs'):
            if not supported(before):
                raise Refused('Mutation profiles are limited to the exact reference model/firmware; see docs/COMPATIBILITY.md')
            script = ROOT / 'runtime' / (args.command + '.sh')
            result = adb.script(script.read_text(), root=True)
            write_json(state / 'command-result.json', {'command': args.command, 'result': result})
            write_json(state / 'after.json', adb.audit())
        if args.command == 'verify':
            p = build_plan(before)
            notes = [a['path'] for a in p['artifacts'] if a['status'] == 'match']
            print(json.dumps({'known_artifacts_remaining': notes, 'profile_supported': p['supported'],
                              'secure_adb_property': before['properties']['ro.adb.secure'],
                              'warning': 'Inspect restrictions and processes in the saved audit. This is not a clean-device certificate.'}, indent=2))
        else:
            print('Saved private evidence to ' + str(state))

if __name__ == '__main__':
    try:
        main()
    except (Refused, ValueError, KeyError, OSError, tarfile.TarError) as e:
        print('Stopped: ' + str(e), file=sys.stderr)
        sys.exit(1)
