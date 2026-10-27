#!/usr/bin/env python3
"""Check text-only publication contents and reproducible helper checksums."""
import argparse
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_SUFFIXES = {'.apk', '.elf', '.tar', '.gz', '.zip', '.png', '.jpg', '.pcap', '.pcapng', '.pem', '.p12', '.pub'}
SKIP_DIRS = {'.git', '__pycache__', '.venv', '.pytest_cache'}

def files():
    return sorted(p for p in ROOT.rglob('*') if p.is_file() and not any(x in SKIP_DIRS for x in p.relative_to(ROOT).parts) and p.suffix not in {'.pyc', '.pyo'})

def inspect(paths):
    for path in paths:
        rel = path.relative_to(ROOT)
        if path.is_symlink() or path.suffix.lower() in FORBIDDEN_SUFFIXES or path.name.startswith('adbkey'):
            raise ValueError('Unpublishable artifact: ' + str(rel))
        data = path.read_bytes()
        if b'\0' in data or len(data) > 256 * 1024:
            raise ValueError('Unexpected binary/large file: ' + str(rel))
        text = data.decode('utf-8')
        marker = '-----BEGIN ' + '(?:RSA |OPENSSH |EC )?PRIVATE KEY-----'
        if re.search(marker, text) or re.search(r'gh[pousr]_[A-Za-z0-9]{30,}', text):
            raise ValueError('Credential pattern: ' + str(rel))
        if any(part in {'state', 'backups', 'evidence', 'local'} for part in rel.parts):
            raise ValueError('Device state must be outside checkout: ' + str(rel))

def checksums(paths):
    return ''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.relative_to(ROOT).as_posix() + '\n'
                   for p in paths if p.name != 'SHA256SUMS')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--write', action='store_true', help='Regenerate SHA256SUMS after reviewing source changes')
    args = p.parse_args()
    paths = files()
    inspect(paths)
    expected = checksums(paths)
    manifest = ROOT / 'SHA256SUMS'
    if args.write:
        manifest.write_text(expected)
    elif not manifest.exists() or manifest.read_text() != expected:
        raise ValueError('SHA256SUMS mismatch; review changes and run host/check_release.py --write')
    print('Publication contents and checksums verified (' + str(len(paths)) + ' files).')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, UnicodeError) as e:
        sys.exit(str(e))
