#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Shared deployment primitives. No third-party Python packages are required."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile

INSTANCE = re.compile(r'(vless|vmess|anytls|hysteria|hysteria2)-[1-9][0-9]*\Z')


class Paths:
    def __init__(self, root=Path('/')):
        self.root = Path(root)
        self.binary = self.at('/usr/local/bin/elise')
        self.manager = self.at('/usr/local/bin/elisectl')
        self.support = self.at('/usr/local/lib/elise')
        self.licenses = self.at('/usr/local/share/licenses/elise')
        self.config = self.at('/etc/elise/instances')
        self.units = self.at('/etc/systemd/system')
        self.unit = self.units / 'elise@.service'
        self.legacy_config = self.at('/etc/v2bx-elise')
        self.legacy_binary = self.at('/usr/local/libexec/V2bX/elise')
        self.legacy_helper = self.at('/usr/bin/V2bX-elise')
        self.backups = self.at('/var/lib/elise/backups')

    def at(self, absolute):
        return self.root / absolute.lstrip('/')


class Systemd:
    def run(self, *args):
        return subprocess.run(['systemctl', *args], check=True, capture_output=True, text=True).stdout.strip()

    def property(self, unit, name):
        return self.run('show', unit, '--property=' + name, '--value')

    def active(self, unit):
        state = self.property(unit, 'ActiveState')
        if state not in ('active', 'inactive', 'failed'):
            raise RuntimeError(f'{unit} is {state}; wait for it to settle before continuing')
        return state == 'active'

    def enabled(self, unit):
        state = self.property(unit, 'UnitFileState')
        if state not in ('enabled', 'disabled', 'masked'):
            raise RuntimeError(f'{unit} has unsupported enable state {state!r}; use a persistent enabled/disabled state first')
        return state


def instances(directory):
    for config in sorted(directory.glob('*/elise.conf')):
        if not INSTANCE.fullmatch(config.parent.name):
            raise RuntimeError(f'Unrecognized instance directory: {config.parent}')
        yield config.parent.name


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def public_directory(path):
    """Create public program/license directories without changing existing modes."""
    missing = []
    current = Path(path)
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir()
        directory.chmod(0o755)


def write_json(path, value):
    atomic_write(path, (json.dumps(value, indent=2) + '\n').encode())


@contextlib.contextmanager
def deployment_lock(paths):
    lock = paths.at('/run/lock/elise.lock')
    lock.parent.mkdir(parents=True, exist_ok=True)
    with lock.open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another Elise management operation is running') from None
        yield


def handle_signals():
    def interrupted(signum, _frame):
        raise InterruptedError(f'Interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)


def health_check(paths, instance):
    subprocess.run([str(paths.manager), '__health', instance], check=True, timeout=420)


class FileBackup:
    """Keep original bytes and modes in a private, persistent rollback directory."""
    def __init__(self, paths, prefix):
        paths.backups.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(paths.backups, 0o700)
        self.directory = Path(tempfile.mkdtemp(prefix=prefix, dir=paths.backups))
        self.entries = []

    def save(self, path):
        path = Path(path)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise RuntimeError(f'Refusing to replace a non-regular file: {path}')
        backup = self.directory / str(len(self.entries))
        mode = path.stat().st_mode & 0o777 if path.exists() else None
        if mode is not None:
            shutil.copy2(path, backup)
        self.entries.append((path, backup, mode))
        write_json(self.directory / 'files.json', [
            {'path': str(p), 'backup': b.name, 'mode': m} for p, b, m in self.entries
        ])

    def restore(self):
        errors = []
        for path, backup, mode in reversed(self.entries):
            try:
                if mode is None:
                    if path.exists():
                        path.unlink()
                else:
                    atomic_write(path, backup.read_bytes(), mode)
            except OSError as error:
                errors.append(str(error))
        if errors:
            raise RuntimeError('Could not restore files: ' + '; '.join(errors))
