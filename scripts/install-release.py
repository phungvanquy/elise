#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Apply a checksum-verified release; roll back files and services on failure."""
import os
from pathlib import Path
import re
import subprocess
import sys

from runtime import (FileBackup, Paths, Systemd, atomic_write, deployment_lock,
                     handle_signals, health_check, instances, public_directory, write_json)


def release_files(paths):
    return {
        'elise': (paths.binary, 0o755),
        'elisectl': (paths.manager, 0o755),
        'install.sh': (paths.support / 'install.sh', 0o755),
        'install-release.py': (paths.support / 'install-release.py', 0o644),
        # Replace the retired migration implementation with the archive's stub.
        'migrate.py': (paths.support / 'migrate.py', 0o644),
        'runtime.py': (paths.support / 'runtime.py', 0o644),
        'elise@.service': (paths.unit, 0o644),
        'LICENSE': (paths.licenses / 'LICENSE', 0o644),
        'SCRIPTS-LICENSE': (paths.licenses / 'SCRIPTS-LICENSE', 0o644),
        'THIRD-PARTY-NOTICES': (paths.licenses / 'THIRD-PARTY-NOTICES', 0o644),
    }


def install(package, tag, paths=None, systemd=None, health=health_check):
    paths, systemd = paths or Paths(), systemd or Systemd()
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?', tag):
        raise RuntimeError('Invalid release version')
    files = release_files(paths)
    for name in files:
        source = package / name
        if source.is_symlink() or not source.is_file() or not source.stat().st_size:
            raise RuntimeError('Missing or invalid release file: ' + name)
    version = subprocess.check_output([str(package / 'elise'), '--version'], text=True).strip()
    if version != 'elise ' + tag[1:]:
        raise RuntimeError(f'Binary version {version!r} does not match {tag}')
    for name in ('elisectl', 'install.sh'):
        subprocess.run(['bash', '-n', str(package / name)], check=True)
    active = [i for i in instances(paths.config) if systemd.active(f'elise@{i}.service')]
    backup = FileBackup(paths, 'install-')
    for destination, _mode in files.values():
        backup.save(destination)
    manifest = {'release': tag, 'active': active, 'status': 'prepared'}
    write_json(backup.directory / 'install.json', manifest)
    print(f'Installation backup: {backup.directory}', flush=True)
    changed = False
    try:
        changed = True
        for instance in active:
            systemd.run('stop', f'elise@{instance}.service')
        for directory in (paths.binary.parent, paths.manager.parent, paths.support, paths.licenses):
            public_directory(directory)
        for name, (destination, mode) in files.items():
            atomic_write(destination, (package / name).read_bytes(), mode)
        paths.config.mkdir(parents=True, exist_ok=True, mode=0o700)
        systemd.run('daemon-reload')
        for instance in active:
            systemd.run('start', f'elise@{instance}.service')
            health(paths, instance)
        manifest['status'] = 'complete'
        write_json(backup.directory / 'install.json', manifest)
    except BaseException:
        if changed:
            errors = []
            # Stop all new processes before restoring the executable and manager.
            for instance in active:
                try:
                    systemd.run('stop', f'elise@{instance}.service')
                except Exception as error:
                    errors.append(str(error))
            # Never swap files or restart old processes if a new process could
            # not be stopped. Leave the backup and report incomplete recovery.
            if not errors:
                try:
                    backup.restore()
                    systemd.run('daemon-reload')
                except Exception as error:
                    errors.append(str(error))
                if not errors:
                    for instance in active:
                        try:
                            systemd.run('start', f'elise@{instance}.service')
                        except Exception as error:
                            errors.append(str(error))
            manifest['status'] = 'rollback-incomplete' if errors else 'rolled-back'
            manifest['errors'] = errors
            write_json(backup.directory / 'install.json', manifest)
            print(f'Installation failed; {manifest["status"]}. Backup: {backup.directory}', file=sys.stderr)
            if errors:
                print('\n'.join(errors), file=sys.stderr)
        raise
    print(f'Installed {version}. Add a node with: sudo elisectl add <protocol> <id> [panel]')


if __name__ == '__main__':
    try:
        if os.geteuid() != 0 or len(sys.argv) != 3:
            raise RuntimeError('Run through install.sh as root')
        os.umask(0o077)
        handle_signals()
        with deployment_lock(Paths()):
            install(Path(sys.argv[1]), sys.argv[2])
    except Exception as error:
        print(f'Elise: {error}', file=sys.stderr)
        sys.exit(1)
