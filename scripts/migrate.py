#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Move V2bX-managed Elise instances without copying live traffic counters."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

from runtime import (FileBackup, Paths, Systemd, atomic_write, deployment_lock,
                     handle_signals, health_check, instances, write_json)

PATH_KEYS = {
    'nodes_dir', 'routes_file', 'routes_path', 'dns_file', 'dns_path', 'dns_rules_file',
    'block_list', 'audit_block_list', 'block_list_file', 'white_list', 'audit_white_list',
    'white_list_file', 'geoip_file', 'geoip_path', 'geosite_file', 'geosite_path',
    'log_file', 'log_file_dir', 'audit_log_file', 'cert_file', 'key_file',
}
RETIRED_HELPER = b'''#!/usr/bin/env bash
# Elise has moved to its own repository and service manager.
echo 'Elise is now managed with elisectl. See https://github.com/phungvanquy/elise' >&2
# Old V2bX uninstallers call this helper: never uninstall standalone Elise.
[[ "${1:-}" == uninstall ]] && exit 0
exit 1
'''


def value(text):
    return text.strip().strip('"').strip("'").strip()


def global_values(text):
    result = {}
    node_section = False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('[') and line.endswith(']'):
            node_section = bool(re.fullmatch(r'node_?[0-9]+', line[1:-1].strip()))
        elif '=' in line and not node_section:
            key, item = line.split('=', 1)
            result[key.strip().lower()] = value(item)
    return result


def absolute(path, working_directory):
    path = Path(path)
    return Path(os.path.abspath(path if path.is_absolute() else working_directory / path))


def under(path, directory):
    return path == directory or directory in path.parents


def rewrite_config(text, source, target, paths, main=False):
    """Rewrite recognized paths only; credentials and arbitrary values are untouched."""
    result = []
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith(('#', ';')) or '=' not in stripped:
            result.append(line)
            continue
        key, raw = stripped.split('=', 1)
        key = key.strip().lower()
        item = value(raw)
        if key not in PATH_KEYS | {'ip_user_cache_save_dir'} or not item:
            result.append(line)
            continue
        old = absolute(item, source)
        # V2bX uninstall removes these directories. Don't silently break external
        # certificate renewal by copying its output to a different location.
        for owned in (paths.at('/etc/V2bX'), paths.at('/usr/local/V2bX')):
            if under(old, owned) or under(old.resolve(), owned):
                raise RuntimeError(f'{key} uses V2bX-owned data at {old}; relocate it and its renewal hook before migration')
        if key != 'ip_user_cache_save_dir' and under(old, source):
            new = target / old.relative_to(source)
        else:
            new = old
        result.append(f'{key}={new}\n')
    if main:
        values = global_values(text)
        # load_from_file defaults state to the CONFIG PARENT, not /etc/elise.
        # Keep that original directory so rollback uses the latest counters too.
        state = absolute(values.get('ip_user_cache_save_dir') or str(source), source)
        # Prepend defaults: they remain in the global section even if a config
        # ends in a [node_N] block; explicit values below take precedence.
        defaults = f'ip_user_cache_save_dir={state}\n'
        if 'nodes_dir' not in values:
            raise RuntimeError(f'{source}: explicit nodes_dir is required for automatic migration')
        result.insert(0, defaults)
    return ''.join(result)


def validate_unit(texts, paths, instance):
    properties = {}
    forbidden = {
        'EnvironmentFile', 'RootDirectory', 'RootImage', 'ReadWritePaths',
        'ReadOnlyPaths', 'InaccessiblePaths', 'BindPaths', 'BindReadOnlyPaths',
        'ProtectSystem', 'TemporaryFileSystem',
    }
    for text in texts:
        if '\\\n' in text:
            raise RuntimeError('Multiline systemd directives require manual review before migration')
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', ';', '[')) or '=' not in line:
                continue
            key, item = line.split('=', 1)
            key, item = key.strip(), item.strip()
            if any(str(paths.at(p)) in item for p in ('/etc/V2bX', '/usr/local/V2bX')) or 'V2bX.service' in item:
                raise RuntimeError(f'Systemd {key} depends on V2bX; relocate that dependency before migration')
            if key in forbidden or (key.startswith('Exec') and key != 'ExecStart'):
                raise RuntimeError(f'Custom systemd {key} requires manual review before migration')
            if key == 'Environment' and 'ELISE_' in item:
                raise RuntimeError('ELISE_* environment overrides require manual review before migration')
            if key in ('User', 'Group') and item not in ('', 'root'):
                raise RuntimeError('Custom service users require manual review before migration')
            properties[key] = item.replace('%i', instance)
    expected_dir = str(paths.legacy_config / instance)
    if properties.get('WorkingDirectory') != expected_dir:
        raise RuntimeError('Custom WorkingDirectory requires manual review before migration')
    expected_exec = f'{paths.legacy_binary} run -c {expected_dir}/elise.conf'
    if properties.get('ExecStart') != expected_exec:
        raise RuntimeError('Custom ExecStart requires manual review before migration')


def rewrite_unit(text, paths):
    return text.replace(str(paths.legacy_binary), str(paths.binary)).replace(
        str(paths.legacy_config), str(paths.config)).replace('V2bX Elise', 'Elise')


def inventory(paths, systemd):
    plan = []
    for instance in instances(paths.legacy_config):
        source, target = paths.legacy_config / instance, paths.config / instance
        old_unit, new_unit = f'V2bX-elise@{instance}.service', f'elise@{instance}.service'
        marker = target / '.migrated-from-v2bx.json'
        if marker.is_file():
            record = json.loads(marker.read_text())
            if record.get('source') == str(source) and record.get('status') == 'complete':
                if systemd.active(old_unit) or systemd.enabled(old_unit) != 'masked':
                    raise RuntimeError(f'{old_unit} was reactivated after migration; stop and mask it before proceeding')
                print(f'{instance}: already migrated')
                continue
        if source.is_symlink() or (source / 'elise.conf').is_symlink():
            raise RuntimeError(f'{source}: symlinked configuration requires manual review')
        if target.exists() or target.is_symlink() or (paths.units / new_unit).exists() or (paths.units / new_unit).is_symlink() or (paths.units / (new_unit + '.d')).exists():
            raise RuntimeError(f'{instance}: standalone configuration or service already exists; refusing to overwrite it')
        enabled = systemd.enabled(old_unit)
        if enabled == 'masked':
            raise RuntimeError(f'{old_unit} is masked; unmask it before automatic migration')
        active = systemd.active(old_unit)
        fragment = Path(systemd.property(old_unit, 'FragmentPath'))
        if fragment != paths.units / 'V2bX-elise@.service' or not fragment.is_file():
            raise RuntimeError(f'{old_unit}: custom or missing service template requires manual review')
        dropins = [Path(p) for p in shlex.split(systemd.property(old_unit, 'DropInPaths'))]
        texts = [fragment.read_text()] + [p.read_text() for p in dropins]
        validate_unit(texts, paths, instance)
        config = (source / 'elise.conf').read_text()
        rewrite_config(config, source, target, paths, main=True)
        for config_file in source.rglob('*.conf'):
            if config_file.is_symlink():
                raise RuntimeError(f'{config_file}: symlinked configuration requires manual review')
            rewrite_config(config_file.read_text(), source, target, paths)
        plan.append({'instance': instance, 'source': str(source), 'target': str(target),
                     'active': active, 'enabled': enabled, 'unit_texts': texts,
                     'config_sha256': hashlib.sha256(config.encode()).hexdigest()})
    return plan


def migrate(paths=None, systemd=None, dry_run=False, health=health_check):
    paths, systemd = paths or Paths(), systemd or Systemd()
    plan = inventory(paths, systemd)
    for entry in plan:
        print(f'{entry["instance"]}: {"running" if entry["active"] else "stopped"}, {entry["enabled"]}; '
              f'{entry["source"]} -> {entry["target"]}; existing traffic-state location retained')
    if dry_run or not plan:
        print('Dry run: no files or services changed.' if dry_run else 'No legacy instances need migration.')
        return
    if not paths.binary.is_file() or not paths.unit.is_file():
        raise RuntimeError('Install standalone Elise before migrating')
    backup = FileBackup(paths, 'migration-')
    backup.save(paths.legacy_helper)
    manifest = {'status': 'prepared', 'instances': plan}
    write_json(backup.directory / 'migration.json', manifest)
    print(f'Migration backup: {backup.directory}', flush=True)
    created_directories = []
    new_units = []
    changed = False
    try:
        changed = True
        # Flush final state before copying config/certificates; state itself stays
        # at its original path and is never restored from a stale snapshot.
        for entry in plan:
            unit = f'V2bX-elise@{entry["instance"]}.service'
            systemd.run('stop', unit)
            systemd.run('disable', unit)
            systemd.run('mask', unit)
        for entry in plan:
            instance = entry['instance']
            source, target = Path(entry['source']), Path(entry['target'])
            shutil.copytree(source, backup.directory / instance, symlinks=True)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            created_directories.append(target)
            shutil.copytree(source, target, symlinks=True)
            os.chmod(target, 0o700)
            for config_file in target.rglob('*.conf'):
                if config_file.is_symlink():
                    raise RuntimeError('Configuration became a symlink during migration')
                content = rewrite_config(config_file.read_text(), source, target, paths,
                                         main=config_file == target / 'elise.conf')
                atomic_write(config_file, content.encode(), 0o600)
            unit = paths.units / f'elise@{instance}.service'
            backup.save(unit)
            atomic_write(unit, rewrite_unit(entry['unit_texts'][0], paths).encode(), 0o644)
            new_units.append(unit.name)
            if len(entry['unit_texts']) > 1:
                dropin_dir = paths.units / (unit.name + '.d')
                created_directories.append(dropin_dir)
                dropin_dir.mkdir()
                for index, text in enumerate(entry['unit_texts'][1:]):
                    # Preserve the effective order returned by systemd, including
                    # template versus instance drop-in precedence.
                    atomic_write(dropin_dir / f'{index:04d}-migrated.conf',
                                 rewrite_unit(text, paths).encode(), 0o644)
        systemd.run('daemon-reload')
        for entry in plan:
            unit = f'elise@{entry["instance"]}.service'
            systemd.run('enable' if entry['enabled'] == 'enabled' else 'disable', unit)
            if entry['active']:
                systemd.run('start', unit)
                health(paths, entry['instance'])
        # Cached old V2bX managers can call this helper during Go uninstall.
        # Retire it only after EVERY migrated instance passes its checks.
        atomic_write(paths.legacy_helper, RETIRED_HELPER, 0o755)
        for entry in plan:
            write_json(Path(entry['target']) / '.migrated-from-v2bx.json', {
                'source': entry['source'], 'status': 'complete', 'backup': str(backup.directory),
                'source_sha256': entry['config_sha256'],
            })
        manifest['status'] = 'complete'
        write_json(backup.directory / 'migration.json', manifest)
    except BaseException:
        if changed:
            errors = []
            for unit in new_units:
                try:
                    systemd.run('stop', unit)
                    systemd.run('disable', unit)
                except Exception:
                    try:
                        if systemd.active(unit):
                            errors.append(f'Could not stop {unit}')
                    except Exception as error:
                        errors.append(str(error))
            if not errors:
                try:
                    backup.restore()
                    for directory in reversed(created_directories):
                        if directory.exists():
                            shutil.rmtree(directory)
                    systemd.run('daemon-reload')
                except Exception as error:
                    errors.append(str(error))
                for entry in plan:
                    unit = f'V2bX-elise@{entry["instance"]}.service'
                    try:
                        systemd.run('unmask', unit)
                        systemd.run('enable' if entry['enabled'] == 'enabled' else 'disable', unit)
                        if entry['active']:
                            systemd.run('start', unit)
                    except Exception as error:
                        errors.append(str(error))
            manifest['status'] = 'rollback-incomplete' if errors else 'rolled-back'
            manifest['errors'] = errors
            write_json(backup.directory / 'migration.json', manifest)
            print(f'Migration failed; {manifest["status"]}. Backup: {backup.directory}', file=sys.stderr)
            if errors:
                print('\n'.join(errors), file=sys.stderr)
        raise
    print('Migration complete. Use elisectl to manage Elise. Legacy instances are disabled and masked.')
    print('Keep the legacy configuration directories: migrated instances still use their live traffic state.')
    print('Update external certificate renewal hooks to: elisectl restart <instance>')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--from-v2bx', action='store_true', required=True)
    parser.add_argument('--dry-run', action='store_true')
    arguments = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise RuntimeError('Run as root')
        os.umask(0o077)
        handle_signals()
        if arguments.dry_run:
            migrate(dry_run=True)
        else:
            with deployment_lock(Paths()):
                migrate()
    except Exception as error:
        print(f'Elise: {error}', file=sys.stderr)
        sys.exit(1)
