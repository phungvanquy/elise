#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Deployment regressions run entirely in temporary directories with fake systemd."""
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest

import migrate
from runtime import Paths

spec = importlib.util.spec_from_file_location('install_release', Path(__file__).with_name('install-release.py'))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class FakeSystemd:
    def __init__(self, paths):
        self.paths = paths
        self.units = {}
        self.calls = []
        self.on_stop = None

    def add(self, instance, active=True, enabled='enabled', dropins=()):
        unit = f'V2bX-elise@{instance}.service'
        self.units[unit] = {'active': active, 'enabled': enabled, 'dropins': list(dropins)}

    def entry(self, unit):
        return self.units.setdefault(unit, {'active': False, 'enabled': 'disabled', 'dropins': []})

    def active(self, unit):
        return self.entry(unit)['active']

    def enabled(self, unit):
        return self.entry(unit)['enabled']

    def property(self, unit, prop):
        if prop == 'FragmentPath':
            return str(self.paths.units / 'V2bX-elise@.service')
        if prop == 'DropInPaths':
            return ' '.join(str(p) for p in self.entry(unit)['dropins'])
        raise AssertionError(prop)

    def run(self, command, *arguments):
        self.calls.append((command, *arguments))
        if command == 'daemon-reload':
            return ''
        unit = arguments[-1]
        entry = self.entry(unit)
        if command in ('start', 'stop'):
            if command == 'start':
                assert entry['enabled'] != 'masked'
                if unit.startswith('elise@'):
                    assert not self.active('V2bX-' + unit)
            entry['active'] = command == 'start'
            if command == 'stop' and self.on_stop:
                self.on_stop(unit)
        elif command in ('enable', 'disable', 'mask', 'unmask'):
            entry['enabled'] = {'enable': 'enabled', 'disable': 'disabled',
                                'mask': 'masked', 'unmask': 'disabled'}[command]
        else:
            raise AssertionError(command)
        return ''


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = Paths(Path(self.temp.name))
        self.systemd = FakeSystemd(self.paths)
        self.paths.units.mkdir(parents=True)
        self.paths.binary.parent.mkdir(parents=True)
        self.paths.binary.write_text('old binary')
        self.paths.unit.write_text('standalone template')
        self.paths.legacy_helper.parent.mkdir(parents=True)
        self.paths.legacy_helper.write_text('old helper')
        (self.paths.units / 'V2bX-elise@.service').write_text(
            '[Service]\nUser=root\nGroup=root\n'
            f'WorkingDirectory={self.paths.legacy_config}/%i\n'
            f'ExecStart={self.paths.legacy_binary} run -c {self.paths.legacy_config}/%i/elise.conf\n'
            'Restart=on-failure\n[Install]\nWantedBy=multi-user.target\n'
        )

    def legacy(self, instance='vmess-9', active=True, enabled='enabled', extra=''):
        source = self.paths.legacy_config / instance
        source.mkdir(parents=True)
        (source / 'nodes').mkdir()
        (source / 'cert').mkdir()
        (source / 'cert/key.pem').write_text('keep this private key')
        (source / 'traffic').mkdir()
        (source / 'traffic/pending.json').write_text('{"7":[1,2]}')
        (source / 'elise.conf').write_text(
            f'type=xboard\nnode_id=9\npanel_node_type=vmess\nlisten=127.0.0.1\n'
            f'panel_key=literal {source}/must-not-change\n'
            f'nodes_dir={source}/nodes\ncert_file={source}/cert/cert.pem\n'
            f'key_file={source}/cert/key.pem\n{extra}'
        )
        (source / 'nodes/node_9.conf').write_text(f'[user]\nkey_file={source}/cert/key.pem\n')
        self.systemd.add(instance, active, enabled)
        return source

    def run_migration(self, **kwargs):
        return migrate.migrate(self.paths, self.systemd, health=lambda _paths, _instance: None, **kwargs)

    def test_dry_run_is_read_only(self):
        self.legacy()
        self.run_migration(dry_run=True)
        self.assertEqual(self.systemd.calls, [])
        self.assertFalse(self.paths.config.exists())
        self.assertFalse(self.paths.backups.exists())
        self.assertEqual(self.paths.legacy_helper.read_text(), 'old helper')

    def test_migration_preserves_states_keys_credentials_and_effective_state_path(self):
        source = self.legacy(extra='[node_9]\nlisten=127.0.0.1\n')
        self.legacy('anytls-10', active=False, enabled='enabled')
        self.legacy('hysteria2-11', active=True, enabled='disabled')
        self.legacy('vless-12', active=False, enabled='disabled')
        self.run_migration()
        target = self.paths.config / 'vmess-9'
        values = migrate.global_values((target / 'elise.conf').read_text())
        self.assertEqual(values['ip_user_cache_save_dir'], str(source))
        self.assertEqual(values['key_file'], str(target / 'cert/key.pem'))
        self.assertEqual(values['panel_key'], f'literal {source}/must-not-change')
        self.assertEqual((target / 'cert/key.pem').read_bytes(), (source / 'cert/key.pem').read_bytes())
        self.assertIn(str(target / 'cert/key.pem'), (target / 'nodes/node_9.conf').read_text())
        self.assertTrue(self.systemd.active('elise@vmess-9.service'))
        self.assertFalse(self.systemd.active('elise@anytls-10.service'))
        self.assertEqual(self.systemd.enabled('elise@anytls-10.service'), 'enabled')
        self.assertTrue(self.systemd.active('elise@hysteria2-11.service'))
        self.assertEqual(self.systemd.enabled('elise@hysteria2-11.service'), 'disabled')
        self.assertFalse(self.systemd.active('elise@vless-12.service'))
        self.assertEqual(self.systemd.enabled('elise@vless-12.service'), 'disabled')
        self.assertEqual(self.systemd.enabled('V2bX-elise@vmess-9.service'), 'masked')
        self.assertEqual((target / 'elise.conf').stat().st_mode & 0o777, 0o600)
        self.assertEqual(subprocess.run(['bash', str(self.paths.legacy_helper), 'uninstall'], capture_output=True).returncode, 0)
        before = list(self.systemd.calls)
        self.run_migration()
        self.assertEqual(self.systemd.calls, before)

    def test_explicit_relative_state_is_resolved_against_old_working_directory(self):
        source = self.legacy(extra='ip_user_cache_save_dir=state\n')
        self.run_migration()
        config = (self.paths.config / 'vmess-9/elise.conf').read_text()
        self.assertEqual(migrate.global_values(config)['ip_user_cache_save_dir'], str(source / 'state'))

    def test_rollback_keeps_latest_traffic_and_restores_all_legacy_states(self):
        source = self.legacy()
        self.legacy('anytls-10', active=False, enabled='disabled')
        pending = source / 'traffic/pending.json'
        def failed_health(_paths, _instance):
            # The new service acknowledged some traffic. Restoring the old
            # snapshot would report it twice, so rollback MUST retain this file.
            pending.write_text('{"7":[0,1]}')
            raise RuntimeError('simulated listener failure')
        with self.assertRaisesRegex(RuntimeError, 'listener failure'):
            migrate.migrate(self.paths, self.systemd, health=failed_health)
        self.assertEqual(pending.read_text(), '{"7":[0,1]}')
        self.assertTrue(self.systemd.active('V2bX-elise@vmess-9.service'))
        self.assertEqual(self.systemd.enabled('V2bX-elise@vmess-9.service'), 'enabled')
        self.assertFalse(self.systemd.active('V2bX-elise@anytls-10.service'))
        self.assertFalse((self.paths.config / 'vmess-9').exists())
        self.assertEqual(self.paths.legacy_helper.read_text(), 'old helper')
        self.assertFalse((self.paths.units / 'elise@vmess-9.service').exists())
        self.assertEqual(self.systemd.enabled('elise@vmess-9.service'), 'disabled')

    def test_existing_destination_is_never_overwritten(self):
        self.legacy()
        target = self.paths.config / 'vmess-9'
        target.mkdir(parents=True)
        (target / 'elise.conf').write_text('independent config')
        with self.assertRaisesRegex(RuntimeError, 'refusing to overwrite'):
            self.run_migration()
        self.assertEqual(self.systemd.calls, [])
        self.assertEqual((target / 'elise.conf').read_text(), 'independent config')

    def test_v2bx_owned_certificates_are_flagged_before_stopping_services(self):
        self.legacy(extra=f'key_file={self.paths.at("/etc/V2bX/cert/key.pem")}\n')
        with self.assertRaisesRegex(RuntimeError, 'V2bX-owned data'):
            self.run_migration()
        self.assertEqual(self.systemd.calls, [])

    def test_dropin_resource_limits_are_preserved(self):
        self.legacy()
        dropin = self.paths.units / 'V2bX-elise@.service.d/limits.conf'
        dropin.parent.mkdir()
        dropin.write_text('[Service]\nLimitNOFILE=65536\nRestartSec=20\n')
        self.systemd.entry('V2bX-elise@vmess-9.service')['dropins'] = [dropin]
        self.run_migration()
        target = self.paths.units / 'elise@vmess-9.service.d/0000-migrated.conf'
        self.assertEqual(target.read_text(), dropin.read_text())

    def test_environment_overrides_require_review_before_changes(self):
        self.legacy()
        dropin = self.paths.units / 'custom.conf'
        dropin.write_text('[Service]\nEnvironment=ELISE_IP_USER_CACHE_SAVE_DIR=/some/state\n')
        self.systemd.entry('V2bX-elise@vmess-9.service')['dropins'] = [dropin]
        with self.assertRaisesRegex(RuntimeError, 'environment overrides'):
            self.run_migration()
        self.assertEqual(self.systemd.calls, [])

    def test_unit_dependencies_on_v2bx_are_rejected_before_changes(self):
        self.legacy()
        dropin = self.paths.units / 'custom.conf'
        self.systemd.entry('V2bX-elise@vmess-9.service')['dropins'] = [dropin]
        for content in ('[Unit]\nRequires=V2bX.service\n',
                        f'[Service]\nStandardOutput=append:{self.paths.at("/etc/V2bX/elise.log")}\n'):
            dropin.write_text(content)
            with self.assertRaisesRegex(RuntimeError, 'depends on V2bX'):
                self.run_migration()
        self.assertEqual(self.systemd.calls, [])

    def package(self):
        package = Path(self.temp.name) / 'package'
        package.mkdir()
        for name in installer.release_files(self.paths):
            (package / name).write_text('new ' + name)
        (package / 'elise').write_text('#!/bin/sh\necho elise 1.0.4\n')
        (package / 'elise').chmod(0o755)
        for name in ('elisectl', 'install.sh'):
            (package / name).write_text('#!/bin/bash\ntrue\n')
        return package

    def test_fresh_install_and_version_mismatch(self):
        package = self.package()
        with self.assertRaisesRegex(RuntimeError, 'does not match'):
            installer.install(package, 'v1.0.5', self.paths, self.systemd)
        self.assertEqual(self.paths.binary.read_text(), 'old binary')
        installer.install(package, 'v1.0.4', self.paths, self.systemd)
        self.assertEqual(self.paths.binary.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.systemd.calls, [('daemon-reload',)])

    def test_upgrade_failure_restores_binary_manager_and_running_states(self):
        package = self.package()
        for instance in ('vmess-9', 'anytls-10'):
            config = self.paths.config / instance
            config.mkdir(parents=True)
            (config / 'elise.conf').write_text('original config')
        self.paths.manager.write_text('old manager')
        self.systemd.entry('elise@vmess-9.service')['active'] = True
        self.systemd.entry('elise@vmess-9.service')['enabled'] = 'enabled'
        def failed_health(_paths, _instance):
            raise RuntimeError('simulated startup failure')
        with self.assertRaisesRegex(RuntimeError, 'startup failure'):
            installer.install(package, 'v1.0.4', self.paths, self.systemd, health=failed_health)
        self.assertEqual(self.paths.binary.read_text(), 'old binary')
        self.assertEqual(self.paths.manager.read_text(), 'old manager')
        self.assertTrue(self.systemd.active('elise@vmess-9.service'))
        self.assertFalse(self.systemd.active('elise@anytls-10.service'))
        self.assertEqual((self.paths.config / 'vmess-9/elise.conf').read_text(), 'original config')


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.asset = 'elise-linux-amd64.tar.gz'
        self.release = {'tag_name': 'v1.0.4', 'draft': False, 'prerelease': False, 'assets': [
            {'state': 'uploaded', 'browser_download_url':
             f'https://github.com/phungvanquy/elise/releases/download/v1.0.4/{name}'}
            for name in (self.asset, self.asset + '.sha256')
        ]}

    def prepare(self, invalid_member=False):
        with tarfile.open(self.directory / self.asset, 'w:gz') as archive:
            for name in installer.release_files(Paths()):
                info = tarfile.TarInfo('elise/' + name)
                data = b'fixture'
                info.size = len(data)
                if invalid_member and name == 'elisectl':
                    info.type = tarfile.SYMTYPE
                    info.linkname = '/etc/passwd'
                    info.size = 0
                archive.addfile(info, io.BytesIO(data))
        digest = hashlib.sha256((self.directory / self.asset).read_bytes()).hexdigest()
        (self.directory / (self.asset + '.sha256')).write_text(f'{digest}  {self.asset}\n')
        (self.directory / 'release.json').write_text(json.dumps(self.release))

    def download(self, requested='v1.0.4'):
        bootstrap = Path(__file__).resolve().parent.parent / 'install.sh'
        command = '''
source "$1"
fetch() {
    case "$1" in
        https://api.github.com/repos/phungvanquy/elise/releases/*) cp "$FIXTURE/release.json" "$2" ;;
        https://github.com/phungvanquy/elise/releases/download/v1.0.4/*) cp "$FIXTURE/${1##*/}" "$2" ;;
        *) return 1 ;;
    esac
}
download_release "$2" amd64
test -f "$work/elisectl"
test "$resolved_tag" = v1.0.4
'''
        return subprocess.run(['bash', '-c', command, 'bash', str(bootstrap), requested],
                              env=dict(os.environ, FIXTURE=str(self.directory)), capture_output=True, text=True)

    def test_valid_pinned_and_latest_release(self):
        self.prepare()
        for version in ('v1.0.4', ''):
            result = self.download(version)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_bad_checksum_aborts(self):
        self.prepare()
        (self.directory / self.asset).write_bytes(b'corrupted download')
        result = self.download()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Checksum mismatch', result.stderr)

    def test_archive_symlinks_are_rejected(self):
        self.prepare(invalid_member=True)
        result = self.download()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid archive member', result.stderr)

    def test_missing_assets_and_unexpected_version_are_rejected(self):
        self.release['assets'] = []
        self.prepare()
        self.assertIn('missing', self.download().stderr)
        self.release['tag_name'] = 'v1.0.5'
        self.prepare()
        self.assertIn('Unexpected', self.download().stderr)


if __name__ == '__main__':
    unittest.main()
