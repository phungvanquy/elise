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
import sys
import tempfile
import tarfile
import unittest

from runtime import Paths

spec = importlib.util.spec_from_file_location('install_release', Path(__file__).with_name('install-release.py'))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)

# Archive contract enforced by already released Elise installers. Keep this
# independent of release_files() so packaging cannot silently break upgrades.
REQUIRED_ARCHIVE_FILES = (
    'elise', 'elisectl', 'install.sh', 'install-release.py', 'migrate.py',
    'runtime.py', 'elise@.service', 'LICENSE', 'SCRIPTS-LICENSE', 'THIRD-PARTY-NOTICES',
)


class FakeSystemd:
    def __init__(self):
        self.units = {}
        self.calls = []

    def entry(self, unit):
        return self.units.setdefault(unit, {'active': False, 'enabled': 'disabled'})

    def active(self, unit):
        return self.entry(unit)['active']

    def run(self, command, *arguments):
        self.calls.append((command, *arguments))
        if command == 'daemon-reload':
            return ''
        entry = self.entry(arguments[-1])
        if command in ('start', 'stop'):
            if command == 'start':
                assert entry['enabled'] != 'masked'
            entry['active'] = command == 'start'
        else:
            raise AssertionError(command)
        return ''


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = Paths(Path(self.temp.name))
        self.systemd = FakeSystemd()
        self.paths.units.mkdir(parents=True)
        self.paths.binary.parent.mkdir(parents=True)
        self.paths.binary.write_text('old binary')
        self.paths.unit.write_text('standalone template')

    def package(self):
        package = Path(self.temp.name) / 'package'
        package.mkdir()
        for name in installer.release_files(self.paths):
            (package / name).write_text('new ' + name)
        (package / 'elise').write_text('#!/bin/sh\necho elise 1.0.4\n')
        (package / 'elise').chmod(0o755)
        for name in ('elisectl', 'install.sh'):
            (package / name).write_text('#!/bin/bash\ntrue\n')
        (package / 'migrate.py').write_bytes(Path(__file__).with_name('migrate.py').read_bytes())
        return package

    def existing_installation(self):
        self.paths.manager.write_text('old manager')
        self.paths.support.mkdir(parents=True)
        (self.paths.support / 'migrate.py').write_text('old migration implementation')
        self.traffic = Path(self.temp.name) / 'external-state/traffic/pending.json'
        self.traffic.parent.mkdir(parents=True)
        self.traffic.write_text('{"7":[1,2]}')
        certificate = Path(self.temp.name) / 'external-cert/key.pem'
        certificate.parent.mkdir(parents=True)
        certificate.write_text('keep this private key')
        preserved = [self.traffic, certificate]
        for instance, active, enabled in [
            ('vmess-9', True, 'enabled'), ('anytls-10', False, 'enabled'),
            ('hysteria2-11', True, 'disabled'), ('vless-12', False, 'disabled'),
        ]:
            config = self.paths.config / instance / 'elise.conf'
            config.parent.mkdir(parents=True)
            config.write_text(f'ip_user_cache_save_dir={self.traffic.parent.parent}\n'
                              f'key_file={certificate}\npanel_key=literal +$value;key\n')
            unit = self.paths.units / f'elise@{instance}.service'
            unit.write_text(f'[Service]\nWorkingDirectory={config.parent}\n'
                            f'ExecStart={self.paths.binary} run -c {config}\n')
            dropin = self.paths.units / f'elise@{instance}.service.d/custom.conf'
            dropin.parent.mkdir()
            dropin.write_text('[Service]\nLimitNOFILE=65536\n')
            preserved.extend([config, unit, dropin])
            self.systemd.entry(unit.name).update(active=active, enabled=enabled)
        self.systemd.entry('other.service')['active'] = True
        states = {unit: entry.copy() for unit, entry in self.systemd.units.items()}
        return {path: path.read_bytes() for path in preserved}, states

    def test_fresh_install_and_version_mismatch(self):
        package = self.package()
        with self.assertRaisesRegex(RuntimeError, 'does not match'):
            installer.install(package, 'v1.0.5', self.paths, self.systemd)
        self.assertEqual(self.paths.binary.read_text(), 'old binary')
        installer.install(package, 'v1.0.4', self.paths, self.systemd)
        self.assertEqual(self.paths.binary.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.systemd.calls, [('daemon-reload',)])

    def test_upgrade_retires_migration_and_preserves_custom_units_and_external_state(self):
        package = self.package()
        preserved, states = self.existing_installation()
        checked = []
        installer.install(package, 'v1.0.4', self.paths, self.systemd,
                          health=lambda _paths, instance: checked.append(instance))
        self.assertCountEqual(checked, ['vmess-9', 'hysteria2-11'])
        self.assertEqual(self.systemd.units, states)
        self.assertTrue(all(call[-1] in ('elise@vmess-9.service', 'elise@hysteria2-11.service')
                            for call in self.systemd.calls if call[0] != 'daemon-reload'))
        retired = self.paths.support / 'migrate.py'
        self.assertEqual(retired.read_bytes(), (package / 'migrate.py').read_bytes())
        result = subprocess.run([sys.executable, str(retired), '--dry-run'],
                                cwd=self.temp.name, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('automatic migration has been removed', result.stderr)
        for path, contents in preserved.items():
            self.assertEqual(path.read_bytes(), contents, str(path))

    def test_upgrade_failure_restores_programs_and_states_without_rewinding_traffic(self):
        package = self.package()
        preserved, states = self.existing_installation()
        def failed_health(_paths, _instance):
            # A running node can update pending reports before startup checks fail.
            self.traffic.write_text('{"7":[3,4]}')
            raise RuntimeError('simulated startup failure')
        with self.assertRaisesRegex(RuntimeError, 'startup failure'):
            installer.install(package, 'v1.0.4', self.paths, self.systemd, health=failed_health)
        self.assertEqual(self.paths.binary.read_text(), 'old binary')
        self.assertEqual(self.paths.manager.read_text(), 'old manager')
        self.assertEqual((self.paths.support / 'migrate.py').read_text(), 'old migration implementation')
        self.assertEqual(self.systemd.units, states)
        self.assertEqual(self.traffic.read_text(), '{"7":[3,4]}')
        for path, contents in preserved.items():
            if path != self.traffic:
                self.assertEqual(path.read_bytes(), contents, str(path))


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
            for name in REQUIRED_ARCHIVE_FILES:
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

    def test_packaged_release_satisfies_published_installer_archive_contract(self):
        binary = self.directory / 'binary'
        binary.write_text('#!/bin/sh\necho elise 1.0.4\n')
        binary.chmod(0o755)
        subprocess.run(['bash', str(Path(__file__).with_name('package-elise.sh')),
                        str(binary), 'amd64', str(self.directory)],
                       check=True, capture_output=True, text=True, timeout=30)
        with tarfile.open(self.directory / self.asset, 'r:gz') as archive:
            for name in REQUIRED_ARCHIVE_FILES:
                self.assertTrue(archive.getmember('elise/' + name).isfile(), name)
            stub = archive.extractfile('elise/migrate.py').read()
        (self.directory / 'release.json').write_text(json.dumps(self.release))
        result = self.download()
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([sys.executable, '-'], input=stub,
                                cwd=self.directory, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'automatic migration has been removed', result.stderr)

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


class BootstrapProvisionTests(unittest.TestCase):
    """Run the real bootstrap dispatch with offline downloads and no system writes."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.bootstrap = Path(__file__).resolve().parent.parent / 'install.sh'
        self.log = self.directory / 'calls.jsonl'
        self.log.write_text('')
        (self.directory / 'elise').write_text('unused core fixture')
        (self.directory / 'elisectl').write_text('''#!/bin/bash
python3 - "$@" <<'PY'
import json, os, pathlib, sys
with (pathlib.Path(os.environ['FIXTURE']) / 'calls.jsonl').open('a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\\n')
sys.exit(1 if os.environ.get('FAIL_STAGE') == sys.argv[1] else 0)
PY
''')
        (self.directory / 'install-release.py').write_text('''
import json, os, pathlib, sys
with (pathlib.Path(os.environ['FIXTURE']) / 'calls.jsonl').open('a') as log:
    log.write(json.dumps(['install', sys.argv[2]]) + '\\n')
sys.exit(1 if os.environ.get('FAIL_STAGE') == 'install' else 0)
''')
        self.options = ['--node-type=vmess', '--panel-url', 'https://panel.example.com',
                        '--api-key=literal +$value;key', '--node-id=9']

    def run_bootstrap(self, arguments=(), fail=''):
        command = '''
source "$1"; shift
manager="$FIXTURE/elisectl"
ensure_install_dependencies() { arch=arm64; }
download_release() {
    printf '%s' "$1" > "$FIXTURE/requested"
    work=$(mktemp -d)
    cp "$FIXTURE/elisectl" "$FIXTURE/elise" "$FIXTURE/install-release.py" "$work/"
    resolved_tag=v1.0.5
}
main "$@"
'''
        result = subprocess.run(['bash', '-c', command, 'bash', str(self.bootstrap), *arguments],
                                env=dict(os.environ, FIXTURE=str(self.directory), FAIL_STAGE=fail),
                                input='', capture_output=True, text=True, timeout=20)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        return result, calls

    def test_checks_then_installs_then_provisions_with_exact_arguments(self):
        result, calls = self.run_bootstrap(['install', 'v1.0.5', *self.options])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[0] for call in calls], ['__check-add', 'install', 'add'])
        self.assertEqual(calls[0][2:], self.options)
        self.assertEqual(calls[1], ['install', 'v1.0.5'])
        self.assertEqual(calls[2][1:], self.options)
        self.assertEqual((self.directory / 'requested').read_text(), 'v1.0.5')

    def test_bare_flags_install_latest(self):
        result, calls = self.run_bootstrap(self.options)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[-1], ['add', *self.options])
        self.assertEqual((self.directory / 'requested').read_text(), '')

    def test_default_install_and_update_create_no_nodes(self):
        for arguments in ([], ['install'], ['update'], ['update', 'v1.0.5']):
            with self.subTest(arguments=arguments):
                self.log.write_text('')
                result, calls = self.run_bootstrap(arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [['install', 'v1.0.5']])

    def test_manager_update_passes_optional_version_without_empty_argument(self):
        (self.directory / 'install.sh').write_text('''#!/bin/bash
python3 - "$@" <<'PY'
import json, sys
print(json.dumps(sys.argv[1:]))
PY
''')
        manager = Path(__file__).with_name('elise.sh')
        for arguments in ([], ['v1.0.5']):
            with self.subTest(arguments=arguments):
                command = 'source "$1"; shift; support_dir=$1; shift; need_root() { :; }; need_systemd() { :; }; main update "$@"'
                result = subprocess.run(['bash', '-c', command, 'bash', str(manager), str(self.directory), *arguments],
                                        text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), ['install', *arguments])

    def test_preflight_failure_never_installs(self):
        result, calls = self.run_bootstrap(self.options, fail='__check-add')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call[0] for call in calls], ['__check-add'])

    def test_install_failure_never_provisions(self):
        result, calls = self.run_bootstrap(self.options, fail='install')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call[0] for call in calls], ['__check-add', 'install'])

    def test_node_failure_is_reported(self):
        result, calls = self.run_bootstrap(self.options, fail='add')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call[0] for call in calls], ['__check-add', 'install', 'add'])

    def test_invalid_bootstrap_arguments_do_not_install(self):
        for arguments in (['--api-key'], ['--api-key='], ['--node-id', '--listen=::'],
                          ['--unknown=do-not-print-this'], ['install', '../../file'],
                          ['update', *self.options]):
            with self.subTest(arguments=arguments):
                result, calls = self.run_bootstrap(arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
                self.assertNotIn('do-not-print-this', result.stdout + result.stderr)

    def test_piped_script_supports_help_without_systemd_or_root(self):
        result = subprocess.run(['bash', '-s', '--', '--help'], input=self.bootstrap.read_text(),
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--node-type', result.stdout)
        self.assertIn('--api-key-file', result.stdout)


if __name__ == '__main__':
    unittest.main()
