#!/usr/bin/env python3
"""Test purge in a temporary filesystem with a fake systemctl; never touch host services."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest

HELPER = Path(__file__).with_name('elise.sh')
SETUP = r'''
source "$1"
fixture=$2
shift 2
bin_dir="$fixture/bin"
binary="$bin_dir/elise"
config_dir="$fixture/etc/elise/instances"
state_dir="$fixture/state"
support_dir="$fixture/support"
license_dir="$fixture/licenses"
unit_file="$fixture/units/elise@.service"
need_root() { :; }
need_systemd() { :; }
systemctl() {
    printf '%s\n' "$*" >> "$fixture/services.log"
    case "$1" in
        list-units)
            [[ ! -f "$fixture/list-fail" ]] || return 1
            if [[ ! -f "$fixture/uninstalled" ]]; then
                echo 'elise@orphan.service loaded activating start Elise'
            fi ;;
        list-unit-files)
            if [[ ! -f "$fixture/uninstalled" ]]; then
                echo 'elise@.service disabled enabled'
                echo 'elise@vmess-2.service enabled enabled'
            fi ;;
        show)
            if [[ -f "$fixture/uninstalled" || "$2" == elise@vless-1.service ]]; then
                echo not-found
            else
                echo loaded
            fi ;;
        stop) [[ ! -f "$fixture/stop-fail" ]] || return 1 ;;
        disable) [[ ! -f "$fixture/uninstalled" ]] || return 1 ;;
        reset-failed|daemon-reload) ;;
        *) echo "unexpected systemctl command: $*" >&2; return 1 ;;
    esac
}
purge_all "$@"
'''


class PurgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ['bin/elise', 'bin/elisectl', 'etc/elise/instances/vless-1/elise.conf',
                     'etc/elise/instances/vless-1/cert/key.pem', 'state/backups/saved',
                     'support/install.sh', 'licenses/LICENSE', 'units/elise@.service',
                     'units/elise@vmess-2.service', 'units/elise@vmess-2.service.d/override.conf',
                     'units/elise@.service.d/custom.conf', 'outside/key.pem',
                     'external-state/traffic.json', 'units/other.service', 'bin/other']:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('keep or remove as owned\n')
        wants = self.root / 'units/multi-user.target.wants'
        wants.mkdir()
        (wants / 'elise@vmess-2.service').symlink_to('../elise@vmess-2.service')
        (wants / 'elise@missing.service').symlink_to('../missing.service')
        (wants / 'other.service').symlink_to('../other.service')
        (self.root / 'etc/elise/external').symlink_to(self.root / 'outside', target_is_directory=True)

    def run_purge(self, *args):
        return subprocess.run(['bash', '-c', SETUP, 'bash', str(HELPER), str(self.root), *args],
                              text=True, capture_output=True, timeout=10)

    def assert_files_retained(self):
        for name in ['bin/elise', 'bin/elisectl', 'etc/elise/instances/vless-1/elise.conf',
                     'state/backups/saved', 'units/elise@.service']:
            self.assertTrue((self.root / name).exists(), name)

    def test_requires_exact_confirmation_before_any_changes(self):
        for args in [(), ('--force',), ('--yes', 'extra')]:
            result = self.run_purge(*args)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('purge --yes', result.stderr)
            self.assert_files_retained()
            self.assertFalse((self.root / 'services.log').exists())

    def test_purge_removes_owned_paths_and_preserves_external_data(self):
        result = self.run_purge('--yes')
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ['etc/elise', 'state', 'support', 'licenses', 'bin/elise', 'bin/elisectl']:
            self.assertFalse((self.root / name).exists(), name)
        self.assertFalse(list((self.root / 'units').rglob('elise@*')))
        for name in ['outside/key.pem', 'external-state/traffic.json', 'units/other.service',
                     'units/multi-user.target.wants/other.service', 'bin/other']:
            self.assertTrue((self.root / name).exists(), name)
        calls = (self.root / 'services.log').read_text().splitlines()
        self.assertIn('stop elise@orphan.service', calls)
        self.assertIn('stop elise@vmess-2.service', calls)
        self.assertNotIn('stop elise@vless-1.service', calls)
        first_disable = next(i for i, call in enumerate(calls) if call.startswith('disable '))
        self.assertTrue(all(i < first_disable for i, call in enumerate(calls) if call.startswith('stop ')))

    def test_stop_failure_preserves_every_file(self):
        (self.root / 'stop-fail').touch()
        result = self.run_purge('--yes')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('could not stop', result.stderr)
        self.assert_files_retained()
        self.assertNotIn('disable ', (self.root / 'services.log').read_text())

    def test_service_enumeration_failure_preserves_every_file(self):
        (self.root / 'list-fail').touch()
        self.assertNotEqual(self.run_purge('--yes').returncode, 0)
        self.assert_files_retained()

    def test_purge_after_uninstall_and_repeated_purge(self):
        (self.root / 'uninstalled').touch()
        (self.root / 'units/elise@.service').unlink()
        (self.root / 'bin/elise').unlink()
        for _ in range(2):
            result = self.run_purge('--yes')
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'outside/key.pem').exists())

    def test_top_level_data_symlink_is_unlinked_not_followed(self):
        import shutil
        shutil.rmtree(self.root / 'state')
        (self.root / 'state').symlink_to(self.root / 'outside', target_is_directory=True)
        result = self.run_purge('--yes')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'state').is_symlink())
        self.assertTrue((self.root / 'outside/key.pem').exists())


class UninstallBootstrapTests(unittest.TestCase):
    """Exercise the entry point with offline downloads and a harmless manager."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bootstrap = HELPER.resolve().parent.parent / 'uninstall.sh'
        self.manager = self.root / 'manager'
        self.manager.write_text('''#!/bin/bash
printf '%s\\n' "$@" > "$FIXTURE/manager-args"
exit "${PURGE_STATUS:-0}"
''')
        curl = self.root / 'curl'
        curl.write_text('''#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
root = pathlib.Path(os.environ['FIXTURE'])
args = sys.argv[1:]
(root / 'curl-args').write_text(json.dumps(args))
if os.environ.get('DOWNLOAD_FAIL'):
    sys.exit(22)
shutil.copyfile(root / 'manager', args[args.index('--output') + 1])
''')
        curl.chmod(0o755)

    def run_uninstall(self, *arguments, **extra_env):
        # Override only host prerequisites. Real downloads are replaced via PATH;
        # the manager fixture never executes any host filesystem/service operation.
        setup = '''
source "$1"; shift
ensure_uninstall_dependencies() { echo checked > "$FIXTURE/dependencies"; }
main "$@"
'''
        return subprocess.run(['bash', '-c', setup, 'bash', str(self.bootstrap), *arguments],
                              env=dict(os.environ, PATH=f'{self.root}:{os.environ["PATH"]}',
                                       FIXTURE=str(self.root), **extra_env),
                              input='', capture_output=True, text=True, timeout=10)

    def assert_download_cleaned_up(self):
        args = json.loads((self.root / 'curl-args').read_text())
        download = Path(args[args.index('--output') + 1])
        self.assertFalse(download.parent.exists(), download.parent)
        return args

    def test_confirmation_and_help_never_download_or_run_manager(self):
        for arguments in [(), ('--force',), ('--yes', 'extra'), ('--help', '--yes'),
                          ('--help',), ('-h',), ('help',)]:
            with self.subTest(arguments=arguments):
                result = self.run_uninstall(*arguments)
                if arguments in [('--help',), ('-h',), ('help',)]:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('Permanently remove', result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('--yes', result.stderr)
                for name in ['dependencies', 'curl-args', 'manager-args']:
                    self.assertFalse((self.root / name).exists(), name)

    def test_downloads_current_manager_and_runs_purge_with_confirmation(self):
        result = self.run_uninstall('--yes')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'manager-args').read_text().splitlines(), ['purge', '--yes'])
        args = self.assert_download_cleaned_up()
        self.assertEqual(args[-1], 'https://raw.githubusercontent.com/phungvanquy/elise/refs/heads/main/scripts/elise.sh')
        for flag in ['--proto', '--proto-redir']:
            self.assertEqual(args[args.index(flag) + 1], '=https')

    def test_failed_download_does_not_run_manager(self):
        result = self.run_uninstall('--yes', DOWNLOAD_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('could not download', result.stderr)
        self.assertFalse((self.root / 'manager-args').exists())
        self.assert_download_cleaned_up()

    def test_empty_or_invalid_download_does_not_run_manager(self):
        for content in ['', 'if then\n']:
            with self.subTest(content=content):
                self.manager.write_text(content)
                result = self.run_uninstall('--yes')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('invalid removal tool', result.stderr)
                self.assertFalse((self.root / 'manager-args').exists())
                self.assert_download_cleaned_up()

    def test_purge_failure_is_propagated_and_download_is_cleaned_up(self):
        result = self.run_uninstall('--yes', PURGE_STATUS='23')
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assert_download_cleaned_up()

    def test_help_works_from_file_and_stdin(self):
        for command, source in [(['bash', str(self.bootstrap), '--help'], ''),
                                (['bash', '-s', '--', '--help'], self.bootstrap.read_text())]:
            result = subprocess.run(command, input=source, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('uninstall.sh --yes', result.stdout)


if __name__ == '__main__':
    unittest.main()
