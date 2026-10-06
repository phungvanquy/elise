#!/usr/bin/env python3
"""Test purge in a temporary filesystem with a fake systemctl; never touch host services."""
from pathlib import Path
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
                     'legacy-v2bx/traffic.json', 'units/other.service', 'bin/other']:
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
        for name in ['outside/key.pem', 'legacy-v2bx/traffic.json', 'units/other.service',
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


if __name__ == '__main__':
    unittest.main()
