#!/usr/bin/env python3
"""Exercise bootstrap selection and identity preservation in disposable repositories."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='peerward-bootstrap-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scripts = self.root / 'deploy/compose'
        self.scripts.mkdir(parents=True)
        shutil.copy2(ROOT / 'release.toml', self.root / 'release.toml')
        for name in ('bootstrap.sh', 'bootstrap.py', 'install.py', 'public_entry.py'):
            shutil.copy2(ROOT / 'deploy/compose' / name, self.scripts / name)

    def run_bootstrap(self, *arguments, success=True):
        result = subprocess.run(['sh', str(self.scripts / 'bootstrap.sh'), *arguments],
                                cwd=self.root, text=True, capture_output=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def hashes(self, directory):
        return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in directory.rglob('*') if path.is_file()}

    def test_new_and_repeated_bootstrap_preserve_identity_and_root_overrides(self):
        self.run_bootstrap('127.0.0.1')
        state = self.scripts / 'state'
        before = self.hashes(state)
        root_env = self.root / '.env'
        with root_env.open('a') as stream:
            stream.write('COMPOSE_PROJECT_NAME=existing-project\nPEERWARD_CONSOLE_PORT=29081\n')
        original = root_env.read_bytes()
        self.run_bootstrap('127.0.0.1')
        self.run_bootstrap()
        self.assertEqual(root_env.read_bytes(), original)
        self.assertEqual(self.hashes(state), before)
        self.assertEqual(root_env.stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.root / 'artifacts').exists())

    def test_incompatible_installation_is_rejected_without_touching_data_or_environment(self):
        self.run_bootstrap()
        manifest_path = self.scripts / 'state/installation.json'
        original = json.loads(manifest_path.read_text())
        for metadata in ({'version':2,'host_id':original['host_id']},
                         {**original,'schema_version':3,'wire_major':4}):
            manifest_path.write_text(json.dumps(metadata))
            before = self.hashes(self.root)
            result = self.run_bootstrap(success=False)
            self.assertIn('Incompatible installation', result.stderr)
            self.assertIn('--state-dir NEW_DIRECTORY', result.stderr)
            self.assertEqual(self.hashes(self.root), before)

    def test_select_existing_installation_backs_up_legacy_and_reuses_project(self):
        state = self.scripts / 'state-v2-local'
        self.run_bootstrap('127.0.0.1', '--state-dir', str(state))
        before = self.hashes(state)
        root_env = self.root / '.env'
        legacy = b'POSTGRES_DB=legacy\nPOSTGRES_PASSWORD=old-secret\n'
        root_env.write_bytes(legacy)
        self.run_bootstrap('127.0.0.1', '--state-dir', str(state))
        self.assertEqual(root_env.read_bytes(), (state / '.env').read_bytes())
        backups = list((self.root / 'artifacts/bootstrap').glob('*/root.env'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), legacy)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.hashes(state), before)
        self.run_bootstrap('127.0.0.1')
        self.assertEqual(self.hashes(state), before)

    def test_new_explicit_installation_keeps_old_state_and_separates_database(self):
        old = self.scripts / 'state'
        old.mkdir()
        (old / 'root.key').write_text('old identity')
        (self.root / '.env').write_text('POSTGRES_DB=old\n')
        before = self.hashes(old)
        state = old / 'local-v2'
        self.run_bootstrap('--state-dir', str(state))
        self.assertEqual((old / 'root.key').read_text(), 'old identity')
        self.assertEqual(before['root.key'], self.hashes(old)['root.key'])
        self.assertIn('COMPOSE_PROJECT_NAME=peerward-', (self.root / '.env').read_text())
        self.assertTrue(list((self.root / 'artifacts/bootstrap').glob('*/root.env')))

    def test_legacy_or_partial_installation_fails_without_overwriting(self):
        state = self.scripts / 'state'
        state.mkdir()
        (state / 'root.key').write_text('legacy identity')
        root_env = self.root / '.env'
        root_env.write_text('POSTGRES_DB=legacy\n')
        before = self.hashes(self.root)
        self.run_bootstrap(success=False)
        self.assertEqual(self.hashes(self.root), before)
        root_env.unlink()
        before = self.hashes(self.root)
        self.run_bootstrap(success=False)
        self.assertEqual(self.hashes(self.root), before)

    def test_interrupted_install_recovers_root_env_without_regenerating(self):
        self.run_bootstrap('relay.example.test')
        before = self.hashes(self.scripts / 'state')
        original = (self.root / '.env').read_bytes()
        (self.root / '.env').unlink()
        self.run_bootstrap('relay.example.test')
        self.assertEqual((self.root / '.env').read_bytes(), original)
        self.assertEqual(self.hashes(self.scripts / 'state'), before)

    def test_different_address_fails_without_modifying_existing_installation(self):
        self.run_bootstrap('relay.example.test')
        before = self.hashes(self.root)
        result = self.run_bootstrap('127.0.0.1', success=False)
        self.assertIn('differs', result.stderr)
        self.assertEqual(self.hashes(self.root), before)
        self.run_bootstrap()

    def test_invalid_addresses_fail_before_creating_state(self):
        for host in ('https://relay.example.test', '127.0.0.1:7777', '<public IP>', ''):
            self.run_bootstrap(host, success=False)
        self.assertFalse((self.scripts / 'state').exists())
        self.assertFalse((self.root / '.env').exists())

    def test_incomplete_active_installation_fails_instead_of_reinitializing(self):
        self.run_bootstrap()
        (self.scripts / 'state/control/tls.key').unlink()
        before = self.hashes(self.root)
        self.run_bootstrap(success=False)
        self.assertEqual(self.hashes(self.root), before)

    def test_environment_is_not_executed(self):
        (self.root / '.env').write_text('PEERWARD_STATE=$(touch UNEXPECTED)\n')
        self.run_bootstrap(success=False)
        self.assertFalse((self.root / 'UNEXPECTED').exists())

    def test_stun_settings_are_host_scoped_and_reuse_does_not_reconfigure(self):
        self.run_bootstrap('relay.example.test', '--stun-port', '33478')
        state = self.scripts / 'state'
        dynamic = tomllib.loads((state / 'control/dynamic.toml').read_text())
        relay = tomllib.loads((state / 'relay/relay.toml').read_text())
        self.assertEqual(dynamic['stun_servers'], ['relay.example.test:33478'])
        self.assertEqual(relay['stun_addresses'], ['0.0.0.0:3478'])
        self.assertIn('PEERWARD_STUN_PORT=33478\n', (self.root / '.env').read_text())
        before = self.hashes(self.root)
        self.run_bootstrap('--stun-port', '33478')
        self.assertEqual(self.hashes(self.root), before)
        self.run_bootstrap('--stun-port', '3478', success=False)
        self.assertEqual(self.hashes(self.root), before)

    def test_stun_can_be_disabled_and_invalid_port_never_creates_state(self):
        for port in ('-1', '65536'):
            self.run_bootstrap('--stun-port', port, success=False)
            self.assertFalse((self.scripts / 'state').exists())
        self.run_bootstrap('--stun-port', '0')
        state = self.scripts / 'state'
        self.assertEqual(tomllib.loads((state / 'control/dynamic.toml').read_text())['stun_servers'], [])
        self.assertEqual(tomllib.loads((state / 'relay/relay.toml').read_text())['stun_addresses'], [])

    def test_public_oidc_installation_is_explicit_and_repeatable(self):
        oidc = self.root / 'oidc.toml'
        oidc.write_text('issuer_url="https://login.example.test"\nclient_id="peerward"\n'
                        'redirect_uri="https://mesh.example.test/auth/callback"\n'
                        'admin_groups=["mesh-admin"]\nclient_secret="private-test-secret"\n')
        oidc.chmod(0o600)
        arguments = ('relay.example.test', '--public-url', 'https://mesh.example.test', '--oidc-config-file', str(oidc))
        result = self.run_bootstrap(*arguments)
        self.assertNotIn('private-test-secret', result.stdout + result.stderr)
        state = self.scripts / 'state'
        config = tomllib.loads((state / 'control/control.toml').read_text())
        self.assertEqual(config['public_url'], 'https://mesh.example.test')
        self.assertEqual(config['oidc']['admin_groups'], ['mesh-admin'])
        self.assertIn('deploy/compose/oidc.yaml', (self.root / '.env').read_text())
        self.assertIn('PEERWARD_DEV_BEARER=disabled-for-oidc', (self.root / '.env').read_text())
        before = self.hashes(self.root)
        self.run_bootstrap(*arguments)
        self.run_bootstrap('--public-url', 'https://other.example.test', success=False)
        self.assertEqual(self.hashes(self.root), before)

    def test_invalid_public_entry_never_creates_installation(self):
        for url in ('http://mesh.example.test', 'https://user:secret@mesh.example.test',
                    'https://mesh.example.test/path', 'https://mesh.example.test/?secret=x',
                    'https://mesh.example.test/#fragment', 'https://mesh.example.test:bad'):
            self.run_bootstrap('--public-url', url, success=False)
            self.assertFalse((self.scripts / 'state').exists())
        oidc = self.root / 'oidc.toml'
        oidc.write_text('issuer_url="https://login.example.test"\nclient_id="peerward"\n'
                        'redirect_uri="https://wrong.example.test/auth/callback"\nadmin_groups=["admin"]')
        oidc.chmod(0o600)
        self.run_bootstrap('--oidc-config-file', str(oidc), success=False)
        self.run_bootstrap('--public-url', 'https://mesh.example.test', '--oidc-config-file', str(oidc), success=False)
        self.assertFalse((self.scripts / 'state').exists())


if __name__ == '__main__':
    unittest.main()
